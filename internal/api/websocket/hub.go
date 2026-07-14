package websocket

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Origin is validated by the Gin CORS middleware before the upgrade.
		// At the WS layer we trust the request has already been authenticated
		// and CORS-checked by the route handler.
		return true
	},
}

type Message struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

type Client struct {
	hub   *Hub
	conn  *websocket.Conn
	send  chan []byte
	orgID string
}

type Hub struct {
	clients        map[*Client]bool
	broadcast      chan Message
	broadcastBytes chan []byte
	register       chan *Client
	unregister     chan *Client
	mu             sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients:        make(map[*Client]bool),
		broadcast:      make(chan Message, 256),
		broadcastBytes: make(chan []byte, 256),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case msg := <-h.broadcast:
			msg.Timestamp = time.Now()
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			h.fanout(data, "")

		case raw := <-h.broadcastBytes:
			h.fanout(raw, "")
		}
	}
}

func (h *Hub) fanout(data []byte, orgID string) {
	h.mu.RLock()
	targets := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		if orgID != "" && client.orgID != orgID {
			continue
		}
		targets = append(targets, client)
	}
	h.mu.RUnlock()

	var slow []*Client
	for _, client := range targets {
		select {
		case client.send <- data:
		default:
			slow = append(slow, client)
		}
	}
	if len(slow) > 0 {
		h.mu.Lock()
		for _, client := range slow {
			if _, ok := h.clients[client]; ok {
				close(client.send)
				delete(h.clients, client)
			}
		}
		h.mu.Unlock()
	}
}

func (h *Hub) Broadcast(msg Message) {
	h.broadcast <- msg
}

func (h *Hub) BroadcastToOrg(orgID string, data []byte) {
	h.mu.RLock()
	targets := make([]*Client, 0)
	for client := range h.clients {
		if client.orgID == orgID {
			targets = append(targets, client)
		}
	}
	h.mu.RUnlock()

	var slow []*Client
	for _, client := range targets {
		select {
		case client.send <- data:
		default:
			slow = append(slow, client)
		}
	}
	if len(slow) > 0 {
		h.mu.Lock()
		for _, client := range slow {
			if _, ok := h.clients[client]; ok {
				close(client.send)
				delete(h.clients, client)
			}
		}
		h.mu.Unlock()
	}
}

func (h *Hub) BroadcastRaw(data []byte) {
	h.broadcastBytes <- data
}

func (h *Hub) BroadcastBytes(data []byte) {
	h.broadcastBytes <- data
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request, orgID string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &Client{
		hub:   hub,
		conn:  conn,
		send:  make(chan []byte, 256),
		orgID: orgID,
	}

	hub.register <- client

	go client.writePump()
	go client.readPump()
}

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512 * 1024
)

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		_ = c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
