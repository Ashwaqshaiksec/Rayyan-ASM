package port

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CommonPorts are the most commonly scanned ports
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
	27017, 6379, 5432, 1521, 1433, 9200, 9300, 2181, 2375, 2376,
	4443, 8000, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
	8088, 8089, 8090, 9000, 9001, 9090, 9091, 9092, 10000,
}

type OpenPort struct {
	Host     string
	Port     int
	Protocol string // tcp, udp
	State    string // open, closed, filtered
	Service  string
	Banner   string
	Latency  time.Duration
}

type ScanOptions struct {
	Hosts      []string
	Ports      []int  // empty = common ports
	Protocol   string // tcp, udp, both
	FullRange  bool
	Timeout    time.Duration
	Workers    int
	BannerGrab bool
}

type Scanner struct {
	log *zap.SugaredLogger
}

func NewScanner(log *zap.SugaredLogger) *Scanner {
	return &Scanner{log: log}
}

func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (<-chan OpenPort, error) {
	results := make(chan OpenPort, 10000)

	ports := opts.Ports
	if len(ports) == 0 {
		if opts.FullRange {
			ports = makeRange(1, 65535)
		} else {
			ports = CommonPorts
		}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 1 * time.Second
	}

	workers := opts.Workers
	if workers == 0 {
		workers = 500
	}

	type target struct {
		host string
		port int
	}

	go func() {
		defer close(results)

		targetCh := make(chan target, workers*2)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range targetCh {
					select {
					case <-ctx.Done():
						return
					default:
					}

					result := s.probePort(ctx, t.host, t.port, opts)
					if result.State == "open" {
						select {
						case results <- result:
						case <-ctx.Done():
							return
						}
					}
				}
			}()
		}

		for _, host := range opts.Hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					goto done
				case targetCh <- target{host: host, port: port}:
				}
			}
		}

	done:
		close(targetCh)
		wg.Wait()
	}()

	return results, nil
}

func (s *Scanner) probePort(ctx context.Context, host string, port int, opts ScanOptions) OpenPort {
	result := OpenPort{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()

	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	result.Latency = time.Since(start)

	if err != nil {
		if isRefused(err) {
			result.State = "closed"
		} else {
			result.State = "filtered"
		}
		return result
	}

	defer func() { _ = conn.Close() }()
	result.State = "open"

	// Banner grabbing
	if opts.BannerGrab {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			result.Banner = string(buf[:n])
		}
	}

	// Service identification
	result.Service = identifyService(port, result.Banner)

	return result
}

func identifyService(port int, banner string) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		2375:  "docker",
		2376:  "docker-tls",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		27017: "mongodb",
	}

	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}

func isRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for i := 0; i <= len(msg)-17; i++ {
		if msg[i:i+17] == "connection refuse" {
			return true
		}
	}
	return false
}

func makeRange(start, end int) []int {
	ports := make([]int, end-start+1)
	for i := range ports {
		ports[i] = start + i
	}
	return ports
}
