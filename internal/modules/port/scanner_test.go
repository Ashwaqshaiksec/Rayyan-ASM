package port_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func startTCPServer(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("TEST BANNER\r\n"))
			_ = conn.Close()
		}
	}()

	return addr.IP.String(), addr.Port
}

func TestScanOpenPort(t *testing.T) {
	ip, p := startTCPServer(t)

	s := port.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := s.Scan(ctx, port.ScanOptions{
		Hosts:      []string{ip},
		Ports:      []int{p},
		Protocol:   "tcp",
		Timeout:    1 * time.Second,
		Workers:    5,
		BannerGrab: true,
	})
	require.NoError(t, err)

	var found *port.OpenPort
	for result := range ch {
		r := result
		if r.Port == p {
			found = &r
		}
	}

	require.NotNil(t, found)
	assert.Equal(t, "open", found.State)
	assert.Equal(t, p, found.Port)
	assert.Contains(t, found.Banner, "TEST BANNER")
}

func TestScanClosedPort(t *testing.T) {
	s := port.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port 1 is almost certainly closed/filtered on loopback
	ch, err := s.Scan(ctx, port.ScanOptions{
		Hosts:   []string{"127.0.0.1"},
		Ports:   []int{1},
		Timeout: 200 * time.Millisecond,
		Workers: 2,
	})
	require.NoError(t, err)

	var found bool
	for r := range ch {
		if r.Port == 1 && r.State == "open" {
			found = true
		}
	}
	assert.False(t, found, "port 1 should not be open")
}

func TestCommonPortsList(t *testing.T) {
	assert.Contains(t, port.CommonPorts, 80)
	assert.Contains(t, port.CommonPorts, 443)
	assert.Contains(t, port.CommonPorts, 22)
	assert.Contains(t, port.CommonPorts, 3306)
	assert.Greater(t, len(port.CommonPorts), 20)
}

func TestContextCancellation(t *testing.T) {
	s := port.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	ch, err := s.Scan(ctx, port.ScanOptions{
		Hosts:   []string{"192.168.255.255"},
		Ports:   port.CommonPorts,
		Timeout: 5 * time.Second,
		Workers: 50,
	})
	require.NoError(t, err)

	// Should drain quickly without hanging
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("scanner did not respect context cancellation")
	}
}
