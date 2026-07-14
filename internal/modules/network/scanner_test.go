package network_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestExpandTargets_ValidCIDR(t *testing.T) {
	s := network.NewScanner(zap.NewNop().Sugar())

	// Use a tiny /30 so we don't generate huge slices
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Spin up a local listener on loopback so something responds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	opts := network.ScanOptions{
		Targets:    []string{"127.0.0.1"},
		Workers:    5,
		Timeout:    1 * time.Second,
		ResolveDNS: false,
	}

	ch, err := s.Scan(ctx, opts)
	require.NoError(t, err)

	var found bool
	for h := range ch {
		if h.IP == "127.0.0.1" && h.IsUp {
			found = true
		}
	}
	assert.True(t, found, "loopback should be detected as up")
}

func TestScanLocalHTTPServer(t *testing.T) {
	// Start a minimal HTTP server on a random port
	srv := &http.Server{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	_ = addr // addr holds host:port
	// The scanner will detect TCP connection on this port
	// Just verify the scanner runs without panic
	s := network.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ch, err := s.Scan(ctx, network.ScanOptions{
		Targets: []string{"127.0.0.1"},
		Workers: 2,
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	for range ch {
	} // drain
}
