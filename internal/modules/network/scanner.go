package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type DiscoveredHost struct {
	IP         string
	Hostname   string
	ReverseDNS string
	IsUp       bool
	Latency    time.Duration
	Method     string // icmp, arp, tcp
}

type Scanner struct {
	log       *zap.SugaredLogger
	workers   int
	timeout   time.Duration
	rateLimit int // hosts per second
}

type ScanOptions struct {
	Targets    []string // CIDRs, IPs, ranges
	Workers    int
	Timeout    time.Duration
	RateLimit  int
	Methods    []string // icmp, tcp, arp
	ResolveDNS bool
}

func NewScanner(log *zap.SugaredLogger) *Scanner {
	return &Scanner{
		log:       log,
		workers:   100,
		timeout:   3 * time.Second,
		rateLimit: 1000,
	}
}

// Scan discovers hosts in the given targets using the specified options.
// Results are sent to the returned channel. Close ctx to cancel.
func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (<-chan DiscoveredHost, error) {
	results := make(chan DiscoveredHost, 1000)

	// Expand all targets to individual IPs
	ips, err := s.expandTargets(opts.Targets)
	if err != nil {
		return nil, fmt.Errorf("expanding targets: %w", err)
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = s.workers
	}

	go func() {
		defer close(results)

		// Worker pool
		ipCh := make(chan string, workers*2)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipCh {
					select {
					case <-ctx.Done():
						return
					default:
					}

					host := s.probeHost(ctx, ip, opts)
					if host.IsUp {
						if opts.ResolveDNS {
							host = s.resolveDNS(host)
						}
						select {
						case results <- host:
						case <-ctx.Done():
							return
						}
					}
				}
			}()
		}

		// Rate-limited IP feeding
		ticker := time.NewTicker(time.Second / time.Duration(maxInt(opts.RateLimit, 100)))
		defer ticker.Stop()

	feedIPs:
		for _, ip := range ips {
			select {
			case <-ctx.Done():
				break feedIPs
			case <-ticker.C:
				ipCh <- ip
			}
		}
		close(ipCh)
		wg.Wait()
	}()

	return results, nil
}

func (s *Scanner) probeHost(ctx context.Context, ip string, opts ScanOptions) DiscoveredHost {
	host := DiscoveredHost{IP: ip}

	// TCP probe on common ports as fallback for ICMP
	ports := []int{80, 443, 22, 21, 8080}
	for _, port := range ports {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			host.IsUp = true
			host.Method = "tcp"
			return host
		}
	}

	// ICMP-like check via UDP (no raw sockets needed)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "33434"), 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
	}

	// Try plain TCP connect to see if host is alive
	dialer := &net.Dialer{Timeout: s.timeout}
	conn2, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "0"))
	if err == nil {
		_ = conn2.Close()
	}

	// Check if we get a connection refused (host is up but port closed)
	conn3, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "65534"), 300*time.Millisecond)
	if err != nil {
		if isConnectionRefused(err) {
			host.IsUp = true
			host.Method = "tcp-refused"
		}
	} else {
		_ = conn3.Close()
		host.IsUp = true
		host.Method = "tcp"
	}

	return host
}

func (s *Scanner) resolveDNS(host DiscoveredHost) DiscoveredHost {
	names, err := net.LookupAddr(host.IP)
	if err == nil && len(names) > 0 {
		host.ReverseDNS = names[0]
		host.Hostname = names[0]
	}
	return host
}

// expandTargets expands CIDRs, ranges, and individual IPs into a flat list
func (s *Scanner) expandTargets(targets []string) ([]string, error) {
	var ips []string

	for _, target := range targets {
		// Try CIDR
		if _, ipNet, err := net.ParseCIDR(target); err == nil {
			ones, bits := ipNet.Mask.Size()
			if bits > 0 && ones < 16 {
				// Reject overly broad CIDRs to prevent DoS (>65 536 hosts).
				return nil, fmt.Errorf("CIDR range too broad: %s (minimum prefix length /16)", target)
			}
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				ips = append(ips, ip.String())
			}
			continue
		}

		// Try single IP
		if ip := net.ParseIP(target); ip != nil {
			ips = append(ips, target)
			continue
		}

		// Try hostname
		addrs, err := net.LookupHost(target)
		if err == nil {
			ips = append(ips, addrs...)
			continue
		}

		return nil, fmt.Errorf("invalid target: %s", target)
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "connection refused")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
