// ports.go resolves Options.PortProfile (+ ConfirmFullPortScan) into the
// actual port list probePorts scans, and holds the concurrency defaults
// for the worker-pool port scanner in providers.go.
package discovery

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// PortProfile selects which port set Options.PortProfile probes per host.
const (
	PortProfileQuick   = "quick"   // today's compact 23-port list (default)
	PortProfileTop1000 = "top1000" // Nmap's top-1000 TCP ports by frequency
	PortProfileFull    = "full"    // every TCP port 1-65535; requires ConfirmFullPortScan
)

//go:embed portdata/top1000_tcp.txt
var top1000TCPRaw string

var (
	top1000Once  sync.Once
	top1000Ports []int
)

// parsePortList parses a comma-separated list of port numbers, silently
// dropping anything out of the valid 1-65535 TCP port range.
func parsePortList(raw string) []int {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, n)
	}
	return out
}

// top1000TCPPorts returns the embedded Nmap top-1000-by-frequency TCP port
// list (see portdata/SOURCE.md), parsed once per process.
func top1000TCPPorts() []int {
	top1000Once.Do(func() { top1000Ports = parsePortList(top1000TCPRaw) })
	return top1000Ports
}

// fullPortRange returns every TCP port from 1 to 65535.
func fullPortRange() []int {
	ports := make([]int, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, p)
	}
	return ports
}

// portsForProfile resolves Options.PortProfile to the port list
// probePorts should scan. "full" requires confirmFull=true given the
// time and legal-authorization implications of scanning every port on a
// target — without confirmation it logs a WARN and falls back to
// "top1000" rather than silently launching a full 65k-port scan. log may
// be nil (e.g. in unit tests that don't care about the log line);
// callers in production always have a non-nil *Engine.log available.
// Unrecognized/empty profile falls back to "quick" (today's existing
// DefaultPorts list).
func portsForProfile(profile string, confirmFull bool, log *zap.SugaredLogger) []int {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case PortProfileTop1000:
		return top1000TCPPorts()
	case PortProfileFull:
		if confirmFull {
			return fullPortRange()
		}
		if log != nil {
			log.Warnw("discovery: PortProfile=\"full\" requested without ConfirmFullPortScan; falling back to top1000",
				"requested_profile", PortProfileFull, "fallback_profile", PortProfileTop1000)
		}
		return top1000TCPPorts()
	default:
		return DefaultPorts
	}
}

// defaultPortConcurrency bounds simultaneous port-probe goroutines per
// host when Options.PortConcurrency is unset (<= 0) — sane enough to scan
// the "full" 65k-port profile in well under a minute per host without
// firing tens of thousands of sequential DialTimeout calls.
const defaultPortConcurrency = 200

// portConcurrencyOrDefault returns n if positive, else defaultPortConcurrency.
func portConcurrencyOrDefault(n int) int {
	if n <= 0 {
		return defaultPortConcurrency
	}
	return n
}
