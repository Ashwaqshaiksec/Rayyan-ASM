package tools

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// PortResult holds a discovered open port from any network tool.
type PortResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Source   string `json:"source"`
}

// nmapXML mirrors the minimal structure of nmap's XML output needed for parsing.
type nmapXML struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// RunNmap performs a service-version scan on target using nmap with XML output.
func RunNmap(target string, ports string, timeout time.Duration) ([]PortResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nmap")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nmap")
	}

	args := []string{"-sV", "-sC", "--open", "-oX", "-"}
	if ports != "" {
		args = append(args, "-p", ports)
	}
	args = append(args, target)

	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("nmap", result.Error == nil)

	var nmapOut nmapXML
	if err := xml.Unmarshal([]byte(result.Stdout), &nmapOut); err != nil {
		// Fallback: return empty with no panic
		return nil, nil
	}

	var out []PortResult
	for _, host := range nmapOut.Hosts {
		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		for _, p := range host.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			version := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			out = append(out, PortResult{
				Host:     ip,
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Version:  version,
				Source:   "nmap",
			})
		}
	}
	return out, nil
}

// RunNaabu runs naabu for fast port scanning with JSON output.
func RunNaabu(target string, timeout time.Duration) ([]PortResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("naabu")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("naabu")
	}

	args := []string{"-host", target, "-json", "-silent", "-rate", "1000"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("naabu", result.Error == nil)

	var out []PortResult
	for _, line := range parseLines(result.Stdout) {
		// naabu JSON: {"ip":"1.2.3.4","port":443,"protocol":"tcp"}
		var obj struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		out = append(out, PortResult{
			Host:     obj.IP,
			Port:     obj.Port,
			Protocol: obj.Protocol,
			State:    "open",
			Source:   "naabu",
		})
	}
	return out, nil
}

// RunRustscan runs rustscan and parses its text output.
func RunRustscan(target string, timeout time.Duration) ([]PortResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("rustscan")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("rustscan")
	}

	args := []string{"-a", target, "--ulimit", "5000", "--no-nmap", "--"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("rustscan", result.Error == nil)

	var out []PortResult
	for _, line := range parseLines(result.Stdout) {
		// rustscan output: "Open 1.2.3.4:80"
		if !strings.HasPrefix(line, "Open ") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "Open "), ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		out = append(out, PortResult{
			Host:     strings.TrimSpace(parts[0]),
			Port:     port,
			Protocol: "tcp",
			State:    "open",
			Source:   "rustscan",
		})
	}
	return out, nil
}

// RunMasscan runs masscan with JSON output for high-speed port scanning.
func RunMasscan(target string, rate string, timeout time.Duration) ([]PortResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("masscan")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("masscan")
	}

	if rate == "" {
		rate = "1000"
	}
	args := []string{target, "-p", "1-65535", "--rate", rate, "-oJ", "-"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("masscan", result.Error == nil)

	// masscan JSON is wrapped: [ { "ip": ..., "ports": [...] }, ... ]
	type masscanPort struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
	}
	type masscanRecord struct {
		IP    string        `json:"ip"`
		Ports []masscanPort `json:"ports"`
	}

	var out []PortResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var records []masscanRecord
	if err := parseJSONSlice(clean, &records); err != nil {
		return out, nil
	}
	for _, r := range records {
		for _, p := range r.Ports {
			out = append(out, PortResult{
				Host:     r.IP,
				Port:     p.Port,
				Protocol: p.Proto,
				State:    p.Status,
				Source:   "masscan",
			})
		}
	}
	return out, nil
}
