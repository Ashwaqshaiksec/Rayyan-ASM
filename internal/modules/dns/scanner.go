package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type DNSRecord struct {
	Name     string
	Type     string
	Value    string
	TTL      uint32
	Priority uint16 // MX
}

type DomainInfo struct {
	Domain      string
	Records     []DNSRecord
	Nameservers []string
	Errors      []string
	ScannedAt   time.Time
}

type Scanner struct {
	log       *zap.SugaredLogger
	resolvers []string // custom DNS resolvers
	timeout   time.Duration
}

func NewScanner(log *zap.SugaredLogger, resolvers []string) *Scanner {
	if len(resolvers) == 0 {
		resolvers = []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"8.8.4.4:53",
		}
	}
	return &Scanner{
		log:       log,
		resolvers: resolvers,
		timeout:   5 * time.Second,
	}
}

type ScanOptions struct {
	Domains     []string
	Workers     int
	RecordTypes []string // A, AAAA, MX, TXT, NS, SOA, PTR
}

func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (<-chan DomainInfo, error) {
	results := make(chan DomainInfo, 100)

	recordTypes := opts.RecordTypes
	if len(recordTypes) == 0 {
		recordTypes = []string{"A", "AAAA", "MX", "TXT", "NS", "SOA"}
	}

	workers := opts.Workers
	if workers == 0 {
		workers = 20
	}

	go func() {
		defer close(results)

		domainCh := make(chan string, workers)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for domain := range domainCh {
					select {
					case <-ctx.Done():
						return
					default:
					}

					info := s.scanDomain(ctx, domain, recordTypes)
					select {
					case results <- info:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

	feedDomains:
		for _, domain := range opts.Domains {
			select {
			case <-ctx.Done():
				break feedDomains
			case domainCh <- domain:
			}
		}
		close(domainCh)
		wg.Wait()
	}()

	return results, nil
}

func (s *Scanner) scanDomain(ctx context.Context, domain string, types []string) DomainInfo {
	info := DomainInfo{
		Domain:    domain,
		ScannedAt: time.Now(),
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: s.timeout}
			return d.DialContext(ctx, "udp", s.resolvers[0])
		},
	}

	for _, t := range types {
		records, err := s.lookupType(ctx, resolver, domain, t)
		if err != nil {
			info.Errors = append(info.Errors, fmt.Sprintf("%s: %v", t, err))
			continue
		}
		info.Records = append(info.Records, records...)
	}

	// Get nameservers
	ns, _ := resolver.LookupNS(ctx, domain)
	for _, n := range ns {
		info.Nameservers = append(info.Nameservers, n.Host)
	}

	return info
}

func (s *Scanner) lookupType(ctx context.Context, resolver *net.Resolver, domain, recordType string) ([]DNSRecord, error) {
	var records []DNSRecord

	switch recordType {
	case "A":
		addrs, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if net.ParseIP(addr).To4() != nil {
				records = append(records, DNSRecord{Name: domain, Type: "A", Value: addr})
			}
		}

	case "AAAA":
		addrs, err := resolver.LookupHost(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && ip.To4() == nil {
				records = append(records, DNSRecord{Name: domain, Type: "AAAA", Value: addr})
			}
		}

	case "MX":
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, mx := range mxs {
			records = append(records, DNSRecord{
				Name:     domain,
				Type:     "MX",
				Value:    mx.Host,
				Priority: mx.Pref,
			})
		}

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, txt := range txts {
			records = append(records, DNSRecord{Name: domain, Type: "TXT", Value: txt})
		}

	case "NS":
		nss, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, ns := range nss {
			records = append(records, DNSRecord{Name: domain, Type: "NS", Value: ns.Host})
		}

	case "PTR":
		ptrs, err := resolver.LookupAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		for _, ptr := range ptrs {
			records = append(records, DNSRecord{Name: domain, Type: "PTR", Value: ptr})
		}
	}

	return records, nil
}

// EnumerateSubdomains performs DNS-based subdomain enumeration
func (s *Scanner) EnumerateSubdomains(ctx context.Context, domain string, wordlist []string) (<-chan string, error) {
	results := make(chan string, 1000)

	go func() {
		defer close(results)

		sem := make(chan struct{}, 50)
		var wg sync.WaitGroup

		resolver := &net.Resolver{PreferGo: true}

		for _, word := range wordlist {
			fqdn := word + "." + domain

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				defer func() { <-sem }()

				_, err := resolver.LookupHost(ctx, sub)
				if err == nil {
					select {
					case results <- sub:
					case <-ctx.Done():
					}
				}
			}(fqdn)
		}
		wg.Wait()
	}()

	return results, nil
}
