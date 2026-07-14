package dns_test

import (
	"context"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newScanner() *dns.Scanner {
	return dns.NewScanner(zap.NewNop().Sugar(), nil)
}

func TestScanWellKnownDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	s := newScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := s.Scan(ctx, dns.ScanOptions{
		Domains:     []string{"example.com"},
		Workers:     2,
		RecordTypes: []string{"A", "NS"},
	})
	require.NoError(t, err)

	var results []dns.DomainInfo
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	info := results[0]
	assert.Equal(t, "example.com", info.Domain)

	var hasA bool
	for _, rec := range info.Records {
		if rec.Type == "A" {
			hasA = true
			assert.NotEmpty(t, rec.Value)
		}
	}
	assert.True(t, hasA, "example.com should have A records")
}

func TestScanNonExistentDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	s := newScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := s.Scan(ctx, dns.ScanOptions{
		Domains:     []string{"this-domain-definitely-does-not-exist-12345.example.invalid"},
		Workers:     1,
		RecordTypes: []string{"A"},
	})
	require.NoError(t, err)

	var results []dns.DomainInfo
	for r := range ch {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	// Should have errors but not panic
	assert.NotEmpty(t, results[0].Errors)
	assert.Empty(t, results[0].Records)
}

func TestScanMultipleDomains(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	s := newScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	domains := []string{"example.com", "iana.org"}

	ch, err := s.Scan(ctx, dns.ScanOptions{
		Domains:     domains,
		Workers:     5,
		RecordTypes: []string{"A"},
	})
	require.NoError(t, err)

	var count int
	for range ch {
		count++
	}
	assert.Equal(t, len(domains), count)
}
