package discovery

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// retryWithBackoff retries fn with exponential backoff (baseDelay*2^i) up
// to attempts times, bailing early on ctx cancellation.
func retryWithBackoff(ctx context.Context, attempts int, baseDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		delay := baseDelay * time.Duration(int64(1)<<uint(i))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

type ttlCacheEntry struct {
	value   any
	expires time.Time
}

// ttlCache is a per-run cache so we don't hammer the same external API
// for hosts on the same /24 or ASN.
type ttlCache struct {
	mu   sync.Mutex
	data map[string]ttlCacheEntry
	ttl  time.Duration
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{data: make(map[string]ttlCacheEntry), ttl: ttl}
}

func (c *ttlCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.data[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.value, true
}

func (c *ttlCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = ttlCacheEntry{value: value, expires: time.Now().Add(c.ttl)}
}

// circuitBreaker trips after `threshold` consecutive failures against one
// provider and stays open for the rest of the run, so we stop paying retry
// cost once it's clear a dependency is down.
type circuitBreaker struct {
	mu         sync.Mutex
	name       string
	threshold  int
	failures   int
	open       bool
	loggedOpen bool
}

func newCircuitBreaker(name string, threshold int) *circuitBreaker {
	if threshold < 1 {
		threshold = 1
	}
	return &circuitBreaker{name: name, threshold: threshold}
}

func (cb *circuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return !cb.open
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

func (cb *circuitBreaker) RecordFailure(log *zap.SugaredLogger) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.failures >= cb.threshold {
		cb.open = true
	}
	if cb.open && !cb.loggedOpen {
		cb.loggedOpen = true
		if log != nil {
			log.Warnw("discovery: provider circuit breaker open, skipping for rest of run",
				"provider", cb.name, "consecutive_failures", cb.failures)
		}
	}
}

// providerCacheTTL is generous since providerState only lives for one run anyway.
const providerCacheTTL = 30 * time.Minute

const circuitBreakerThreshold = 5

// providerState holds the per-run cache + circuit breaker for each external
// lookup (Cymru ASN, bgp.tools CIDR, ip-api.com GeoIP). Fresh per run, never
// shared across jobs.
type providerState struct {
	asnCache  *ttlCache
	cidrCache *ttlCache
	geoCache  *ttlCache

	asnBreaker  *circuitBreaker
	cidrBreaker *circuitBreaker
	geoBreaker  *circuitBreaker
}

func newProviderState() *providerState {
	return &providerState{
		asnCache:    newTTLCache(providerCacheTTL),
		cidrCache:   newTTLCache(providerCacheTTL),
		geoCache:    newTTLCache(providerCacheTTL),
		asnBreaker:  newCircuitBreaker("cymru-asn", circuitBreakerThreshold),
		cidrBreaker: newCircuitBreaker("bgp.tools-cidr", circuitBreakerThreshold),
		geoBreaker:  newCircuitBreaker("ip-api-geoip", circuitBreakerThreshold),
	}
}
