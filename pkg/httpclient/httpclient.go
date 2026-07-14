package httpclient

import (
	"net/http"
	"net/url"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
)

// New returns an *http.Client configured with the given timeout and, if
// cfg.Proxy.Enabled is true, the appropriate proxy transport. Callers that
// need a plain client without proxy support can pass a zero-value ProxyConfig.
func New(timeout time.Duration, cfg config.ProxyConfig) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.Enabled {
		// Prefer SOCKS5 > HTTPS > HTTP in that order.
		var proxyURL *url.URL
		var err error
		switch {
		case cfg.SOCKS5 != "":
			proxyURL, err = url.Parse(cfg.SOCKS5)
		case cfg.HTTPS != "":
			proxyURL, err = url.Parse(cfg.HTTPS)
		case cfg.HTTP != "":
			proxyURL, err = url.Parse(cfg.HTTP)
		}
		if err == nil && proxyURL != nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		if cfg.NoProxy != "" {
			// golang http.Transport honours NO_PROXY env but not a programmatic
			// list. Set it temporarily via the transport's ProxyFunc wrapper so
			// we don't mutate the process environment.
			noProxy := cfg.NoProxy
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				for _, host := range splitHosts(noProxy) {
					if req.URL.Hostname() == host {
						return nil, nil
					}
				}
				if proxyURL != nil {
					return proxyURL, nil
				}
				return http.ProxyFromEnvironment(req)
			}
		}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// splitHosts splits a comma-separated no-proxy host list.
func splitHosts(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			h := s[start:i]
			if h != "" {
				out = append(out, h)
			}
			start = i + 1
		}
	}
	return out
}
