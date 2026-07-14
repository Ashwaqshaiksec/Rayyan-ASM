package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type WebAsset struct {
	URL             string
	FinalURL        string
	StatusCode      int
	Title           string
	Server          string
	ContentType     string
	ContentLength   int64
	Headers         map[string]string
	SecurityHeaders map[string]string
	RedirectChain   []string
	TLSInfo         *TLSInfo
	Technologies    []string
	ScanError       string
	ScannedAt       time.Time
}

type TLSInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	Fingerprint  string
	SANs         []string
	SerialNumber string
	Version      int
	IsWildcard   bool
	IsSelfSigned bool
	IsExpired    bool
	SignatureAlg string
	KeyAlg       string
	KeyBits      int
}

type ScanOptions struct {
	Targets         []string
	Workers         int
	Timeout         time.Duration
	FollowRedirects bool
	ParseTLS        bool
	GrabBanners     bool
	UserAgent       string
}

type Scanner struct {
	log    *zap.SugaredLogger
	client *http.Client
}

func NewScanner(log *zap.SugaredLogger) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 10,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Scanner{log: log, client: client}
}

func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (<-chan WebAsset, error) {
	results := make(chan WebAsset, 1000)

	workers := opts.Workers
	if workers == 0 {
		workers = 50
	}

	if opts.Timeout > 0 {
		s.client.Timeout = opts.Timeout
	}

	go func() {
		defer close(results)

		targetCh := make(chan string, workers)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for target := range targetCh {
					select {
					case <-ctx.Done():
						return
					default:
					}

					// Try HTTP and HTTPS
					for _, scheme := range []string{"https", "http"} {
						url := fmt.Sprintf("%s://%s", scheme, target)
						asset := s.scanURL(ctx, url, opts)
						select {
						case results <- asset:
						case <-ctx.Done():
							return
						}
					}
				}
			}()
		}

	feedTargets:
		for _, target := range opts.Targets {
			select {
			case <-ctx.Done():
				break feedTargets
			case targetCh <- target:
			}
		}
		close(targetCh)
		wg.Wait()
	}()

	return results, nil
}

func (s *Scanner) scanURL(ctx context.Context, url string, opts ScanOptions) WebAsset {
	asset := WebAsset{
		URL:             url,
		ScannedAt:       time.Now(),
		Headers:         make(map[string]string),
		SecurityHeaders: make(map[string]string),
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; RayyanASM/1.0; +https://github.com/ShadooowX/rayyan-asm)"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		asset.ScanError = err.Error()
		return asset
	}
	req.Header.Set("User-Agent", ua)

	resp, err := s.client.Do(req)
	if err != nil {
		asset.ScanError = err.Error()
		return asset
	}
	defer func() { _ = resp.Body.Close() }()

	asset.StatusCode = resp.StatusCode
	asset.FinalURL = resp.Request.URL.String()
	asset.ContentType = resp.Header.Get("Content-Type")
	asset.ContentLength = resp.ContentLength
	asset.Server = resp.Header.Get("Server")

	// Capture headers
	for k, v := range resp.Header {
		asset.Headers[k] = strings.Join(v, ", ")
	}

	// Security headers
	secHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-Permitted-Cross-Domain-Policies",
	}
	for _, h := range secHeaders {
		if val := resp.Header.Get(h); val != "" {
			asset.SecurityHeaders[h] = val
		}
	}

	// Parse body for title and tech detection
	bodyBytes := make([]byte, 1024*64) // 64KB max
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	body := string(bodyBytes[:n])

	asset.Title = extractTitle(body)
	asset.Technologies = detectTechnologies(body, asset.Headers)

	// TLS info
	if opts.ParseTLS && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		asset.TLSInfo = parseCert(resp.TLS.PeerCertificates[0])
	}

	return asset
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := body[start : start+end]
	if len(title) > 255 {
		title = title[:255]
	}
	return strings.TrimSpace(title)
}

func detectTechnologies(body string, headers map[string]string) []string {
	var techs []string

	// Server header detection
	if server, ok := headers["Server"]; ok {
		server = strings.ToLower(server)
		if strings.Contains(server, "nginx") {
			techs = append(techs, "Nginx")
		}
		if strings.Contains(server, "apache") {
			techs = append(techs, "Apache")
		}
		if strings.Contains(server, "iis") {
			techs = append(techs, "IIS")
		}
		if strings.Contains(server, "cloudflare") {
			techs = append(techs, "Cloudflare")
		}
	}

	// X-Powered-By
	if powered, ok := headers["X-Powered-By"]; ok {
		powered = strings.ToLower(powered)
		if strings.Contains(powered, "php") {
			techs = append(techs, "PHP")
		}
		if strings.Contains(powered, "asp.net") {
			techs = append(techs, "ASP.NET")
		}
		if strings.Contains(powered, "express") {
			techs = append(techs, "Express.js")
		}
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)
	techPatterns := map[string]string{
		"WordPress": "wp-content",
		"Drupal":    "drupal",
		"Joomla":    "joomla",
		"React":     "react.js",
		"Angular":   "angular",
		"Vue.js":    "vue.js",
		"jQuery":    "jquery",
		"Bootstrap": "bootstrap",
		"Tailwind":  "tailwindcss",
		"Next.js":   "__next",
		"Nuxt.js":   "__nuxt",
		"Laravel":   "laravel",
		"Django":    "csrfmiddlewaretoken",
		"Rails":     "rails",
	}

	for tech, pattern := range techPatterns {
		if strings.Contains(bodyLower, pattern) {
			techs = append(techs, tech)
		}
	}

	return unique(techs)
}

func parseCert(cert *x509.Certificate) *TLSInfo {
	info := &TLSInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Version:      cert.Version,
		IsExpired:    time.Now().After(cert.NotAfter),
		IsSelfSigned: cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName,
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	// SANs
	info.SANs = append(info.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	// Wildcard check
	for _, san := range info.SANs {
		if strings.HasPrefix(san, "*.") {
			info.IsWildcard = true
			break
		}
	}

	// Fingerprint
	fp := sha256.Sum256(cert.Raw)
	info.Fingerprint = hex.EncodeToString(fp[:])

	// Key info
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		info.KeyAlg = "RSA"
	case x509.ECDSA:
		info.KeyAlg = "ECDSA"
	case x509.Ed25519:
		info.KeyAlg = "Ed25519"
	}

	return info
}

func unique(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
