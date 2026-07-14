package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func startTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestScanHTTP200(t *testing.T) {
	srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Test Page</title></head><body>Hello WordPress wp-content</body></html>`))
	})

	s := web.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Strip scheme from URL for scanner input
	host := srv.Listener.Addr().String()

	ch, err := s.Scan(ctx, web.ScanOptions{
		Targets:  []string{host},
		Workers:  1,
		Timeout:  3 * time.Second,
		ParseTLS: false,
	})
	require.NoError(t, err)

	var assets []web.WebAsset
	for a := range ch {
		assets = append(assets, a)
	}

	// Should have at least one successful scan (http://)
	var found *web.WebAsset
	for i := range assets {
		if assets[i].StatusCode == 200 {
			found = &assets[i]
			break
		}
	}
	require.NotNil(t, found, "should have found a 200 response")

	assert.Equal(t, 200, found.StatusCode)
	assert.Equal(t, "Test Page", found.Title)
	assert.Equal(t, "TestServer/1.0", found.Server)
	assert.Equal(t, "DENY", found.SecurityHeaders["X-Frame-Options"])
	assert.Contains(t, found.Technologies, "WordPress")
}

func TestScanHTTP404(t *testing.T) {
	srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	s := web.NewScanner(zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := s.Scan(ctx, web.ScanOptions{
		Targets: []string{srv.Listener.Addr().String()},
		Workers: 1,
		Timeout: 3 * time.Second,
	})
	require.NoError(t, err)

	var found bool
	for a := range ch {
		if a.StatusCode == 404 {
			found = true
		}
	}
	assert.True(t, found)
}

func TestDetectTechnologies(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers map[string]string
		want    []string
	}{
		{
			name:    "react detection",
			body:    `<div id="__next">hello</div>`,
			headers: map[string]string{"Server": "nginx"},
			want:    []string{"Nginx", "Next.js"},
		},
		{
			name:    "wordpress detection",
			body:    `<link rel="stylesheet" href="/wp-content/themes/x.css">`,
			headers: map[string]string{"X-Powered-By": "PHP/8.1"},
			want:    []string{"PHP", "WordPress"},
		},
		{
			name:    "drupal detection",
			body:    `<meta name="Generator" content="Drupal 9">`,
			headers: map[string]string{"Server": "Apache"},
			want:    []string{"Apache", "Drupal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
				_, _ = w.Write([]byte(tt.body))
			})

			s := web.NewScanner(zap.NewNop().Sugar())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			ch, err := s.Scan(ctx, web.ScanOptions{
				Targets: []string{srv.Listener.Addr().String()},
				Workers: 1,
				Timeout: 3 * time.Second,
			})
			require.NoError(t, err)

			var techs []string
			for a := range ch {
				techs = append(techs, a.Technologies...)
			}

			for _, expected := range tt.want {
				assert.Contains(t, techs, expected, "should detect %s", expected)
			}
		})
	}
}
