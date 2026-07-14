// Package metrics provides Prometheus instrumentation for Rayyan ASM.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rayyan",
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests.",
	}, []string{"method", "path", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "rayyan",
		Name:      "http_request_duration_seconds",
		Help:      "HTTP request latency.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "path"})

	ScanJobsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "rayyan",
		Name:      "scan_jobs_total",
		Help:      "Total scan jobs by type and status.",
	}, []string{"type", "status"})

	ScanJobDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "rayyan",
		Name:      "scan_job_duration_seconds",
		Help:      "Scan job execution time in seconds.",
		Buckets:   []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800},
	}, []string{"type"})

	QueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "rayyan",
		Name:      "queue_depth",
		Help:      "Number of jobs currently pending in the queue.",
	})

	ActiveScans = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "rayyan",
		Name:      "active_scans",
		Help:      "Number of currently running scan jobs.",
	})

	FindingsOpen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "rayyan",
		Name:      "findings_open",
		Help:      "Open findings by severity.",
	}, []string{"severity"})
)

// Middleware returns a Gin middleware that records HTTP metrics.
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		dur := time.Since(start).Seconds()
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}
		status := strconv.Itoa(c.Writer.Status())
		HTTPRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		HTTPRequestDuration.WithLabelValues(c.Request.Method, path).Observe(dur)
	}
}

// Handler returns the Prometheus HTTP handler for the /metrics endpoint.
func Handler() http.Handler {
	return promhttp.Handler()
}

// RecordScanComplete records a completed or cancelled scan job.
func RecordScanComplete(scanType, status string, duration time.Duration) {
	ScanJobsTotal.WithLabelValues(scanType, status).Inc()
	ScanJobDuration.WithLabelValues(scanType).Observe(duration.Seconds())
}
