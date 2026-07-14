package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api"
	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/api/websocket"
	"github.com/ShadooowX/rayyan-asm/internal/config"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules"
	"github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/ShadooowX/rayyan-asm/internal/modules/exposure"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/ShadooowX/rayyan-asm/internal/scheduler"
	"github.com/ShadooowX/rayyan-asm/pkg/logger"
	"github.com/google/uuid"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		// Can't use the structured logger before config loads — stderr is acceptable here.
		_, _ = os.Stderr.WriteString("FATAL: failed to load config: " + err.Error() + "\n")
		os.Exit(1)
	}

	log := logger.New(cfg.Log.Level, cfg.Log.Format)
	defer func() { _ = log.Sync() }()

	log.Info("Starting Rayyan ASM Platform",
		"version", cfg.App.Version,
		"environment", cfg.App.Environment,
	)

	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatal("failed to initialize database", "error", err)
	}

	if err := database.Migrate(db); err != nil {
		log.Fatal("failed to run migrations", "error", err)
	}

	var redisClient *queue.RedisClient
	if cfg.Redis.Enabled {
		redisClient, err = queue.NewRedisClient(cfg.Redis)
		if err != nil {
			log.Warn("Redis not available, using in-memory queue (token revocation disabled)", "error", err)
		}
	}

	isProd := cfg.App.Environment == "production"
	switch {
	case cfg.Auth.JWTSecret == "":
		if isProd {
			log.Fatal("RAYYAN_AUTH_JWTSECRET must be set in production (generate: openssl rand -hex 32)")
		}
		log.Warn("RAYYAN_AUTH_JWTSECRET is not set — insecure empty secret.")
	case cfg.Auth.JWTSecret == "change-this-secret-in-production":
		if isProd {
			log.Fatal("RAYYAN_AUTH_JWTSECRET is the default placeholder — replace it")
		}
		log.Warn("RAYYAN_AUTH_JWTSECRET is the default placeholder.")
	case len(cfg.Auth.JWTSecret) < 32:
		if isProd {
			log.Fatal("RAYYAN_AUTH_JWTSECRET must be at least 32 characters")
		}
		log.Warn("RAYYAN_AUTH_JWTSECRET is shorter than 32 characters.")
	}

	if isProd {
		if cfg.Auth.CredentialKey != "" {
			if _, err := cryptoutil.DecodeKey(cfg.Auth.CredentialKey); err != nil {
				log.Fatal("RAYYAN_AUTH_CREDENTIALKEY is invalid", "error", err)
			}
		} else {
			log.Warn("RAYYAN_AUTH_CREDENTIALKEY is not set — tool credential storage is disabled")
		}
	}

	jobQueue := queue.New(redisClient, cfg.Queue)

	// Wire dead-letter queue to DB so exhausted jobs are never silently dropped.
	jobQueue.SetDLQ(func(job queue.Job, lastErr error) {
		payloadBytes, _ := json.Marshal(job.Payload)
		var payload models.JSONB
		_ = json.Unmarshal(payloadBytes, &payload)
		entry := models.FailedJob{
			JobType:  job.Type,
			Payload:  payload,
			Error:    lastErr.Error(),
			Attempts: job.Attempts,
		}
		entry.ID = uuid.New()
		if err := db.Create(&entry).Error; err != nil {
			log.Warnw("failed to write job to DLQ", "job_type", job.Type, "error", err)
		} else {
			log.Warnw("job moved to DLQ", "job_type", job.Type, "attempts", job.Attempts, "error", lastErr)
		}
	})

	hub := websocket.NewHub()
	go hub.Run()

	var credKey []byte
	if cfg.Auth.CredentialKey != "" {
		if k, err := cryptoutil.DecodeKey(cfg.Auth.CredentialKey); err == nil {
			credKey = k
		} else {
			log.Warn("ignoring invalid RAYYAN_AUTH_CREDENTIALKEY", "error", err)
		}
	}
	handlers.SetNotificationCredentialKey(credKey)

	dispatcher := modules.NewDispatcher(db, hub, log, credKey)
	dispatcher.RegisterAll(jobQueue)
	log.Info("Scan modules registered: network, port, dns, web, full")

	// Wire proxy into discovery providers if configured.
	if cfg.Proxy.Enabled {
		proxyURL := cfg.Proxy.SOCKS5
		if proxyURL == "" {
			proxyURL = cfg.Proxy.HTTPS
		}
		if proxyURL == "" {
			proxyURL = cfg.Proxy.HTTP
		}
		discovery.InitHTTPClient(proxyURL)
		log.Infow("proxy configured for outbound HTTP", "url", proxyURL)
	}

	toolrunner.RegisterAll()

	// Verification spawns a subprocess per registered tool (~66 today) to
	// check its binary and version, each with up to a 10s hang-timeout
	// (see DetectVersion), run sequentially. Worst case that's minutes,
	// which used to block here — before the HTTP server started listening
	// at all, so /health was unreachable for the entire duration. Tool
	// status is inherently a "readiness" concern, not a "liveness" one:
	// the server can and should accept traffic (including /health)
	// immediately, with tool status filling in shortly after in the
	// background. Handlers that read the registry already treat
	// not-yet-verified tools the same as "missing" (their zero-value
	// Status), so nothing depends on this completing synchronously.
	go func() {
		log.Info("Verifying external tool installations...")
		toolrunner.DefaultRegistry.VerifyAll()
		toolrunner.PersistRegistryToDB(db, log)
		toolrunner.SyncRegistryFromDB(db, log)

		tools := toolrunner.DefaultRegistry.List()
		installed, missing := 0, 0
		for _, t := range tools {
			if t.Status == toolrunner.StatusInstalled {
				installed++
			} else {
				missing++
			}
		}
		log.Infow("External tool registry ready",
			"total", len(tools),
			"installed", installed,
			"missing", missing,
		)
		// If most/all scanning tools are missing, the operator is very likely
		// running the `dev` image (hot reload, no scanning binaries baked in)
		// instead of the `runtime`/production image — say so explicitly rather
		// than leaving them to guess why every tool shows "missing" in the UI.
		if len(tools) > 0 && installed < len(tools)/2 {
			log.Warnw("most external scanning tools are not installed — you may be running the dev image instead of production",
				"installed", installed,
				"total", len(tools),
				"hint", "run `docker compose -f docker-compose.yml up --build -d` (production image) instead of the docker-compose.dev.yml overlay",
			)
		}
	}()

	intelEngine := intelligence.New(db, log, intelligence.Config{
		ShodanKey:         cfg.External.ShodanAPIKey,
		CensysID:          cfg.External.CensysAPIID,
		CensysSecret:      cfg.External.CensysAPISecret,
		SecurityTrailsKey: cfg.External.SecurityTrailsKey,
		Proxy:             cfg.Proxy,
	})
	// Chains SecurityTrails (+ VirusTotal, via the API key directly) into
	// every Full/subdomain scan's subdomain step — see
	// Dispatcher.chainExtraSubdomainSources. Previously this engine was
	// only ever reachable from the standalone Intelligence page and the
	// scheduler's monitor jobs; scans themselves never saw it.
	dispatcher.SetIntelEngine(intelEngine)
	dispatcher.SetVirusTotalKey(cfg.External.VirusTotalKey)

	sched := scheduler.New(db, jobQueue, log)
	sched.SetCredentialKey(credKey)
	sched.SetIntelEngine(intelEngine)

	healthJob := toolrunner.NewToolHealthJob(db, log)
	sched.AddCron("0 3 * * *", func() { healthJob.Run() })

	riskEngine := riskscore.New(db, log)
	sched.AddCron("0 */4 * * *", func() { riskEngine.RecomputeAll() })

	// Continuous External Attack Surface Discovery: re-run discovery for
	// any org/seed-domain-set with an active daily/weekly/monthly cadence
	// that's due. Checked hourly; the cadence map itself enforces the
	// actual daily/weekly/monthly gap so this is cheap to poll often.
	sched.AddCron("0 * * * *", func() { sched.DispatchContinuousDiscovery() })

	sched.Start()

	exposureEngine := exposure.New(db, log)
	exposureWorker := exposure.NewWorker(exposureEngine, log, 5*time.Minute)
	exposureWorker.Start()

	router := api.NewRouter(cfg, db, redisClient, jobQueue, hub, log)

	srv := &http.Server{
		Addr:              cfg.Server.Address(),
		Handler:           router,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second, // protect against Slowloris
	}

	go func() {
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			log.Info("HTTPS server listening", "addr", cfg.Server.Address())
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				log.Fatal("server error", "error", err)
			}
		} else {
			if isProd {
				log.Warn("TLS is not configured — running HTTP in production is insecure")
			}
			log.Info("HTTP server listening", "addr", cfg.Server.Address())
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal("server error", "error", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sched.Stop()
	exposureWorker.Stop()
	jobQueue.Stop()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("server forced to shutdown", "error", err)
	}

	log.Info("Server exited gracefully")
}
