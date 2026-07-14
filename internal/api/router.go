package api

import (
	"net/http"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/api/websocket"
	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/ShadooowX/rayyan-asm/internal/config"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/modules/attackpath"
	"github.com/ShadooowX/rayyan-asm/internal/modules/changedetect"
	"github.com/ShadooowX/rayyan-asm/internal/modules/correlation"
	"github.com/ShadooowX/rayyan-asm/internal/modules/executive"
	"github.com/ShadooowX/rayyan-asm/internal/modules/exposure"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/ShadooowX/rayyan-asm/pkg/metrics"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func NewRouter(
	cfg *config.Config,
	db *gorm.DB,
	redis *queue.RedisClient,
	jobQueue *queue.Queue,
	hub *websocket.Hub,
	log *zap.SugaredLogger,
) *gin.Engine {
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(middleware.Recovery(log))
	r.Use(middleware.RequestID())
	r.Use(middleware.RequestLogger(log))
	r.Use(middleware.SecurityHeaders())
	r.Use(metrics.Middleware())

	allowedOrigins := cfg.Server.AllowedOrigins
	if len(allowedOrigins) == 0 {
		log.Warnw("server.allowedorigins is empty; falling back to localhost defaults",
			"defaults", []string{"http://localhost:5173", "http://localhost:3000"})
		allowedOrigins = []string{"http://localhost:5173", "http://localhost:3000"}
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type", "X-API-Key"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	authMgr := auth.NewManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.JWTExpiry,
		cfg.Auth.RefreshExpiry,
		cfg.Auth.BcryptCost,
	)

	// Wire Redis as the token revoker when available.
	var tokenRevoker middleware.TokenRevoker
	if redis != nil {
		tokenRevoker = redis
	}

	// cloudCredKey is the AES-256 key used to encrypt TOTP secrets and stored
	// cloud provider credentials at rest. Derived once here so it's available
	// to both the auth handler and the cloud credential handler below.
	var cloudCredKey []byte
	if cfg.Auth.CredentialKey != "" {
		if k, err := cryptoutil.DecodeKey(cfg.Auth.CredentialKey); err == nil {
			cloudCredKey = k
		}
	}

	authHandler := handlers.NewAuthHandler(db, authMgr, log)
	authHandler.SetRevoke(tokenRevoker)
	authHandler.SetAppURL(cfg.App.URL)
	if len(cloudCredKey) > 0 {
		authHandler.SetCredKey(cloudCredKey)
	}

	userHandler := handlers.NewUserHandler(db, authMgr, log)
	orgHandler := handlers.NewOrgHandler(db, log)
	domainHandler := handlers.NewDomainHandler(db, log)
	hostHandler := handlers.NewHostHandler(db, log)
	serviceHandler := handlers.NewServiceHandler(db, log)
	certHandler := handlers.NewCertificateHandler(db, log)
	dnsHandler := handlers.NewDNSHandler(db, log)
	scanHandler := handlers.NewScanHandler(db, jobQueue, hub, log)
	alertHandler := handlers.NewAlertHandler(db, log)
	reportHandler := handlers.NewReportHandler(db, jobQueue, log)
	searchHandler := handlers.NewSearchHandler(db, log)
	savedSearchHandler := handlers.NewSavedSearchHandler(db, log)
	dashboardHandler := handlers.NewDashboardHandler(db, log)
	cloudHandler := handlers.NewCloudHandler(db, log)
	techHandler := handlers.NewTechnologyHandler(db, log)
	apiKeyHandler := handlers.NewAPIKeyHandler(db, authMgr, log)
	auditHandler := handlers.NewAuditHandler(db, log)
	findingHandler := handlers.NewFindingHandler(db, log)
	riskEngine := riskscore.New(db, log)
	riskHandler := handlers.NewRiskScoreHandler(db, log, riskEngine)
	correlationEngine := correlation.New(db, log)
	correlationHandler := handlers.NewCorrelationHandler(db, log, correlationEngine)
	graphHandler := handlers.NewGraphHandler(db, log, correlationEngine)
	attackPathEngine := attackpath.New(db, log)
	attackPathHandler := handlers.NewAttackPathHandler(db, log, attackPathEngine)
	changeDetectEngine := changedetect.New(db, log)
	changeDetectHandler := handlers.NewChangeDetectHandler(db, log, changeDetectEngine)
	executiveEngine := executive.New(db, log)
	executiveHandler := handlers.NewExecutiveHandler(db, log, executiveEngine)
	exposureEngine := exposure.New(db, log)
	exposureHandler := exposure.NewHandler(db, log, exposureEngine)
	intelEngine := intelligence.New(db, log, intelligence.Config{
		ShodanKey:         cfg.External.ShodanAPIKey,
		CensysID:          cfg.External.CensysAPIID,
		CensysSecret:      cfg.External.CensysAPISecret,
		SecurityTrailsKey: cfg.External.SecurityTrailsKey,
	})
	intelHandler := handlers.NewIntelligenceHandler(db, log, intelEngine)
	toolHandler := handlers.NewToolHandler(toolrunner.DefaultRegistry, hub, db, log)
	credentialHandler := handlers.NewCredentialHandler(db, log, cfg.Auth.CredentialKey)
	// cloudCredHandler manages stored encrypted cloud provider credentials used
	// by the scheduler for automatic daily cloud asset syncs.
	cloudCredHandler := handlers.NewCloudCredentialHandler(db, log, cloudCredKey)
	projectHandler := handlers.NewProjectHandler(db, log)
	noteHandler := handlers.NewNoteHandler(db, log)
	todoHandler := handlers.NewTodoHandler(db, log)
	notifHandler := handlers.NewNotificationHandler(db, log)
	toolboxHandler := handlers.NewToolboxHandler(db, log)
	discoveryHandler := handlers.NewDiscoveryHandler(db, jobQueue, log)
	screenshotHandler := handlers.NewScreenshotHandler(db, log)
	importExportHandler := handlers.NewImportExportHandler(db, log)
	wsTicketHandler := handlers.NewWSTicketHandler(db, log)
	serviceHistoryHandler := handlers.NewServiceHistoryHandler(db, log)
	adminOps := handlers.NewAdminOpsHandler(db, log)

	health := func(c *gin.Context) {
		tools := toolrunner.DefaultRegistry.List()
		installed := 0
		for _, t := range tools {
			if t.Status == toolrunner.StatusInstalled {
				installed++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"status":                "ok",
			"version":               cfg.App.Version,
			"tools_installed_count": installed,
			"tools_total_count":     len(tools),
		})
	}
	r.GET("/health", health)
	r.GET("/api/health", health)
	// Prometheus metrics — restrict to internal/localhost in production via nginx.
	r.GET("/metrics", gin.WrapH(metrics.Handler()))

	// WebSocket upgrade — uses a one-time ticket issued by POST /api/v1/ws/ticket.
	// Tickets expire after 30 seconds and are single-use, so the JWT never
	// appears in URLs, server logs, or browser history.
	r.GET("/ws", func(c *gin.Context) {
		ticket := c.Query("ticket")
		if ticket == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "ws ticket required — obtain one via POST /api/v1/ws/ticket"})
			return
		}
		orgID, ok := handlers.GlobalWSTicketStore.Consume(ticket)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired ws ticket"})
			return
		}
		websocket.ServeWS(hub, c.Writer, c.Request, orgID.String())
	})

	v1 := r.Group("/api/v1")

	loginLimiter := middleware.RateLimit(10, time.Minute)
	registerLimiter := middleware.RateLimit(5, time.Minute)
	passwordResetLimiter := middleware.RateLimit(5, 15*time.Minute)
	mfaLimiter := middleware.RateLimit(5, time.Minute)
	if cfg.App.Environment == "test" {
		noop := func(c *gin.Context) { c.Next() }
		loginLimiter, registerLimiter, passwordResetLimiter, mfaLimiter = noop, noop, noop, noop
	}

	v1.POST("/auth/login", loginLimiter, authHandler.Login)
	v1.POST("/auth/register", registerLimiter, authHandler.Register)
	v1.POST("/auth/refresh", authHandler.RefreshToken)
	v1.POST("/auth/forgot-password", passwordResetLimiter, authHandler.ForgotPassword)
	v1.POST("/auth/reset-password", passwordResetLimiter, authHandler.ResetPassword)
	v1.GET("/auth/verify-email", authHandler.VerifyEmail)
	v1.POST("/auth/resend-verification", authHandler.ResendVerification)

	authMiddleware := middleware.AuthWithRevocation(authMgr, db, tokenRevoker)

	// Global per-user rate limit: 300 requests per minute across all protected
	// endpoints. This is a last-resort backstop against runaway clients or
	// credential-stuffed API keys — individual high-risk endpoints (auth,
	// password reset, MFA) have their own tighter limiters applied below.
	globalAPILimiter := middleware.RateLimit(300, time.Minute)

	protected := v1.Group("/")
	protected.Use(authMiddleware)
	protected.Use(globalAPILimiter)
	protected.Use(middleware.AuditLog(db, log))
	{
		protected.POST("/auth/logout", authHandler.Logout)
		// WebSocket ticket — single-use 30s token, avoids JWT in WS URL query string.
		protected.POST("/ws/ticket", wsTicketHandler.Issue)
		protected.GET("/auth/me", authHandler.Me)
		protected.PUT("/auth/me", authHandler.UpdateMe)
		protected.POST("/auth/change-password", authHandler.ChangePassword)
		protected.POST("/auth/mfa/enable", authHandler.EnableMFA)
		protected.POST("/auth/mfa/verify", mfaLimiter, authHandler.VerifyMFA)
		protected.POST("/auth/mfa/disable", authHandler.DisableMFA)

		protected.GET("/dashboard", dashboardHandler.Summary)
		protected.GET("/dashboard/trends", dashboardHandler.Trends)
		protected.GET("/dashboard/top-assets", dashboardHandler.TopAssets)
		protected.GET("/dashboard/risk-score", dashboardHandler.RiskScore)

		protected.GET("/executive/summary", executiveHandler.Summary)
		protected.GET("/executive/trends", executiveHandler.Trends)
		protected.GET("/executive/sla-compliance", executiveHandler.SLACompliance)
		protected.GET("/executive/attack-path-overview", executiveHandler.AttackPathOverview)
		protected.GET("/executive/business-impact", executiveHandler.BusinessImpact)
		protected.POST("/executive/recompute", middleware.RequireRole("admin", "analyst"), executiveHandler.Recompute)

		adminOrg := protected.Group("/org")
		adminOrg.Use(middleware.RequireRole("admin"))
		{
			adminOrg.GET("", orgHandler.Get)
			adminOrg.PUT("", orgHandler.Update)
			adminOrg.GET("/settings", orgHandler.GetSettings)
			adminOrg.PUT("/settings", orgHandler.UpdateSettings)
		}

		protected.GET("/users", middleware.RequireRole("admin"), userHandler.List)
		protected.POST("/users", middleware.RequireRole("admin"), userHandler.Create)
		protected.GET("/users/:id", userHandler.Get)
		protected.PUT("/users/:id", middleware.RequireRole("admin"), userHandler.Update)
		protected.DELETE("/users/:id", middleware.RequireRole("admin"), userHandler.Delete)

		protected.GET("/apikeys", apiKeyHandler.List)
		protected.POST("/apikeys", apiKeyHandler.Create)
		protected.DELETE("/apikeys/:id", apiKeyHandler.Delete)

		protected.GET("/domains", domainHandler.List)
		protected.POST("/domains", middleware.RequireRole("admin", "analyst"), domainHandler.Create)
		protected.GET("/domains/:id", domainHandler.Get)
		protected.PUT("/domains/:id", middleware.RequireRole("admin", "analyst"), domainHandler.Update)
		protected.DELETE("/domains/:id", middleware.RequireRole("admin"), domainHandler.Delete)
		protected.GET("/domains/:id/subdomains", domainHandler.Subdomains)
		protected.GET("/domains/:id/dns", domainHandler.DNSRecords)
		protected.GET("/domains/:id/email-security", dnsHandler.EmailSecurity)

		protected.GET("/subdomains", domainHandler.ListSubdomains)
		protected.GET("/subdomains/export", middleware.RequireRole("admin", "analyst"), adminOps.ExportSubdomains)
		protected.DELETE("/subdomains/bulk", middleware.RequireRole("admin", "analyst"), adminOps.BulkDeleteSubdomains)
		protected.GET("/subdomains/:id", domainHandler.GetSubdomain)

		protected.GET("/hosts", hostHandler.List)
		protected.POST("/hosts", middleware.RequireRole("admin", "analyst"), hostHandler.Create)
		protected.PUT("/hosts/bulk-tag", middleware.RequireRole("admin", "analyst"), hostHandler.BulkTag)
		protected.GET("/hosts/export", middleware.RequireRole("admin", "analyst"), adminOps.ExportHosts)
		protected.DELETE("/hosts/bulk", middleware.RequireRole("admin", "analyst"), adminOps.BulkDeleteHosts)
		protected.GET("/hosts/:id", hostHandler.Get)
		protected.PUT("/hosts/:id", middleware.RequireRole("admin", "analyst"), hostHandler.Update)
		protected.DELETE("/hosts/:id", middleware.RequireRole("admin"), hostHandler.Delete)
		protected.GET("/hosts/:id/services", hostHandler.Services)
		protected.GET("/hosts/:id/port-history", serviceHistoryHandler.ForHost)
		protected.PUT("/subdomains/bulk-tag", middleware.RequireRole("admin", "analyst"), domainHandler.BulkTagSubdomains)

		protected.GET("/services", serviceHandler.List)
		protected.GET("/services/diff", adminOps.ServiceDiff)
		protected.GET("/services/:id", serviceHandler.Get)

		protected.GET("/certificates", certHandler.List)
		protected.GET("/certificates/expiring", certHandler.Expiring)
		protected.GET("/certificates/:id", certHandler.Get)

		protected.GET("/dns", dnsHandler.List)
		protected.GET("/technologies", techHandler.List)
		protected.GET("/technologies/summary", techHandler.Summary)

		protected.GET("/cloud", cloudHandler.List)
		protected.POST("/cloud/sync", middleware.RequireRole("admin", "analyst"), cloudHandler.Sync)
		protected.POST("/cloud/scan", middleware.RequireRole("admin", "analyst"), cloudHandler.ScanAssets)
		protected.GET("/cloud/scan/findings", cloudHandler.ListCloudScanFindings)

		// Cloud provider credentials — stored encrypted creds for the
		// scheduler-driven automatic daily cloud asset sync.
		protected.GET("/cloud/credentials", cloudCredHandler.List)
		protected.POST("/cloud/credentials", middleware.RequireRole("admin", "analyst"), cloudCredHandler.Create)
		protected.PATCH("/cloud/credentials/:id", middleware.RequireRole("admin", "analyst"), cloudCredHandler.Update)
		protected.DELETE("/cloud/credentials/:id", middleware.RequireRole("admin"), cloudCredHandler.Delete)
		protected.POST("/cloud/credentials/:id/sync", middleware.RequireRole("admin", "analyst"), cloudCredHandler.TriggerSync)

		protected.GET("/takeover", cloudHandler.ListTakeover)
		protected.GET("/takeover/stats", cloudHandler.TakeoverStats)

		protected.GET("/scans", scanHandler.List)
		protected.POST("/scans", middleware.RequireRole("admin", "analyst"), scanHandler.Create)
		protected.GET("/scans/:id", scanHandler.Get)
		protected.DELETE("/scans/:id", middleware.RequireRole("admin", "analyst"), scanHandler.Cancel)
		protected.GET("/scans/:id/results", scanHandler.Results)
		protected.POST("/scans/:id/rerun", middleware.RequireRole("admin", "analyst"), scanHandler.Rerun)
		protected.GET("/scans/:id/diff/:other_id", scanHandler.Diff)

		protected.GET("/alerts", alertHandler.List)
		protected.GET("/alerts/:id", alertHandler.Get)
		protected.PUT("/alerts/:id/acknowledge", alertHandler.Acknowledge)
		protected.PUT("/alerts/:id/resolve", alertHandler.Resolve)

		protected.GET("/reports", reportHandler.List)
		protected.POST("/reports", middleware.RequireRole("admin", "analyst"), reportHandler.Generate)
		protected.GET("/reports/:id", reportHandler.Get)
		protected.GET("/reports/:id/download", reportHandler.Download)
		protected.DELETE("/reports/:id", middleware.RequireRole("admin"), reportHandler.Delete)

		protected.GET("/search", searchHandler.Search)
		protected.GET("/search/suggestions", searchHandler.Suggestions)
		protected.GET("/saved-searches", savedSearchHandler.List)
		protected.POST("/saved-searches", savedSearchHandler.Create)
		protected.DELETE("/saved-searches/:id", savedSearchHandler.Delete)
		protected.POST("/saved-searches/:id/use", savedSearchHandler.Use)

		protected.GET("/findings", findingHandler.List)
		protected.GET("/findings/summary", findingHandler.Summary)
		protected.GET("/findings/export", middleware.RequireRole("admin", "analyst"), findingHandler.Export)
		protected.GET("/findings/sla-report", adminOps.SLAReport)
		protected.POST("/findings", middleware.RequireRole("admin", "analyst"), findingHandler.Create)
		protected.POST("/findings/bulk", middleware.RequireRole("admin", "analyst"), findingHandler.BulkUpdate)
		protected.PUT("/findings/bulk-ignore", middleware.RequireRole("admin", "analyst"), adminOps.BulkIgnoreFindings)
		protected.DELETE("/findings/bulk", middleware.RequireRole("admin", "analyst"), adminOps.BulkDeleteFindings)
		protected.GET("/findings/:id", findingHandler.Get)
		protected.PUT("/findings/:id", middleware.RequireRole("admin", "analyst"), findingHandler.Update)
		protected.PUT("/findings/:id/acknowledge", middleware.RequireRole("admin", "analyst"), findingHandler.Acknowledge)
		protected.PUT("/findings/:id/false-positive", middleware.RequireRole("admin", "analyst"), findingHandler.FalsePositive)
		protected.PUT("/findings/:id/fix", middleware.RequireRole("admin", "analyst"), findingHandler.MarkFixed)
		protected.DELETE("/findings/:id", middleware.RequireRole("admin"), findingHandler.Delete)

		protected.GET("/audit", middleware.RequireRole("admin"), auditHandler.List)

		toolsGroup := protected.Group("/tools")
		toolsGroup.Use(middleware.RequireRole("admin"))
		{
			toolsGroup.GET("", toolHandler.List)
			toolsGroup.POST("/verify-all", toolHandler.VerifyAll)
			toolsGroup.POST("/install", toolHandler.Install)
			toolsGroup.GET("/:name", toolHandler.Get)
			toolsGroup.POST("/:name/verify", toolHandler.Verify)
			toolsGroup.POST("/:name/enable", toolHandler.Enable)
			toolsGroup.POST("/:name/disable", toolHandler.Disable)
			toolsGroup.GET("/:name/runs", toolHandler.Runs)
			toolsGroup.PATCH("/:name/rate-limits", toolHandler.SetRateLimits)
		}

		credsGroup := protected.Group("/tool-credentials")
		credsGroup.Use(middleware.RequireRole("admin"))
		{
			credsGroup.GET("", credentialHandler.List)
			credsGroup.POST("", credentialHandler.Create)
			credsGroup.DELETE("/:id", credentialHandler.Delete)
		}

		cloudCredsGroup := protected.Group("/cloud-credentials")
		{
			cloudCredsGroup.GET("", cloudCredHandler.List)
			cloudCredsGroup.POST("", middleware.RequireRole("admin"), cloudCredHandler.Create)
			cloudCredsGroup.PUT("/:id", middleware.RequireRole("admin"), cloudCredHandler.Update)
			cloudCredsGroup.DELETE("/:id", middleware.RequireRole("admin"), cloudCredHandler.Delete)
			cloudCredsGroup.POST("/:id/sync", middleware.RequireRole("admin", "analyst"), cloudCredHandler.TriggerSync)
		}

		projGroup := protected.Group("/projects")
		{
			projGroup.GET("", projectHandler.List)
			projGroup.POST("", middleware.RequireRole("admin", "analyst"), projectHandler.Create)
			projGroup.GET("/:id", projectHandler.Get)
			projGroup.PUT("/:id", middleware.RequireRole("admin", "analyst"), projectHandler.Update)
			projGroup.DELETE("/:id", middleware.RequireRole("admin"), projectHandler.Delete)
		}

		noteGroup := protected.Group("/notes")
		{
			noteGroup.GET("", noteHandler.List)
			noteGroup.POST("", noteHandler.Create)
			noteGroup.GET("/:id", noteHandler.Get)
			noteGroup.PUT("/:id", noteHandler.Update)
			noteGroup.DELETE("/:id", noteHandler.Delete)
		}

		todoGroup := protected.Group("/todos")
		{
			todoGroup.GET("", todoHandler.List)
			todoGroup.POST("", todoHandler.Create)
			todoGroup.GET("/:id", todoHandler.Get)
			todoGroup.PUT("/:id", todoHandler.Update)
			todoGroup.DELETE("/:id", todoHandler.Delete)
		}

		notifGroup := protected.Group("/notifications")
		{
			notifGroup.GET("", notifHandler.List)
			notifGroup.POST("", middleware.RequireRole("admin"), notifHandler.Create)
			notifGroup.PUT("/:id", middleware.RequireRole("admin"), notifHandler.Update)
			notifGroup.DELETE("/:id", middleware.RequireRole("admin"), notifHandler.Delete)
			notifGroup.POST("/:id/test", middleware.RequireRole("admin"), notifHandler.Test)
		}

		toolboxGroup := protected.Group("/toolbox")
		{
			toolboxGroup.GET("/status", toolboxHandler.Status)
			toolboxGroup.GET("/whois", toolboxHandler.Whois)
			toolboxGroup.GET("/port-scan", toolboxHandler.PortScan)
			toolboxGroup.GET("/cms-detect", toolboxHandler.CMSDetect)
			toolboxGroup.GET("/cve/:cve_id", toolboxHandler.CVELookup)
			toolboxGroup.GET("/related-domains", toolboxHandler.RelatedDomains)
			toolboxGroup.GET("/insights", toolboxHandler.FindingsInsights)
			toolboxGroup.GET("/tls-check", toolboxHandler.TLSCheck)
			toolboxGroup.GET("/geoip", toolboxHandler.GeoIP)
		}

		screenshotGroup := protected.Group("/screenshots")
		{
			screenshotGroup.GET("", screenshotHandler.List)
			screenshotGroup.GET("/gallery", adminOps.ListScreenshots)
			screenshotGroup.POST("/capture", middleware.RequireRole("admin", "analyst"), screenshotHandler.Capture)
			screenshotGroup.GET("/:id", screenshotHandler.Get)
		}

		protected.POST("/domains/:id/import-subdomains", middleware.RequireRole("admin", "analyst"), importExportHandler.ImportSubdomains)
		protected.GET("/domains/:id/export-subdomains", middleware.RequireRole("admin", "analyst"), importExportHandler.ExportSubdomains)
		protected.POST("/hosts/import", middleware.RequireRole("admin", "analyst"), importExportHandler.ImportTargets)

		protected.GET("/asn-ranges", adminOps.ListASNRanges)
		protected.POST("/asn-ranges/expand", middleware.RequireRole("admin", "analyst"), adminOps.ExpandASN)
		protected.DELETE("/asn-ranges", middleware.RequireRole("admin"), adminOps.DeleteASNRanges)

		protected.GET("/whois-history", adminOps.GetWHOISHistory)
		protected.POST("/whois-history/snap", middleware.RequireRole("admin", "analyst"), adminOps.SnapWHOIS)

		protected.PUT("/findings/:id/sla", middleware.RequireRole("admin", "analyst"), adminOps.SetFindingSLA)
		protected.PUT("/findings/:id/risk-accept", middleware.RequireRole("admin", "analyst"), adminOps.AcceptRisk)
		protected.DELETE("/findings/:id/risk-accept", middleware.RequireRole("admin", "analyst"), adminOps.RevokeRiskAcceptance)

		protected.PUT("/domains/:id/cadence", middleware.RequireRole("admin", "analyst"), adminOps.SetDomainCadence)

		riskGroup := protected.Group("/risk")
		{
			riskGroup.GET("/assets", riskHandler.Assets)
			riskGroup.GET("/trends", riskHandler.Trends)
			riskGroup.GET("/heatmap", riskHandler.Heatmap)
			riskGroup.POST("/recompute", middleware.RequireRole("admin", "analyst"), riskHandler.Recompute)
		}

		correlationGroup := protected.Group("/correlation")
		{
			correlationGroup.GET("/graph", correlationHandler.Graph)
			correlationGroup.GET("/related/:type/:id", correlationHandler.Related)
			correlationGroup.GET("/exposure-path", correlationHandler.ExposurePath)
			correlationGroup.POST("/rebuild", middleware.RequireRole("admin", "analyst"), correlationHandler.Rebuild)
		}

		graphGroup := protected.Group("/graph")
		{
			graphGroup.GET("/assets/:id", graphHandler.Asset)
			graphGroup.GET("/neighbors/:id", graphHandler.Neighbors)
			graphGroup.GET("/path", graphHandler.Path)
			graphGroup.GET("/stats", graphHandler.Stats)
			graphGroup.GET("/asset-stats", graphHandler.AssetStats)
		}

		attackPathGroup := protected.Group("/attack-paths")
		{
			attackPathGroup.GET("", attackPathHandler.List)
			attackPathGroup.POST("/recompute", middleware.RequireRole("admin", "analyst"), attackPathHandler.Recompute)
		}

		changesGroup := protected.Group("/changes")
		{
			changesGroup.GET("/timeline", changeDetectHandler.Timeline)
			changesGroup.POST("/run", middleware.RequireRole("admin", "analyst"), changeDetectHandler.Run)
		}

		discoveryGroup := protected.Group("/discovery")
		{
			discoveryGroup.POST("/start", middleware.RequireRole("admin", "analyst"), discoveryHandler.Start)
			discoveryGroup.GET("/jobs", discoveryHandler.Jobs)
			discoveryGroup.GET("/jobs/:id", discoveryHandler.Job)
			discoveryGroup.DELETE("/jobs/:id", middleware.RequireRole("admin", "analyst"), discoveryHandler.Cancel)
			discoveryGroup.GET("/dashboard", discoveryHandler.Dashboard)
			discoveryGroup.GET("/events", discoveryHandler.Events)
			discoveryGroup.GET("/changes", discoveryHandler.Changes)
			discoveryGroup.GET("/assets", discoveryHandler.Assets)
			discoveryGroup.GET("/risk-flags", discoveryHandler.RiskFlags)
			discoveryGroup.PUT("/risk-flags/:id/resolve", middleware.RequireRole("admin", "analyst"), discoveryHandler.ResolveRiskFlag)
		}

		exposureGroup := protected.Group("/exposure")
		{
			exposureGroup.GET("/assets", exposureHandler.Assets)
			exposureGroup.GET("/dashboard", exposureHandler.Dashboard)
			exposureGroup.GET("/:id", exposureHandler.Detail)
			exposureGroup.POST("/recompute", middleware.RequireRole("admin", "analyst"), exposureHandler.Recompute)
		}

		intelGroup := protected.Group("/intelligence")
		{
			intelGroup.GET("/results", intelHandler.ListResults)
			intelGroup.POST("/enrich/host", middleware.RequireRole("admin", "analyst"), intelHandler.EnrichHost)
			intelGroup.POST("/enrich/domain", middleware.RequireRole("admin", "analyst"), intelHandler.EnrichDomain)
			intelGroup.GET("/monitors", intelHandler.ListMonitors)
			intelGroup.POST("/monitors", middleware.RequireRole("admin", "analyst"), intelHandler.CreateMonitor)
			intelGroup.PUT("/monitors/:id/toggle", middleware.RequireRole("admin", "analyst"), intelHandler.ToggleMonitor)
			intelGroup.DELETE("/monitors/:id", middleware.RequireRole("admin", "analyst"), intelHandler.DeleteMonitor)
		}

		protected.GET("/webhook-deliveries", adminOps.ListWebhookDeliveries)
		protected.POST("/webhook-deliveries/:id/retry", middleware.RequireRole("admin", "analyst"), adminOps.RetryWebhook)

		protected.GET("/org/backup", middleware.RequireRole("admin"), adminOps.BackupOrg)
		protected.POST("/org/restore", middleware.RequireRole("admin"), adminOps.RestoreOrg)

		protected.GET("/org/scan-limits", adminOps.GetOrgScanLimits)
		protected.PUT("/org/plan", middleware.RequireRole("admin"), adminOps.SetOrgPlan)

		protected.POST("/scan/udp-probe", middleware.RequireRole("admin", "analyst"), adminOps.UDPProbe)

		protected.GET("/auth/theme", adminOps.GetTheme)
		protected.PUT("/auth/theme", adminOps.SetTheme)
	}

	r.Static("/assets", "./frontend/dist/assets")
	r.NoRoute(func(c *gin.Context) {
		c.File("./frontend/dist/index.html")
	})

	return r
}
