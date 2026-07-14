package config

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"
)

// memDBCounter generates unique in-memory SQLite database names so that each
// call to DSN() with FilePath == ":memory:" gets its own isolated database
// instead of sharing the process-wide "file::memory:?cache=shared" instance.
var memDBCounter uint64

type Config struct {
	App      AppConfig
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Queue    QueueConfig
	Auth     AuthConfig
	Log      LogConfig
	External ExternalConfig
	Proxy    ProxyConfig
}

type AppConfig struct {
	Name        string
	Version     string
	Environment string // development, staging, production
	Debug       bool
	URL         string // base URL for reset links
}

type ServerConfig struct {
	Host           string
	Port           int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	TLSEnabled     bool
	TLSCert        string
	TLSKey         string
	AllowedOrigins []string
}

func (s ServerConfig) Address() string {
	return net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
}

type DatabaseConfig struct {
	Driver   string // postgres, sqlite
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
	FilePath string // for SQLite
	MaxOpen  int
	MaxIdle  int
	MaxLife  time.Duration
}

func (d DatabaseConfig) DSN() string {
	if d.Driver == "sqlite" {
		if d.FilePath == "" {
			d.FilePath = "rayyan-asm.db"
		}
		if d.FilePath == ":memory:" {
			// A plain ":memory:" DSN gives every new pooled connection its
			// own empty database. Shared-cache mode fixes that but makes ALL
			// in-process callers share one DB — tests bleed state into each
			// other. A unique named DB per call keeps multi-connection safety
			// while giving each caller full isolation.
			n := atomic.AddUint64(&memDBCounter, 1)
			return fmt.Sprintf("file:mem%d?mode=memory&cache=shared&_busy_timeout=5000", n)
		}
		return fmt.Sprintf("file:%s?_busy_timeout=5000", d.FilePath)
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode)
}

type RedisConfig struct {
	Enabled  bool
	Host     string
	Port     int
	Password string
	DB       int
}

func (r RedisConfig) Address() string {
	return net.JoinHostPort(r.Host, fmt.Sprintf("%d", r.Port))
}

type QueueConfig struct {
	Workers    int
	BufferSize int
}

type AuthConfig struct {
	JWTSecret        string
	JWTExpiry        time.Duration
	RefreshExpiry    time.Duration
	APIKeyLength     int
	MFAEnabled       bool
	BcryptCost       int
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	// CredentialKey is the AES-256 key (base64 or hex, 32 bytes decoded)
	// used to encrypt external tool credentials (internal/crypto). Set via
	// RAYYAN_AUTH_CREDENTIALKEY. Must be set in production.
	CredentialKey string
}

type LogConfig struct {
	Level  string
	Format string // json, console
}

type ExternalConfig struct {
	ShodanAPIKey      string
	CensysAPIID       string
	CensysAPISecret   string
	SecurityTrailsKey string
	VirusTotalKey     string
}

// ProxyConfig holds optional HTTP/SOCKS proxy settings for outbound tool traffic.
type ProxyConfig struct {
	HTTP    string // e.g. http://127.0.0.1:8080
	HTTPS   string // e.g. http://127.0.0.1:8080
	SOCKS5  string // e.g. socks5://127.0.0.1:1080
	NoProxy string // comma-separated hosts to bypass
	Enabled bool
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/rayyan-asm")

	viper.SetEnvPrefix("RAYYAN")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

func setDefaults() {
	viper.SetDefault("app.name", "Rayyan ASM")
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.debug", false)

	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.readtimeout", "30s")
	viper.SetDefault("server.allowedorigins", []string{"http://localhost:5173", "http://localhost:3000"})
	viper.SetDefault("server.writetimeout", "60s")
	viper.SetDefault("server.idletimeout", "120s")

	viper.SetDefault("database.driver", "sqlite")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "rayyan_asm")
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.maxopen", 25)
	viper.SetDefault("database.maxidle", 5)
	viper.SetDefault("database.maxlife", "5m")

	viper.SetDefault("redis.enabled", false)
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	// Same AutomaticEnv trap as auth.credentialkey / external.* below: without
	// this SetDefault, RAYYAN_REDIS_PASSWORD was never bound, so cfg.Redis.Password
	// unmarshaled to "" no matter what the env var was set to — the app then
	// connected to Redis with no password and got NOAUTH errors even when
	// docker-compose.yml's REDIS_PASSWORD/--requirepass were correctly set.
	viper.SetDefault("redis.password", "")

	viper.SetDefault("queue.workers", 10)
	viper.SetDefault("queue.buffersize", 1000)

	viper.SetDefault("auth.jwtexpiry", "24h")
	viper.SetDefault("auth.refreshexpiry", "168h")
	viper.SetDefault("auth.apikeylength", 32)
	viper.SetDefault("auth.bcryptcost", 12)
	viper.SetDefault("auth.maxloginattempts", 5)
	viper.SetDefault("auth.lockoutduration", "15m")
	viper.SetDefault("auth.credentialkey", "")
	// Same AutomaticEnv trap: without this, RAYYAN_AUTH_JWTSECRET was never
	// bound, so cfg.Auth.JWTSecret unmarshaled to "" regardless of what the
	// env var held — main.go's isProd check then always hit the
	// JWTSecret == "" fatal branch, crash-looping the container forever and
	// failing the /health check no matter what secret was configured.
	viper.SetDefault("auth.jwtsecret", "")
	viper.SetDefault("auth.mfaenabled", false)

	viper.SetDefault("app.url", "")
	viper.SetDefault("server.tlsenabled", false)
	viper.SetDefault("server.tlscert", "")
	viper.SetDefault("server.tlskey", "")

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")

	// Empty-string defaults, same pattern as auth.credentialkey above: this
	// is what makes viper.AutomaticEnv() actually pick up
	// RAYYAN_EXTERNAL_SHODANAPIKEY / _CENSYSAPIID / _CENSYSAPISECRET /
	// _SECURITYTRAILSKEY / _VIRUSTOTALKEY. Without registering the key
	// somehow (a default, a config-file entry, or an explicit BindEnv),
	// AutomaticEnv has nothing to attach the env var to and Unmarshal
	// leaves the field at its zero value even when the env var is set.
	viper.SetDefault("external.shodanapikey", "")
	viper.SetDefault("external.censysapiid", "")
	viper.SetDefault("external.censysapisecret", "")
	viper.SetDefault("external.securitytrailskey", "")
	viper.SetDefault("external.virustotalkey", "")
}
