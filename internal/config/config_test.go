package config

import "testing"

// TestLoad_ExternalAPIKeysFromEnv locks in a real bug: the External config
// section (Shodan/Censys/SecurityTrails/VirusTotal API keys) had no viper
// defaults registered, so viper.AutomaticEnv() never picked up the
// corresponding RAYYAN_EXTERNAL_* env vars at all — Load() always returned
// empty strings for these fields regardless of what was actually set in
// the environment. Fixed by registering empty-string defaults for each key
// in setDefaults(), the same pattern already used for auth.credentialkey.
func TestLoad_ExternalAPIKeysFromEnv(t *testing.T) {
	t.Setenv("RAYYAN_EXTERNAL_SHODANAPIKEY", "shodan-test-key")
	t.Setenv("RAYYAN_EXTERNAL_CENSYSAPIID", "censys-id")
	t.Setenv("RAYYAN_EXTERNAL_CENSYSAPISECRET", "censys-secret")
	t.Setenv("RAYYAN_EXTERNAL_SECURITYTRAILSKEY", "st-test-key")
	t.Setenv("RAYYAN_EXTERNAL_VIRUSTOTALKEY", "vt-test-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ShodanAPIKey", cfg.External.ShodanAPIKey, "shodan-test-key"},
		{"CensysAPIID", cfg.External.CensysAPIID, "censys-id"},
		{"CensysAPISecret", cfg.External.CensysAPISecret, "censys-secret"},
		{"SecurityTrailsKey", cfg.External.SecurityTrailsKey, "st-test-key"},
		{"VirusTotalKey", cfg.External.VirusTotalKey, "vt-test-key"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("cfg.External.%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestLoad_ExternalAPIKeysDefaultEmpty confirms the unset case stays a
// clean empty string (not "0", "<nil>", or some other zero-value artifact
// of the reflection-based unmarshal) — the downstream check in
// intelligence.Engine is a plain `== ""` comparison.
func TestLoad_ExternalAPIKeysDefaultEmpty(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if cfg.External.ShodanAPIKey != "" {
		t.Errorf("cfg.External.ShodanAPIKey = %q, want empty string when unset", cfg.External.ShodanAPIKey)
	}
}

// TestLoad_JWTSecretAndRedisPasswordFromEnv locks in a real bug that broke
// docker-compose startup: auth.jwtsecret and redis.password had no viper
// defaults registered (same AutomaticEnv trap as the External keys above),
// so RAYYAN_AUTH_JWTSECRET and RAYYAN_REDIS_PASSWORD were never bound —
// Load() always returned "" for both regardless of what docker-compose.yml
// set them to. That made main.go's production JWT-secret check always hit
// the "must be set in production" fatal (crash-looping the container and
// failing /health), and made the app connect to a password-protected Redis
// with no password (NOAUTH errors). Fixed by registering empty-string
// defaults in setDefaults(), same pattern as auth.credentialkey.
func TestLoad_JWTSecretAndRedisPasswordFromEnv(t *testing.T) {
	t.Setenv("RAYYAN_AUTH_JWTSECRET", "a-jwt-secret-at-least-32-bytes-long")
	t.Setenv("RAYYAN_REDIS_PASSWORD", "redis-test-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	if cfg.Auth.JWTSecret != "a-jwt-secret-at-least-32-bytes-long" {
		t.Errorf("cfg.Auth.JWTSecret = %q, want the env var value", cfg.Auth.JWTSecret)
	}
	if cfg.Redis.Password != "redis-test-password" {
		t.Errorf("cfg.Redis.Password = %q, want the env var value", cfg.Redis.Password)
	}
}
