package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Sends an alert to all active NotificationConfigs in the org that match the
// alert type and minimum severity.

var severityOrder = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// notifCredentialKey is the decoded 32-byte AES-256 key used to decrypt
// stored SMTP passwords on NotificationConfig. It mirrors the
// RAYYAN_AUTH_CREDENTIALKEY pattern already used for tool_credentials (see
// internal/crypto and CredentialHandler). Set once at startup via
// SetNotificationCredentialKey, called from cmd/server/main.go alongside
// the other consumers of the decoded key. DispatchAlertNotifications is a
// free function invoked from many places (scheduler, findings, admin_ops,
// the notification Test endpoint) that don't otherwise have a natural place
// to carry the key, so it's threaded through this package-level variable
// rather than changing every call site's signature.
var notifCredentialKey []byte

// SetNotificationCredentialKey installs the decoded AES-256 credential key
// used to decrypt SMTP passwords for email notifications. If never called
// (or called with nil), email notification dispatch fails closed with a
// clear error rather than sending unauthenticated or silently broken mail.
func SetNotificationCredentialKey(key []byte) {
	notifCredentialKey = key
}

// DispatchAlertNotifications fires webhook/email calls for all matching configs.
// Called from the scheduler and anywhere a new alert is persisted.
func DispatchAlertNotifications(db *gorm.DB, log *zap.SugaredLogger, alert *models.Alert) {
	var configs []models.NotificationConfig
	if err := db.Where("org_id = ? AND active = true", alert.OrgID).
		Find(&configs).Error; err != nil || len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		cfg := cfg // capture
		if !matchesConfig(cfg, alert) {
			continue
		}
		go dispatchOne(db, log, cfg, alert)
	}
}

// dispatchOne sends alert to a single NotificationConfig's channel and
// records the resulting WebhookDelivery row. Extracted from
// DispatchAlertNotifications so DispatchTestNotification (the "Test"
// button on a specific config) can send to exactly that one config without
// re-querying/filtering every active config in the org — previously the
// Test endpoint called DispatchAlertNotifications with a synthetic "test"
// alert, which (a) fanned out to every active config in the org instead of
// just the one being tested, and (b) silently dropped the test entirely for
// any config with an AlertTypes filter that didn't include "test", making
// the test button falsely report success while delivering nothing.
func dispatchOne(db *gorm.DB, log *zap.SugaredLogger, cfg models.NotificationConfig, alert *models.Alert) {
	var err error
	var statusCode int
	endpoint := cfg.WebhookURL
	if cfg.Channel == "telegram" {
		endpoint = "telegram:" + cfg.ChatID
	} else if cfg.Channel == "email" {
		endpoint = "smtp:" + cfg.SMTPHost + ":" + strings.Join(cfg.SMTPTo, ",")
	}

	switch cfg.Channel {
	case "slack":
		statusCode, err = sendSlackWithStatus(cfg.WebhookURL, alert)
	case "discord":
		statusCode, err = sendDiscordWithStatus(cfg.WebhookURL, alert)
	case "telegram":
		err = sendTelegram(cfg.BotToken, cfg.ChatID, alert)
		if err == nil {
			statusCode = 200
		}
	case "teams":
		statusCode, err = sendTeamsWithStatus(cfg.WebhookURL, alert)
	case "siem":
		statusCode, err = sendSIEMWithStatus(cfg, alert)
	case "email":
		err = sendEmail(cfg, alert)
		if err == nil {
			statusCode = 250 // SMTP "OK" — there's no HTTP status here, but
			// 250 reads correctly in delivery logs/UI as the success code
			// for the protocol actually in play.
		}
	default:
		err = fmt.Errorf("unknown channel %q", cfg.Channel)
	}

	success := err == nil
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
		log.Warnw("notification dispatch failed",
			"channel", cfg.Channel, "name", cfg.Name, "error", err)
	}

	// Log delivery
	cfgID := cfg.ID
	alertID := alert.ID
	delivery := models.WebhookDelivery{
		OrgID:         alert.OrgID,
		NotifConfigID: &cfgID,
		AlertID:       &alertID,
		Channel:       cfg.Channel,
		Endpoint:      endpoint,
		StatusCode:    statusCode,
		Success:       success,
		ErrorMessage:  errMsg,
		SentAt:        time.Now(),
	}
	delivery.ID = uuid.New()
	delivery.CreatedAt = time.Now()
	if err := db.Create(&delivery).Error; err != nil {
		log.Warnw("failed to record webhook delivery", "alert_id", alert.ID, "error", err)
	}
}

// DispatchTestNotification sends a synthetic "test" alert directly to the
// given config, bypassing matchesConfig's severity/AlertTypes filters
// (those filters exist to gate real alerts, not a deliberate test that the
// operator asked for by ID) and without touching any other config in the
// org.
func DispatchTestNotification(db *gorm.DB, log *zap.SugaredLogger, cfg models.NotificationConfig, alert *models.Alert) {
	go dispatchOne(db, log, cfg, alert)
}

func matchesConfig(cfg models.NotificationConfig, alert *models.Alert) bool {
	// Severity filter
	minOrd, ok := severityOrder[cfg.MinSeverity]
	if !ok {
		minOrd = 0
	}
	alertOrd := severityOrder[alert.Severity]
	if alertOrd < minOrd {
		return false
	}
	// Alert type filter (empty = all)
	if len(cfg.AlertTypes) > 0 {
		found := false
		for _, t := range cfg.AlertTypes {
			if t == alert.Type {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sendSlackWithStatus(webhookURL string, alert *models.Alert) (int, error) {
	color := severityColor(alert.Severity)
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Title),
				"text":   alert.Message,
				"footer": "Rayyan ASM • " + time.Now().Format("2006-01-02 15:04 UTC"),
				"fields": []map[string]interface{}{
					{"title": "Type", "value": alert.Type, "short": true},
					{"title": "Severity", "value": alert.Severity, "short": true},
				},
			},
		},
	}
	return postJSONWithStatus(webhookURL, payload)
}

func sendDiscordWithStatus(webhookURL string, alert *models.Alert) (int, error) {
	color := severityColorInt(alert.Severity)
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Title),
				"description": alert.Message,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "Type", "value": alert.Type, "inline": true},
					{"name": "Severity", "value": alert.Severity, "inline": true},
				},
				"footer":    map[string]string{"text": "Rayyan ASM"},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	return postJSONWithStatus(webhookURL, payload)
}

func sendTelegram(botToken, chatID string, alert *models.Alert) error {
	if botToken == "" || chatID == "" {
		return fmt.Errorf("telegram: missing bot_token or chat_id")
	}
	text := fmt.Sprintf("🚨 *[%s] %s*\n\n%s\n\n_Type: %s • %s_",
		strings.ToUpper(alert.Severity),
		escapeMarkdown(alert.Title),
		escapeMarkdown(alert.Message),
		alert.Type,
		time.Now().Format("2006-01-02 15:04 UTC"),
	)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	return postJSON(url, payload)
}

// sendTeamsWithStatus posts an Office 365 connector "MessageCard" to a Teams
// incoming webhook. Teams connector cards are the legacy but still widely
// supported format (Adaptive Cards via Power Automate workflows are the
// newer path, but require a different webhook shape entirely and aren't
// universally available on free/legacy connectors), so this targets the
// MessageCard schema for broadest compatibility.
func sendTeamsWithStatus(webhookURL string, alert *models.Alert) (int, error) {
	if webhookURL == "" {
		return 0, fmt.Errorf("teams: missing webhook_url")
	}
	themeColor := severityColorHexNoHash(alert.Severity)
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Title),
		"themeColor": themeColor,
		"title":      fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.Title),
		"text":       alert.Message,
		"sections": []map[string]interface{}{
			{
				"facts": []map[string]string{
					{"name": "Type", "value": alert.Type},
					{"name": "Severity", "value": alert.Severity},
					{"name": "Time", "value": time.Now().Format("2006-01-02 15:04 UTC")},
				},
			},
		},
	}
	return postJSONWithStatus(webhookURL, payload)
}

// siemEvent is the normalized, flat JSON schema posted to SIEM/SOAR
// collectors. Kept intentionally flat and field-named close to Splunk's
// HEC "event" body / CEF-style key names (severity, event_type, host-like
// "source") rather than nested chat-message shapes (Slack attachments,
// Discord embeds), since SIEM ingest pipelines generally expect to map
// each field directly onto an index/schema rather than parse presentation
// markup out of a chat payload.
type siemEvent struct {
	Source    string    `json:"source"`
	EventType string    `json:"event_type"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	AlertID   uuid.UUID `json:"alert_id"`
	OrgID     uuid.UUID `json:"org_id"`
	Timestamp time.Time `json:"timestamp"`
}

// sendSIEMWithStatus posts a normalized alert event to a generic SIEM/SOAR
// HTTP collector (Splunk HEC, a generic ingest endpoint, a Tines/Torq
// webhook, etc). Unlike the Slack/Discord/Teams webhooks above, SIEM/SOAR
// collectors almost universally require an auth token rather than relying
// on the secrecy of the URL, so this sets whatever header the operator
// configured (defaulting to "Authorization") using the decrypted token.
func sendSIEMWithStatus(cfg models.NotificationConfig, alert *models.Alert) (int, error) {
	if cfg.WebhookURL == "" {
		return 0, fmt.Errorf("siem: missing webhook_url")
	}
	token, err := decryptAuthToken(cfg.AuthTokenEncrypted)
	if err != nil {
		return 0, fmt.Errorf("siem: %w", err)
	}

	event := siemEvent{
		Source:    "rayyan-asm",
		EventType: alert.Type,
		Severity:  alert.Severity,
		Title:     alert.Title,
		Message:   alert.Message,
		AlertID:   alert.ID,
		OrgID:     alert.OrgID,
		Timestamp: time.Now().UTC(),
	}

	header := cfg.AuthHeader
	if header == "" {
		header = "Authorization"
	}

	body, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		// Splunk HEC's convention is "Authorization: Splunk <token>"; most
		// other generic collectors expect a bare token or "Bearer <token>"
		// on whatever header they name. Since the operator already chose
		// the header explicitly for their collector, the token is set
		// as-is rather than guessing a scheme prefix that could be wrong
		// for a non-Splunk collector.
		req.Header.Set(header, token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("siem collector returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// EncryptAuthToken encrypts a SIEM/SOAR auth token for storage on a
// NotificationConfig, reusing the same RAYYAN_AUTH_CREDENTIALKEY-derived
// key as SMTP passwords and tool credentials.
func EncryptAuthToken(plaintext string) (string, error) {
	if len(notifCredentialKey) != 32 {
		return "", fmt.Errorf("siem notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)")
	}
	return cryptoutil.Encrypt(notifCredentialKey, []byte(plaintext))
}

func decryptAuthToken(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	if len(notifCredentialKey) != 32 {
		return "", fmt.Errorf("credential storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)")
	}
	plaintext, err := cryptoutil.Decrypt(notifCredentialKey, encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt siem auth token: %w", err)
	}
	return string(plaintext), nil
}

// sendEmail delivers an alert over SMTP using the config's stored connection
// details. The password is decrypted on demand with notifCredentialKey and
// never logged. Supports implicit TLS (port 465), STARTTLS (typically 587),
// and unencrypted relays only when SMTPUseTLS is explicitly false (e.g. a
// local mail relay on a trusted network).
func sendEmail(cfg models.NotificationConfig, alert *models.Alert) error {
	if cfg.SMTPHost == "" {
		return fmt.Errorf("email: missing smtp_host")
	}
	if len(cfg.SMTPTo) == 0 {
		return fmt.Errorf("email: missing smtp_to recipients")
	}
	if cfg.SMTPFrom == "" {
		return fmt.Errorf("email: missing smtp_from")
	}

	password, err := decryptSMTPPassword(cfg.SMTPPasswordEncrypted)
	if err != nil {
		return fmt.Errorf("email: %w", err)
	}

	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, fmt.Sprintf("%d", port))

	subject := fmt.Sprintf("[Rayyan ASM] [%s] %s", strings.ToUpper(alert.Severity), alert.Title)
	body := buildEmailBody(alert)

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", cfg.SMTPFrom))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(cfg.SMTPTo, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	var auth smtp.Auth
	if cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, password, cfg.SMTPHost)
	}

	// Implicit TLS (commonly port 465): the connection itself is TLS from
	// the first byte, so smtp.SendMail (which expects to speak plaintext
	// then optionally STARTTLS) can't be used as-is.
	if cfg.SMTPUseTLS && port == 465 {
		return sendEmailImplicitTLS(addr, cfg.SMTPHost, auth, cfg.SMTPFrom, cfg.SMTPTo, msg.Bytes())
	}

	// STARTTLS (587/25 with TLS) or fully unencrypted (only when the
	// operator explicitly set smtp_use_tls=false): smtp.SendMail negotiates
	// STARTTLS automatically when the server advertises it and PlainAuth is
	// used, so this single call covers both of those cases.
	return smtp.SendMail(addr, auth, cfg.SMTPFrom, cfg.SMTPTo, msg.Bytes())
}

// sendEmailImplicitTLS handles SMTPS (implicit TLS, classically port 465),
// which net/smtp's SendMail helper does not support directly since it
// always dials in plaintext first.
func sendEmailImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer func() { _ = tlsConn.Close() }()

	client, err := smtp.NewClient(tlsConn, host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", addr, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
}

func buildEmailBody(alert *models.Alert) string {
	return fmt.Sprintf(
		"%s\n\n%s\n\nType: %s\nSeverity: %s\nTime: %s\n\n--\nRayyan ASM",
		alert.Title,
		alert.Message,
		alert.Type,
		strings.ToUpper(alert.Severity),
		time.Now().Format("2006-01-02 15:04 UTC"),
	)
}

// EncryptSMTPPassword encrypts an SMTP password for storage on a
// NotificationConfig, using the same credential key configured via
// RAYYAN_AUTH_CREDENTIALKEY as tool_credentials. Returns an error if the key
// hasn't been installed via SetNotificationCredentialKey (e.g. the operator
// never set RAYYAN_AUTH_CREDENTIALKEY) so callers can surface a clear 503
// instead of silently storing an unusable or plaintext secret.
func EncryptSMTPPassword(plaintext string) (string, error) {
	if len(notifCredentialKey) != 32 {
		return "", fmt.Errorf("email notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)")
	}
	return cryptoutil.Encrypt(notifCredentialKey, []byte(plaintext))
}

// NotificationCredentialKeyConfigured reports whether the AES-256 key needed
// to store/send SMTP passwords has been installed. Handlers use this to
// reject email config creation early with a clear error instead of letting
// it fail later inside a background goroutine during dispatch.
func NotificationCredentialKeyConfigured() bool {
	return len(notifCredentialKey) == 32
}

func decryptSMTPPassword(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	if len(notifCredentialKey) != 32 {
		return "", fmt.Errorf("credential storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)")
	}
	plaintext, err := cryptoutil.Decrypt(notifCredentialKey, encrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt smtp password: %w", err)
	}
	return string(plaintext), nil
}

func postJSON(url string, payload interface{}) error {
	_, err := postJSONWithStatus(url, payload)
	return err
}

func postJSONWithStatus(url string, payload interface{}) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func severityColor(s string) string {
	switch s {
	case "critical":
		return "#9b1c1c"
	case "high":
		return "#c05621"
	case "medium":
		return "#b7791f"
	case "low":
		return "#2b6cb0"
	default:
		return "#4a5568"
	}
}

func severityColorInt(s string) int {
	switch s {
	case "critical":
		return 0x9b1c1c
	case "high":
		return 0xc05621
	case "medium":
		return 0xb7791f
	case "low":
		return 0x2b6cb0
	default:
		return 0x4a5568
	}
}

// severityColorHexNoHash returns the severity color as a bare 6-digit hex
// string with no leading '#', which is the format Teams' MessageCard
// themeColor field expects (unlike Slack's attachment "color", which wants
// the '#' prefix).
func severityColorHexNoHash(s string) string {
	switch s {
	case "critical":
		return "9b1c1c"
	case "high":
		return "c05621"
	case "medium":
		return "b7791f"
	case "low":
		return "2b6cb0"
	default:
		return "4a5568"
	}
}

func escapeMarkdown(s string) string {
	r := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "~", "\\~", "`", "\\`",
	)
	return r.Replace(s)
}
