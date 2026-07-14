package changedetect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Engine struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func New(db *gorm.DB, log *zap.SugaredLogger) *Engine {
	return &Engine{db: db, log: log}
}

type snapshot struct {
	Label  string
	Fields map[string]string
}

// Summary is returned from a detection run.
type Summary struct {
	OrgID       uuid.UUID      `json:"org_id"`
	EventsFound int            `json:"events_found"`
	ByType      map[string]int `json:"by_type"`
	DurationMS  int64          `json:"duration_ms"`
}

var trackedTypes = []string{"domain", "subdomain", "host", "service", "certificate", "dns_record", "technology"}

// RunDetection snapshots current state across every tracked asset type,
// diffs it against the last known baseline, records any differences as
// AssetChangeEvent rows, and advances the baseline to the current state.
func (e *Engine) RunDetection(orgID uuid.UUID) (Summary, error) {
	start := time.Now()
	now := time.Now()
	byType := make(map[string]int, len(trackedTypes))
	total := 0

	builders := map[string]func() (map[string]snapshot, error){
		"domain":      func() (map[string]snapshot, error) { return e.snapshotDomains(orgID) },
		"subdomain":   func() (map[string]snapshot, error) { return e.snapshotSubdomains(orgID) },
		"host":        func() (map[string]snapshot, error) { return e.snapshotHosts(orgID) },
		"service":     func() (map[string]snapshot, error) { return e.snapshotServices(orgID) },
		"certificate": func() (map[string]snapshot, error) { return e.snapshotCertificates(orgID) },
		"dns_record":  func() (map[string]snapshot, error) { return e.snapshotDNSRecords(orgID) },
		"technology":  func() (map[string]snapshot, error) { return e.snapshotTechnologies(orgID) },
	}

	for _, assetType := range trackedTypes {
		current, err := builders[assetType]()
		if err != nil {
			return Summary{}, err
		}
		events, err := e.diffAndPersist(orgID, assetType, current, now)
		if err != nil {
			return Summary{}, err
		}
		byType[assetType] = len(events)
		total += len(events)
	}

	return Summary{OrgID: orgID, EventsFound: total, ByType: byType, DurationMS: time.Since(start).Milliseconds()}, nil
}

// Timeline returns recent change events for an org, optionally filtered by
// asset type and/or change type.
func (e *Engine) Timeline(orgID uuid.UUID, assetType, changeType string, limit int) ([]models.AssetChangeEvent, error) {
	q := e.db.Where("org_id = ?", orgID)
	if assetType != "" {
		q = q.Where("asset_type = ?", assetType)
	}
	if changeType != "" {
		q = q.Where("change_type = ?", changeType)
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var events []models.AssetChangeEvent
	if err := q.Order("detected_at desc, created_at desc").Limit(limit).Find(&events).Error; err != nil {
		return nil, err
	}
	return events, nil
}

func (e *Engine) diffAndPersist(orgID uuid.UUID, assetType string, current map[string]snapshot, now time.Time) ([]models.AssetChangeEvent, error) {
	var prevRows []models.AssetStateSnapshot
	if err := e.db.Where("org_id = ? AND asset_type = ?", orgID, assetType).Find(&prevRows).Error; err != nil {
		return nil, err
	}
	prevByKey := make(map[string]models.AssetStateSnapshot, len(prevRows))
	for _, r := range prevRows {
		prevByKey[r.AssetKey] = r
	}

	var events []models.AssetChangeEvent
	var toCreate []models.AssetStateSnapshot
	var toUpdate []models.AssetStateSnapshot
	var staleIDs []uuid.UUID

	for key, cur := range current {
		fields := models.JSONB{}
		for k, v := range cur.Fields {
			fields[k] = v
		}
		prev, existed := prevByKey[key]
		if !existed {
			events = append(events, models.AssetChangeEvent{
				ID: uuid.New(), OrgID: orgID, AssetType: assetType, AssetKey: key, AssetLabel: cur.Label,
				ChangeType: "new", DetectedAt: now,
			})
			toCreate = append(toCreate, models.AssetStateSnapshot{
				ID: uuid.New(), OrgID: orgID, AssetType: assetType, AssetKey: key, Label: cur.Label, Fields: fields, UpdatedAt: now,
			})
			continue
		}

		changed := false
		for field, newVal := range cur.Fields {
			oldVal, _ := prev.Fields[field].(string)
			if oldVal != newVal {
				changed = true
				events = append(events, models.AssetChangeEvent{
					ID: uuid.New(), OrgID: orgID, AssetType: assetType, AssetKey: key, AssetLabel: cur.Label,
					ChangeType: "changed", Field: field, OldValue: oldVal, NewValue: newVal, DetectedAt: now,
				})
			}
		}
		if changed || prev.Label != cur.Label {
			prev.Label = cur.Label
			prev.Fields = fields
			prev.UpdatedAt = now
			toUpdate = append(toUpdate, prev)
		}
	}

	for key, prev := range prevByKey {
		if _, ok := current[key]; !ok {
			events = append(events, models.AssetChangeEvent{
				ID: uuid.New(), OrgID: orgID, AssetType: assetType, AssetKey: key, AssetLabel: prev.Label,
				ChangeType: "removed", DetectedAt: now,
			})
			staleIDs = append(staleIDs, prev.ID)
		}
	}

	if len(toCreate) > 0 {
		if err := e.db.CreateInBatches(&toCreate, 200).Error; err != nil {
			return nil, err
		}
	}
	for _, row := range toUpdate {
		if err := e.db.Save(&row).Error; err != nil {
			return nil, err
		}
	}
	if len(staleIDs) > 0 {
		if err := e.db.Where("id IN ?", staleIDs).Delete(&models.AssetStateSnapshot{}).Error; err != nil {
			return nil, err
		}
	}
	if len(events) > 0 {
		if err := e.db.CreateInBatches(&events, 200).Error; err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (e *Engine) snapshotDomains(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, d := range rows {
		out[strings.ToLower(d.Name)] = snapshot{
			Label: d.Name,
			Fields: map[string]string{
				"status": d.Status, "environment": d.Environment, "registrar": d.Registrar,
			},
		}
	}
	return out, nil
}

func (e *Engine) snapshotSubdomains(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, s := range rows {
		ips := append([]string{}, s.IPs...)
		sort.Strings(ips)
		out[strings.ToLower(s.FQDN)] = snapshot{
			Label: s.FQDN,
			Fields: map[string]string{
				"ips": strings.Join(ips, ","), "dead": strconv.FormatBool(s.Dead), "status": s.Status,
			},
		}
	}
	return out, nil
}

func (e *Engine) snapshotHosts(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, h := range rows {
		out[h.IP] = snapshot{
			Label: h.IP,
			Fields: map[string]string{
				"status": h.Status, "os_version": h.OSVersion, "hostname": h.Hostname,
			},
		}
	}
	return out, nil
}

func serviceKey(hostRef string, hostID uuid.UUID, port int, protocol string) string {
	anchor := hostRef
	if anchor == "" {
		anchor = hostID.String()
	}
	return fmt.Sprintf("%s:%d/%s", anchor, port, protocol)
}

func (e *Engine) snapshotServices(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, s := range rows {
		key := serviceKey(s.HostRef, s.HostID, s.Port, s.Protocol)
		label := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		if s.HostRef != "" {
			label = s.HostRef + ":" + label
		}
		out[key] = snapshot{
			Label: label,
			Fields: map[string]string{
				"state": s.State, "version": s.Version, "product": s.Product,
			},
		}
	}
	return out, nil
}

func expiryStatus(notAfter, now time.Time) string {
	if notAfter.Before(now) {
		return "expired"
	}
	if notAfter.Before(now.Add(30 * 24 * time.Hour)) {
		return "expiring_soon"
	}
	return "valid"
}

func (e *Engine) snapshotCertificates(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Certificate
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	now := time.Now()
	out := make(map[string]snapshot, len(rows))
	for _, c := range rows {
		anchor := c.Subject
		if c.ServiceID != nil {
			anchor = c.ServiceID.String()
		}
		out[anchor] = snapshot{
			Label: c.Subject,
			Fields: map[string]string{
				"fingerprint":   c.Fingerprint,
				"expiry_status": expiryStatus(c.NotAfter, now),
			},
		}
	}
	return out, nil
}

func (e *Engine) snapshotDNSRecords(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.DNSRecord
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, r := range rows {
		key := strings.ToLower(r.Type) + "|" + strings.ToLower(r.Name) + "|" + r.Value
		out[key] = snapshot{
			Label: fmt.Sprintf("%s %s -> %s", r.Type, r.Name, r.Value),
			Fields: map[string]string{
				"ttl": strconv.Itoa(r.TTL), "priority": strconv.Itoa(r.Priority),
			},
		}
	}
	return out, nil
}

func (e *Engine) snapshotTechnologies(orgID uuid.UUID) (map[string]snapshot, error) {
	var rows []models.Technology
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]snapshot, len(rows))
	for _, t := range rows {
		anchor := "unbound"
		if t.ServiceID != nil {
			anchor = t.ServiceID.String()
		}
		key := anchor + "|" + strings.ToLower(t.Name)
		out[key] = snapshot{Label: t.Name, Fields: map[string]string{"version": t.Version}}
	}
	return out, nil
}
