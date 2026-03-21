package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/netwise/agent/internal/network"
)

type LabelCandidate struct {
	Label        string         `json:"label"`
	Score        float64        `json:"score"`
	Confidence   float64        `json:"confidence"`
	Evidence     []string       `json:"evidence,omitempty"`
	SupportTiers map[string]int `json:"support_tiers,omitempty"` // strong|medium|weak|contextual
}

type LabelState struct {
	DeviceCategory            string           `json:"device_category"`
	DeviceSubType             string           `json:"device_subtype,omitempty"`
	LabelConfidence           float64          `json:"label_confidence"`
	LabelConfidenceCalibrated float64          `json:"label_confidence_calibrated"`
	EvidenceSummary           []string         `json:"evidence_summary,omitempty"`
	CandidateLabels           []LabelCandidate `json:"candidate_labels,omitempty"`
	ReasonChain               []string         `json:"reason_chain,omitempty"`
	ConflictFlags             []string         `json:"conflict_flags,omitempty"`
	ConfidenceBand            string           `json:"confidence_band,omitempty"`
}

// Device matches shared schema Device; optional fields for classification and sources.
type Device struct {
	ID                    string        `json:"id"`
	IP                    string        `json:"ip"`
	MAC                   string        `json:"mac"`
	Vendor                string        `json:"vendor"`
	MACIsLocallyAdmin     bool          `json:"mac_is_locally_admin,omitempty"`
	Hostname              *string       `json:"hostname"`
	ProtocolsSeen         ProtocolsSeen `json:"protocols_seen"`
	PortsOpen             []int         `json:"ports_open,omitempty"`
	FirstSeen             string        `json:"first_seen"`
	LastSeen              string        `json:"last_seen"`
	Flags                 []string      `json:"flags"`
	Confidence            float64       `json:"confidence"`
	DeviceType            string        `json:"device_type"`
	LabelState            LabelState    `json:"label_state,omitempty"`
	ClassificationReasons []string      `json:"classification_reasons,omitempty"`
	ManualLabel           string        `json:"manual_label,omitempty"`
	ManualLabelState      string        `json:"manual_label_state,omitempty"`
	ManualLabelSource     string        `json:"manual_label_source,omitempty"`
	ManualLabelUpdatedAt  string        `json:"manual_label_updated_at,omitempty"`
	SourcesSeen           []string      `json:"sources_seen,omitempty"` // arp, mdns, ssdp, tcp_probe
	Observations          []Observation `json:"observations,omitempty"`
	HTTPServer            string        `json:"http_server,omitempty"`
	SSDPServer            string        `json:"ssdp_server,omitempty"`
	TLSSubject            string        `json:"tls_subject,omitempty"`
	TLSIssuer             string        `json:"tls_issuer,omitempty"`
	TLSSANS               string        `json:"tls_san,omitempty"`
	SSHBanner             string        `json:"ssh_banner,omitempty"`
}

type Observation struct {
	Timestamp int64             `json:"timestamp"`
	Strategy  string            `json:"strategy"`
	IP        string            `json:"ip"`
	MAC       string            `json:"mac"`
	Hostname  string            `json:"hostname,omitempty"`
	Key       string            `json:"key"`
	Value     string            `json:"value"`
	Details   map[string]string `json:"details,omitempty"`
}

type ProtocolsSeen struct {
	MDNS    []string `json:"mdns"`
	SSDP    []string `json:"ssdp"`
	NetBIOS []string `json:"netbios"`
}

type NetworkInfo struct {
	Subnet        string `json:"subnet,omitempty"`
	GatewayIP     string `json:"gateway_ip,omitempty"`
	LocalIP       string `json:"local_ip,omitempty"`
	InterfaceName string `json:"interface_name,omitempty"`
	InterfaceMAC  string `json:"interface_mac,omitempty"`
	Netmask       string `json:"netmask,omitempty"`
	Broadcast     string `json:"broadcast,omitempty"`
	IsLargeSubnet bool   `json:"is_large_subnet,omitempty"`
}

type ScanResult struct {
	Network        NetworkInfo `json:"network"`
	Devices        []Device    `json:"devices"`
	ScanStartedAt  string      `json:"scan_started_at"`
	ScanFinishedAt *string     `json:"scan_finished_at"`
	ScanID         string      `json:"scan_id"`
}

type Event struct {
	Type     string          `json:"type"`
	ScanID   string          `json:"scan_id,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	Progress string          `json:"progress,omitempty"`
}

func NewScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano()/1e6)
}

func mergeStringSlices(a, b []string) []string {
	m := make(map[string]struct{})
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		m[s] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	return out
}

func mergeObservationSlices(a, b []Observation) []Observation {
	type key struct {
		strategy string
		key      string
		value    string
		ip       string
	}
	seen := make(map[key]struct{})
	out := make([]Observation, 0, len(a)+len(b))
	for _, o := range a {
		k := key{o.Strategy, o.Key, o.Value, o.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, o)
	}
	for _, o := range b {
		k := key{o.Strategy, o.Key, o.Value, o.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, o)
	}
	return out
}

const (
	manualLabelStrategy = "manual_operator_label_fallback"
	manualLabelKey      = "manual_label"
)

type Store struct {
	mu      sync.RWMutex
	scans   map[string]*ScanResult
	devices map[string]*Device
	latest  []Device
	subs    map[chan Event]struct{}
}

func New() *Store {
	return &Store{
		scans:   make(map[string]*ScanResult),
		devices: make(map[string]*Device),
		latest:  nil,
		subs:    make(map[chan Event]struct{}),
	}
}

func (st *Store) StartScan(scanID string, netInfo *network.Info) {
	now := time.Now().UTC().Format(time.RFC3339)
	st.scans[scanID] = &ScanResult{
		Network: NetworkInfo{
			Subnet:        netInfo.Subnet,
			GatewayIP:     netInfo.GatewayIP,
			LocalIP:       netInfo.LocalIP,
			InterfaceName: netInfo.InterfaceName,
			InterfaceMAC:  netInfo.InterfaceMAC,
			Netmask:       netInfo.Netmask,
			Broadcast:     netInfo.Broadcast,
			IsLargeSubnet: netInfo.IsLargeSubnet,
		},
		Devices:        []Device{},
		ScanStartedAt:  now,
		ScanFinishedAt: nil,
		ScanID:         scanID,
	}
	st.emit(Event{Type: "scan_started", ScanID: scanID})
}

func (st *Store) FinishScan(scanID string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.scans[scanID]; ok {
		now := time.Now().UTC().Format(time.RFC3339)
		s.ScanFinishedAt = &now
		st.emit(Event{Type: "scan_finished", ScanID: scanID})
	}
}

func (st *Store) AddOrUpdateDevice(scanID string, d Device) {
	st.mu.Lock()
	defer st.mu.Unlock()
	existing, ok := st.devices[d.ID]
	now := time.Now().UTC().Format(time.RFC3339)
	if !ok {
		d.FirstSeen = now
		d.LastSeen = now
		d.Flags = append(d.Flags, "new_device")
	} else {
		d.FirstSeen = existing.FirstSeen
		d.LastSeen = now
		if existing.IP != d.IP {
			d.Flags = append(d.Flags, "changed_ip")
		}
		// Merge sources_seen (union)
		d.SourcesSeen = mergeStringSlices(existing.SourcesSeen, d.SourcesSeen)
		if d.ManualLabel == "" && existing.ManualLabelState == "set" {
			d.ManualLabel = existing.ManualLabel
		}
		if d.ManualLabelState == "" {
			d.ManualLabelState = existing.ManualLabelState
		}
		if d.ManualLabelSource == "" {
			d.ManualLabelSource = existing.ManualLabelSource
		}
		if d.ManualLabelUpdatedAt == "" {
			d.ManualLabelUpdatedAt = existing.ManualLabelUpdatedAt
		}
		// Preserve/enrich protocols if existing had more
		if len(existing.ProtocolsSeen.MDNS) > len(d.ProtocolsSeen.MDNS) {
			d.ProtocolsSeen.MDNS = existing.ProtocolsSeen.MDNS
		}
		if len(existing.ProtocolsSeen.SSDP) > len(d.ProtocolsSeen.SSDP) {
			d.ProtocolsSeen.SSDP = existing.ProtocolsSeen.SSDP
		}
		d.Observations = mergeObservationSlices(existing.Observations, d.Observations)
	}
	st.devices[d.ID] = &d
	if scanID == "" {
		st.replaceDeviceInScansLocked(d)
	} else if s, ok := st.scans[scanID]; ok {
		found := false
		for i := range s.Devices {
			if s.Devices[i].ID == d.ID {
				s.Devices[i] = d
				found = true
				break
			}
		}
		if !found {
			s.Devices = append(s.Devices, d)
		}
	}
	st.rebuildLatest()
	payload, _ := json.Marshal(d)
	st.emit(Event{Type: "device_discovered", ScanID: scanID, Payload: payload})
}

func (st *Store) UpdateManualLabel(id, label, source, note string, clear bool) (*Device, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	existing, ok := st.devices[id]
	if !ok {
		return nil, fmt.Errorf("device not found")
	}

	updated := *existing
	now := time.Now().UTC().Format(time.RFC3339)
	updated.ManualLabelUpdatedAt = now
	updated.ManualLabelSource = strings.TrimSpace(source)
	if updated.ManualLabelSource == "" {
		updated.ManualLabelSource = "api"
	}

	updated.Observations = stripManualLabelObservations(updated.Observations)

	if clear || strings.TrimSpace(label) == "" {
		updated.ManualLabel = ""
		updated.ManualLabelState = "cleared"
	} else {
		normalized := strings.TrimSpace(label)
		updated.ManualLabel = normalized
		updated.ManualLabelState = "set"
		details := map[string]string{
			"source": updated.ManualLabelSource,
		}
		if trimmed := strings.TrimSpace(note); trimmed != "" {
			details["note"] = trimmed
		}
		updated.Observations = append(updated.Observations, Observation{
			Timestamp: time.Now().UTC().UnixMilli(),
			Strategy:  manualLabelStrategy,
			IP:        updated.IP,
			MAC:       updated.MAC,
			Hostname:  hostnameValue(updated.Hostname),
			Key:       manualLabelKey,
			Value:     normalized,
			Details:   details,
		})
	}

	st.devices[id] = &updated
	st.rebuildLatest()
	st.replaceDeviceInScansLocked(updated)
	payload, _ := json.Marshal(updated)
	st.emit(Event{Type: "device_updated", ScanID: id, Payload: payload})

	cp := updated
	return &cp, nil
}

func (st *Store) rebuildLatest() {
	st.latest = make([]Device, 0, len(st.devices))
	for _, d := range st.devices {
		st.latest = append(st.latest, *d)
	}
}

func (st *Store) replaceDeviceInScansLocked(updated Device) {
	for _, scan := range st.scans {
		if scan == nil {
			continue
		}
		for i := range scan.Devices {
			if scan.Devices[i].ID == updated.ID {
				scan.Devices[i] = updated
			}
		}
	}
}

func (st *Store) EmitProgress(scanID, msg string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.emit(Event{Type: "progress", ScanID: scanID, Progress: msg})
}

func (st *Store) emit(e Event) {
	for ch := range st.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (st *Store) GetScanResult(scanID string) *ScanResult {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.scans[scanID]
}

func (st *Store) GetLatestDevices() []Device {
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.latest == nil {
		return []Device{}
	}
	out := make([]Device, len(st.latest))
	copy(out, st.latest)
	return out
}

func (st *Store) GetDevice(id string) *Device {
	st.mu.RLock()
	defer st.mu.RUnlock()
	d, ok := st.devices[id]
	if !ok {
		return nil
	}
	cp := *d
	return &cp
}

func (st *Store) Subscribe() chan Event {
	st.mu.Lock()
	defer st.mu.Unlock()
	ch := make(chan Event, 32)
	st.subs[ch] = struct{}{}
	return ch
}

func (st *Store) Unsubscribe(ch chan Event) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.subs, ch)
	close(ch)
}

func stripManualLabelObservations(in []Observation) []Observation {
	if len(in) == 0 {
		return nil
	}
	out := make([]Observation, 0, len(in))
	for _, obs := range in {
		if obs.Strategy == manualLabelStrategy && obs.Key == manualLabelKey {
			continue
		}
		out = append(out, obs)
	}
	return out
}

func hostnameValue(h *string) string {
	if h == nil {
		return ""
	}
	return strings.TrimSpace(*h)
}
