package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/network"
	"github.com/netwise/agent/internal/scanner"
	"github.com/netwise/agent/internal/store"
)

type Server struct {
	port     int
	version  string
	hostname string
	netInfo  *network.Info
	cfg      *config.Config
	store    *store.Store
	mu       sync.Mutex
}

type labelSummary struct {
	DeviceID         string           `json:"device_id"`
	IP               string           `json:"ip"`
	MAC              string           `json:"mac"`
	Hostname         string           `json:"hostname,omitempty"`
	DeviceType       string           `json:"device_type"`
	Confidence       float64          `json:"confidence"`
	ManualLabel      string           `json:"manual_label,omitempty"`
	ManualLabelState string           `json:"manual_label_state,omitempty"`
	LabelState       store.LabelState `json:"label_state"`
	CandidateCount   int              `json:"candidate_count"`
}

type labelDetailResponse struct {
	DeviceID        string                 `json:"device_id"`
	Device          store.Device           `json:"device"`
	LabelState      store.LabelState       `json:"label_state"`
	Evidence        []store.Observation    `json:"evidence"`
	CandidateLabels []store.LabelCandidate `json:"candidate_labels"`
}

type manualLabelRequest struct {
	Label  string `json:"label"`
	Clear  bool   `json:"clear,omitempty"`
	Source string `json:"source,omitempty"`
	Note   string `json:"note,omitempty"`
}

func NewServer(port int, version, hostname string, netInfo *network.Info, cfg *config.Config) *Server {
	return &Server{
		port:     port,
		version:  version,
		hostname: hostname,
		netInfo:  netInfo,
		cfg:      cfg,
		store:    store.New(),
	}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", methodGET(s.health))
	mux.HandleFunc("/info", methodGET(s.info))
	mux.HandleFunc("/scan/start", methodPOST(s.scanStart))
	mux.HandleFunc("/scan/", s.scanStatusRoute)
	mux.HandleFunc("/devices", methodGET(s.devices))
	mux.HandleFunc("/devices/", s.deviceByIDRoute)
	mux.HandleFunc("/labels", methodGET(s.labels))
	mux.HandleFunc("/labels/", s.labelsRoute)
	mux.HandleFunc("/events", methodGET(s.events))

	addr := "0.0.0.0:7777"
	log.Printf("API listening on %s", addr)
	return http.ListenAndServe(addr, cors(mux))
}

func methodGET(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
func methodPOST(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	nf := s.netInfo.ToNetworkFacts()
	info := map[string]interface{}{
		"version":      s.version,
		"hostname":     s.hostname,
		"local_ip":     s.netInfo.LocalIP,
		"subnet":       s.netInfo.Subnet,
		"cidr":         nf.CIDR,
		"netmask":      s.netInfo.Netmask,
		"broadcast":    s.netInfo.Broadcast,
		"gateway":      s.netInfo.GatewayIP,
		"interface":    s.netInfo.InterfaceName,
		"iface_mac":    s.netInfo.InterfaceMAC,
		"large_subnet": s.netInfo.IsLargeSubnet,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) scanStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	scanID := store.NewScanID()
	s.store.StartScan(scanID, s.netInfo)
	s.mu.Unlock()

	log.Printf("Scan started: %s", scanID)
	go s.runScan(scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func (s *Server) runScan(scanID string) {
	sc := scanner.New(s.netInfo, s.cfg, s.store, scanID)
	sc.Run()
	s.mu.Lock()
	s.store.FinishScan(scanID)
	result := s.store.GetScanResult(scanID)
	s.mu.Unlock()
	if result != nil {
		log.Printf("Scan finished: %s, %d devices", scanID, len(result.Devices))
	}
}

func (s *Server) scanStatusRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := path.Base(r.URL.Path)
	if scanID == "" || scanID == "scan" {
		http.Error(w, "missing scan_id", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	result := s.store.GetScanResult(scanID)
	s.mu.Unlock()
	if result == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	devices := s.store.GetLatestDevices()
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"devices": devices})
}

func (s *Server) labels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	devices := s.store.GetLatestDevices()
	s.mu.Unlock()

	summaries := make([]labelSummary, 0, len(devices))
	for _, d := range devices {
		summaries = append(summaries, summarizeLabel(d))
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Confidence != summaries[j].Confidence {
			return summaries[i].Confidence > summaries[j].Confidence
		}
		if summaries[i].DeviceType != summaries[j].DeviceType {
			return summaries[i].DeviceType < summaries[j].DeviceType
		}
		return summaries[i].DeviceID < summaries[j].DeviceID
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"labels": summaries,
		"count":  len(summaries),
	})
}

func (s *Server) labelsRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.labelDetail(w, r)
	case http.MethodPost:
		s.updateLabel(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) labelDetail(w http.ResponseWriter, r *http.Request) {
	id := path.Base(r.URL.Path)
	if id == "" || id == "labels" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	dev := s.store.GetDevice(id)
	s.mu.Unlock()
	if dev == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildLabelDetail(*dev, labelDetailPrivacyConfig(r)))
}

func (s *Server) updateLabel(w http.ResponseWriter, r *http.Request) {
	id := path.Base(r.URL.Path)
	if id == "" || id == "labels" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	var req manualLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	if !req.Clear && strings.TrimSpace(req.Label) == "" {
		http.Error(w, "missing label", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	updated, err := s.store.UpdateManualLabel(id, req.Label, req.Source, req.Note, req.Clear)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	reclassified := s.recomputeDeviceLabel(*updated)
	s.store.AddOrUpdateDevice("", reclassified)

	final := reclassified
	if stored := s.store.GetDevice(id); stored != nil {
		final = *stored
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildLabelDetail(final, labelDetailPrivacyConfig(r)))
}

func (s *Server) deviceByIDRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := path.Base(r.URL.Path)
	if id == "" || id == "devices" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	dev := s.store.GetDevice(id)
	s.mu.Unlock()
	if dev == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dev)
}

func summarizeLabel(d store.Device) labelSummary {
	hostname := ""
	if d.Hostname != nil {
		hostname = *d.Hostname
	}
	return labelSummary{
		DeviceID:         d.ID,
		IP:               d.IP,
		MAC:              d.MAC,
		Hostname:         hostname,
		DeviceType:       d.DeviceType,
		Confidence:       d.Confidence,
		ManualLabel:      d.ManualLabel,
		ManualLabelState: d.ManualLabelState,
		LabelState:       d.LabelState,
		CandidateCount:   len(d.LabelState.CandidateLabels),
	}
}

func buildLabelDetail(d store.Device, privacyCfg evidence.PrivacyConfig) labelDetailResponse {
	evidenceSnapshot := make([]store.Observation, len(d.Observations))
	for i, obs := range d.Observations {
		evidenceSnapshot[i] = redactObservation(obs, privacyCfg)
	}
	sort.Slice(evidenceSnapshot, func(i, j int) bool {
		if evidenceSnapshot[i].Timestamp != evidenceSnapshot[j].Timestamp {
			return evidenceSnapshot[i].Timestamp < evidenceSnapshot[j].Timestamp
		}
		if evidenceSnapshot[i].Strategy != evidenceSnapshot[j].Strategy {
			return evidenceSnapshot[i].Strategy < evidenceSnapshot[j].Strategy
		}
		return evidenceSnapshot[i].Key < evidenceSnapshot[j].Key
	})
	return labelDetailResponse{
		DeviceID:        d.ID,
		Device:          d,
		LabelState:      d.LabelState,
		Evidence:        evidenceSnapshot,
		CandidateLabels: d.LabelState.CandidateLabels,
	}
}

func labelDetailPrivacyConfig(r *http.Request) evidence.PrivacyConfig {
	if r == nil {
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("privacy"))) {
	case "hashed-domain":
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeHashedDomain}
	case "category-only":
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeCategoryOnly}
	default:
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}
	}
}

func redactObservation(obs store.Observation, privacyCfg evidence.PrivacyConfig) store.Observation {
	ev := evidence.FromObservation(obs, privacyCfg)
	obs.Value = ev.CanonicalValue
	return obs
}

func (s *Server) recomputeDeviceLabel(d store.Device) store.Device {
	res := labeling.ClassifyDevice(d, s.cfg)
	d.DeviceType = res.DeviceCategory
	d.Confidence = res.LabelConfidence
	d.LabelState = toStoreLabelState(res)
	d.ClassificationReasons = append([]string{}, res.ReasonChain...)
	if len(res.CandidateLabels) > 0 {
		reasons := make([]string, 0, len(res.CandidateLabels))
		for _, c := range res.CandidateLabels {
			if c.Label == "" || c.Confidence < 0.05 {
				continue
			}
			reasons = append(reasons, "candidate="+c.Label+":"+fmt.Sprintf("%.2f", c.Confidence))
		}
		if len(reasons) > 0 {
			d.ClassificationReasons = append(d.ClassificationReasons, reasons...)
		}
	}
	if len(d.ClassificationReasons) == 0 {
		d.ClassificationReasons = []string{"no identifying signals"}
	}
	return d
}

func toStoreLabelState(res labeling.LabelResult) store.LabelState {
	candidates := make([]store.LabelCandidate, 0, len(res.CandidateLabels))
	for _, c := range res.CandidateLabels {
		candidates = append(candidates, store.LabelCandidate{
			Label:        c.Label,
			Score:        c.Score,
			Confidence:   c.Confidence,
			Evidence:     c.Evidence,
			SupportTiers: c.SupportTiers,
		})
	}
	return store.LabelState{
		DeviceCategory:            res.DeviceCategory,
		DeviceSubType:             res.DeviceSubType,
		LabelConfidence:           res.LabelConfidence,
		LabelConfidenceCalibrated: res.LabelConfidenceCalibrated,
		EvidenceSummary:           res.EvidenceSummary,
		CandidateLabels:           candidates,
		ReasonChain:               res.ReasonChain,
		ConflictFlags:             res.ConflictFlags,
		ConfidenceBand:            string(res.ConfidenceBand),
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	sub := s.store.Subscribe()
	defer s.store.Unsubscribe(sub)

	for {
		select {
		case event, ok := <-sub:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			w.Write([]byte("data: " + string(data) + "\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		case <-time.After(30 * time.Second):
			w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		}
	}
}
