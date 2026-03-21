package strategy

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type HomeApiProbe struct{}

type httpProbeResult struct {
	Scheme      string
	Path        string
	Status      int
	ContentType string
	Server      string
	Location    string
	AuthRealm   string
	Title       string
	TitleSHA1   string
	BodySHA1    string
	BodySize    int
	JSONKeys    []string
}

func (s *HomeApiProbe) Name() string {
	return "home_api_probe"
}

func (s *HomeApiProbe) Collect(targets []Target, emit ObservationSink) {
	paths := []string{"/", "/api", "/api/status", "/api/v1", "/api/info", "/api/system", "/status", "/health"}
	for _, t := range targets {
		seen := false
		for _, scheme := range []string{"http", "https"} {
			for _, p := range paths {
				meta := probeHTTPMetadata(t.IP, scheme, p, nil)
				if meta.Status == 0 && meta.Server == "" && meta.ContentType == "" && meta.TitleSHA1 == "" && meta.BodySHA1 == "" {
					continue
				}
				seen = true
				emitHTTPMetadataObservations(emit, s.Name(), t, "http_api", meta)
			}
		}
		if !seen {
			emitObservation(emit, s.Name(), t, "http_api", "none", map[string]string{"reason": "no_response"})
		}
	}
}

func probeHTTPMetadata(ip, scheme, path string, headers map[string]string) httpProbeResult {
	if ip == "" || scheme == "" {
		return httpProbeResult{}
	}
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, netJoinHostPort(ip, port), path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return httpProbeResult{}
	}
	req.Header.Set("User-Agent", "netwise-http-probe/1.0")
	for k, v := range headers {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	client := &http.Client{
		Timeout: strategyProbeTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if scheme == "https" {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	res, err := client.Do(req)
	if err != nil {
		return httpProbeResult{}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 65536))
	meta := httpProbeResult{
		Scheme:      scheme,
		Path:        path,
		Status:      res.StatusCode,
		ContentType: strings.TrimSpace(res.Header.Get("Content-Type")),
		Server:      strings.TrimSpace(res.Header.Get("Server")),
		Location:    strings.TrimSpace(res.Header.Get("Location")),
		AuthRealm:   parseHTTPAuthRealm(res.Header.Get("WWW-Authenticate")),
		BodySize:    len(body),
		BodySHA1:    sha1Hex(body),
	}
	if title := extractHTMLTitle(string(body)); title != "" {
		meta.Title = title
		meta.TitleSHA1 = sha1Hex([]byte(title))
	}
	if strings.Contains(strings.ToLower(meta.ContentType), "json") || looksLikeJSON(body) {
		meta.JSONKeys = sortedJSONKeys(body)
	}
	return meta
}

func emitHTTPMetadataObservations(emit ObservationSink, strategyName string, t Target, prefix string, meta httpProbeResult) {
	if meta.Status == 0 && meta.Server == "" && meta.ContentType == "" && meta.TitleSHA1 == "" && meta.BodySHA1 == "" {
		return
	}
	baseDetails := map[string]string{
		"scheme": meta.Scheme,
		"path":   meta.Path,
	}
	if meta.Status > 0 {
		emitObservation(emit, strategyName, t, prefix+"_status", strconv.Itoa(meta.Status), baseDetails)
	}
	if meta.Server != "" {
		emitObservation(emit, strategyName, t, prefix+"_server", meta.Server, baseDetails)
	}
	if meta.ContentType != "" {
		emitObservation(emit, strategyName, t, prefix+"_content_type", meta.ContentType, baseDetails)
	}
	if meta.Location != "" {
		emitObservation(emit, strategyName, t, prefix+"_redirect_location", meta.Location, baseDetails)
	}
	if meta.AuthRealm != "" {
		emitObservation(emit, strategyName, t, prefix+"_auth_realm", meta.AuthRealm, baseDetails)
	}
	if meta.TitleSHA1 != "" {
		details := cloneStringMap(baseDetails)
		if meta.Title != "" {
			details["title"] = meta.Title
		}
		emitObservation(emit, strategyName, t, prefix+"_title_sha1", meta.TitleSHA1, details)
	}
	if meta.BodySHA1 != "" {
		emitObservation(emit, strategyName, t, prefix+"_body_sha1", meta.BodySHA1, baseDetails)
	}
	if meta.BodySize > 0 {
		emitObservation(emit, strategyName, t, prefix+"_body_size", strconv.Itoa(meta.BodySize), baseDetails)
	}
	if len(meta.JSONKeys) > 0 {
		emitObservation(emit, strategyName, t, prefix+"_json_keys", strings.Join(meta.JSONKeys, ","), baseDetails)
	}
	emitObservation(emit, strategyName, t, prefix+"_endpoint", meta.Scheme+"://"+meta.Path, baseDetails)
}

func parseHTTPAuthRealm(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return ""
	}
	for _, part := range strings.Split(value, ",") {
		if idx := strings.Index(strings.ToLower(part), "realm="); idx >= 0 {
			realm := strings.TrimSpace(part[idx+len("realm="):])
			return strings.Trim(realm, "\"'")
		}
	}
	return strings.TrimSpace(value)
}

func extractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start < 0 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func looksLikeJSON(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func sortedJSONKeys(body []byte) []string {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	keys := collectJSONKeys(payload, nil)
	if len(keys) == 0 {
		return nil
	}
	return keys
}

func collectJSONKeys(value any, out []string) []string {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			out = append(out, k)
			out = collectJSONKeys(child, out)
		}
	case []any:
		for _, child := range v {
			out = collectJSONKeys(child, out)
		}
	}
	return uniqueSortedStrings(out)
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sortStrings(out)
	return out
}

func sortStrings(values []string) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

func sha1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func netJoinHostPort(ip, port string) string {
	return ip + ":" + port
}
