package strategy

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type HttpFaviconFingerprint struct{}

type faviconFingerprintResult struct {
	Scheme      string
	Path        string
	ContentType string
	Size        int
	SHA1        string
	SHA256      string
}

var faviconHrefRegex = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*(?:icon|shortcut icon|apple-touch-icon)[^"']*["'][^>]*href=["']([^"']+)["']`)

func (s *HttpFaviconFingerprint) Name() string {
	return "http_favicon_fingerprint"
}

func (s *HttpFaviconFingerprint) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		results := probeFaviconFingerprints(t.IP)
		if len(results) == 0 {
			emitObservation(emit, s.Name(), t, "favicon", "none", map[string]string{"reason": "no_favicon_bytes"})
			continue
		}
		for _, r := range results {
			details := map[string]string{
				"scheme":       r.Scheme,
				"path":         r.Path,
				"content_type": r.ContentType,
			}
			emitObservation(emit, s.Name(), t, "favicon_path", r.Path, details)
			emitObservation(emit, s.Name(), t, "favicon_sha1", r.SHA1, details)
			emitObservation(emit, s.Name(), t, "favicon_sha256", r.SHA256, details)
			emitObservation(emit, s.Name(), t, "favicon_size", strconv.Itoa(r.Size), details)
			if r.ContentType != "" {
				emitObservation(emit, s.Name(), t, "favicon_content_type", r.ContentType, details)
			}
			emitObservation(emit, s.Name(), t, "favicon_signature", fmt.Sprintf("%s:%d", r.SHA1, r.Size), details)
		}
	}
}

func probeFaviconFingerprints(ip string) []faviconFingerprintResult {
	if ip == "" {
		return nil
	}
	discovered := map[string]struct{}{}
	candidates := []string{"/favicon.ico", "/favicon.png", "/favicon.svg", "/apple-touch-icon.png"}
	for _, scheme := range []string{"http", "https"} {
		html := fetchRootHTML(ip, scheme)
		for _, path := range discoverIconPaths(html) {
			discovered[path] = struct{}{}
		}
	}
	for _, c := range candidates {
		discovered[c] = struct{}{}
	}

	paths := make([]string, 0, len(discovered))
	for p := range discovered {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	results := []faviconFingerprintResult{}
	for _, scheme := range []string{"http", "https"} {
		for _, path := range paths {
			res := fetchFaviconBytes(ip, scheme, path)
			if res == nil {
				continue
			}
			results = append(results, *res)
		}
	}
	return results
}

func fetchRootHTML(ip, scheme string) string {
	url := fmt.Sprintf("%s://%s/", scheme, netJoinHostPort(ip, schemePort(scheme)))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	client := http.Client{Timeout: strategyProbeTimeout}
	if scheme == "https" {
		client.Transport = insecureHTTPTransport()
	}
	res, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 32768))
	return string(body)
}

func discoverIconPaths(html string) []string {
	matches := faviconHrefRegex.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return nil
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		href := strings.TrimSpace(match[1])
		if href == "" {
			continue
		}
		u, err := url.Parse(href)
		if err != nil {
			continue
		}
		path := u.Path
		if path == "" {
			path = href
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func fetchFaviconBytes(ip, scheme, path string) *faviconFingerprintResult {
	url := fmt.Sprintf("%s://%s%s", scheme, netJoinHostPort(ip, schemePort(scheme)), path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	client := http.Client{Timeout: strategyProbeTimeout}
	if scheme == "https" {
		client.Transport = insecureHTTPTransport()
	}
	res, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 65536))
	if len(data) == 0 {
		return nil
	}
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	return &faviconFingerprintResult{
		Scheme:      scheme,
		Path:        path,
		ContentType: strings.TrimSpace(res.Header.Get("Content-Type")),
		Size:        len(data),
		SHA1:        hex.EncodeToString(sha1Sum[:]),
		SHA256:      hex.EncodeToString(sha256Sum[:]),
	}
}

func schemePort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

func insecureHTTPTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}
