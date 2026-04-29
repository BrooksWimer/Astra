package routeradmin

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

const (
	xfinityLoginPath            = "/index.jst"
	xfinityLoginSubmitPath      = "/check.jst"
	xfinityConnectedDevicesPath = "/connected_devices_computers.jst"
	xfinityLoggedOutPath        = "home_loggedout.jst"
)

type XfinityClient struct {
	cfg        Config
	httpClient *http.Client
}

type fetchResult struct {
	statusCode int
	body       []byte
}

func NewXfinityClient(cfg Config) (*XfinityClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &XfinityClient{
		cfg: cfg,
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: cfg.Timeout,
		},
	}, nil
}

func (c *XfinityClient) Collect(ctx context.Context) (Inventory, error) {
	inventory := Inventory{
		Provider:             ProviderXfinity,
		BaseURL:              c.cfg.BaseURL,
		Status:               StatusUnavailable,
		ConnectedDevicesPath: xfinityConnectedDevicesPath,
	}

	loginPage, err := c.doRequest(ctx, http.MethodGet, xfinityLoginPath, nil, nil)
	if err != nil {
		return inventory, err
	}
	if !looksLikeXfinityLoginPage(loginPage.body) {
		inventory.StatusReason = "login_form_not_detected"
		return inventory, nil
	}
	if err := c.login(ctx); err != nil {
		return inventory, err
	}

	connectedPage, err := c.doRequest(ctx, http.MethodGet, xfinityConnectedDevicesPath, nil, nil)
	if err != nil {
		return inventory, err
	}
	inventory.ListPageTitle = extractHTMLTitle(string(connectedPage.body))
	inventory.ListPageSHA1 = sha1Hex(connectedPage.body)
	inventory.ListPageBytes = len(connectedPage.body)
	inventory.Devices = extractClickableDeviceLabels(connectedPage.body)
	inventory.DetailPath, inventory.DetailCandidates = discoverDetailPath(connectedPage.body)
	inventory.DetailPathResolved = inventory.DetailPath != ""

	if isLoggedOutPage(connectedPage.body) || looksLikeXfinityLoginPage(connectedPage.body) {
		inventory.Status = StatusAuthRejected
		inventory.StatusReason = "connected_devices_page_rejected_session"
		return inventory, nil
	}

	inventory.Status = StatusPageFetched
	return inventory, nil
}

func (c *XfinityClient) login(ctx context.Context) error {
	form := url.Values{}
	form.Set("username", strings.ToLower(strings.TrimSpace(c.cfg.Username)))
	form.Set("password", c.cfg.Password)
	form.Set("locale", "false")
	_, err := c.doRequest(
		ctx,
		http.MethodPost,
		xfinityLoginSubmitPath,
		strings.NewReader(form.Encode()),
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      c.resolveURL(xfinityLoginPath),
		},
	)
	return err
}

func (c *XfinityClient) doRequest(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (fetchResult, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.resolveURL(path), body)
	if err != nil {
		return fetchResult{}, err
	}
	request.Header.Set("User-Agent", c.cfg.UserAgent)
	for key, value := range headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		request.Header.Set(key, value)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fetchResult{}, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return fetchResult{}, err
	}
	return fetchResult{
		statusCode: response.StatusCode,
		body:       payload,
	}, nil
}

func (c *XfinityClient) resolveURL(path string) string {
	if path == "" {
		return c.cfg.BaseURL
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return c.cfg.BaseURL + path
	}
	return c.cfg.BaseURL + "/" + path
}

func looksLikeXfinityLoginPage(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "pageform") &&
		strings.Contains(text, "check.jst") &&
		strings.Contains(text, "username") &&
		strings.Contains(text, "password")
}

func isLoggedOutPage(body []byte) bool {
	text := strings.ToLower(string(body))
	return strings.Contains(text, "please login first!") ||
		strings.Contains(text, `location.href="home_loggedout.jst"`) ||
		strings.Contains(text, `location.href='home_loggedout.jst'`) ||
		strings.Contains(text, strings.ToLower(xfinityLoggedOutPath))
}

func discoverDetailPath(body []byte) (string, []string) {
	rawCandidates := extractJSTCandidates(string(body))
	if len(rawCandidates) == 0 {
		return "", nil
	}

	filtered := make([]string, 0, len(rawCandidates))
	seen := map[string]struct{}{}
	for _, candidate := range rawCandidates {
		normalized := normalizeCandidatePath(candidate)
		if normalized == "" {
			continue
		}
		switch normalized {
		case "index.jst", "check.jst", "home_loggedout.jst", "connected_devices_computers.jst":
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		filtered = append(filtered, normalized)
	}
	sort.Strings(filtered)
	if len(filtered) == 0 {
		return "", nil
	}

	prioritized := make([]string, 0, len(filtered))
	for _, candidate := range filtered {
		lower := strings.ToLower(candidate)
		if strings.Contains(lower, "detail") || strings.Contains(lower, "device") || strings.Contains(lower, "client") {
			prioritized = append(prioritized, candidate)
		}
	}
	switch {
	case len(prioritized) == 1:
		return prioritized[0], filtered
	case len(prioritized) == 0 && len(filtered) == 1:
		return filtered[0], filtered
	default:
		return "", filtered
	}
}

func extractJSTCandidates(body string) []string {
	parts := strings.FieldsFunc(body, func(r rune) bool {
		switch r {
		case '"', '\'', ' ', '\n', '\r', '\t', '<', '>', '(', ')':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.Contains(strings.ToLower(part), ".jst") {
			out = append(out, part)
		}
	}
	return out
}

func normalizeCandidatePath(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	candidate = strings.Trim(candidate, `"'`)
	candidate = strings.TrimPrefix(candidate, "./")
	candidate = strings.TrimPrefix(candidate, "/")
	if candidate == "" {
		return ""
	}
	if index := strings.Index(candidate, "?"); index >= 0 {
		candidate = candidate[:index]
	}
	if index := strings.Index(candidate, "#"); index >= 0 {
		candidate = candidate[:index]
	}
	return candidate
}

func extractClickableDeviceLabels(body []byte) []DeviceSummary {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	out := []DeviceSummary{}
	seen := map[string]struct{}{}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode && isLikelyDeviceNode(node) {
			label := normalizeWhitespace(nodeText(node))
			if isLikelyDeviceLabel(label) {
				key := strings.ToLower(label)
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					out = append(out, DeviceSummary{
						Name:       label,
						DetailHint: strings.TrimSpace(firstAttr(node, "onclick")),
					})
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func isLikelyDeviceNode(node *html.Node) bool {
	if node == nil || node.Type != html.ElementNode {
		return false
	}
	switch node.Data {
	case "a", "button", "div", "span", "td":
		// supported
	default:
		return false
	}
	href := strings.ToLower(firstAttr(node, "href"))
	onclick := strings.ToLower(firstAttr(node, "onclick"))
	id := strings.ToLower(firstAttr(node, "id"))
	className := strings.ToLower(firstAttr(node, "class"))
	return strings.Contains(href, "javascript:void(0)") ||
		strings.Contains(onclick, ".jst") ||
		strings.Contains(onclick, "void(0)") ||
		strings.Contains(id, "device") ||
		strings.Contains(className, "device") ||
		strings.Contains(className, "client")
}

func isLikelyDeviceLabel(label string) bool {
	if label == "" || len(label) > 64 || strings.Contains(label, ":") {
		return false
	}
	lower := strings.ToLower(label)
	switch lower {
	case "online devices", "offline devices", "more", "less", "remove", "login":
		return false
	}
	if strings.Contains(lower, "gateway") || strings.Contains(lower, "device name") {
		return false
	}
	return true
}

func firstAttr(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

func nodeText(node *html.Node) string {
	if node == nil {
		return ""
	}
	if node.Type == html.TextNode {
		return node.Data
	}
	var builder strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		builder.WriteString(nodeText(child))
		builder.WriteString(" ")
	}
	return builder.String()
}

func normalizeWhitespace(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
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

func sha1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}
