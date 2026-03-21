package passive

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	macRegex       = regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	ipv4Regex      = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1?\d?\d)(?:\.(?:25[0-5]|2[0-4][0-9]|1?\d?\d)){3}\b`)
	domainRegex    = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b`)
	rssiRegex      = regexp.MustCompile(`(?i)rssi[=: ](-?\d+)`)
	bandRegex      = regexp.MustCompile(`(?i)\b(2\.4ghz|5ghz|6ghz)\b`)
	channelRegex   = regexp.MustCompile(`(?i)channel[=: ]([0-9]+)`)
	roamRegex      = regexp.MustCompile(`(?i)roam(?:_count)?[=: ]([0-9]+)`)
	countRegex     = regexp.MustCompile(`(?i)(?:count|sessions)[=: ]([0-9]+)`)
	longLivedRegex = regexp.MustCompile(`(?i)(?:long_lived|persistent)[=: ]([0-9]+)`)
)

func (s *Session) listenSyslog(ctx context.Context, addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		s.parseSyslogLine(string(buf[:n]))
	}
}

func (s *Session) parseSyslogLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	now := time.Now().UTC()
	if ev, ok := parseWiFiLine(line, now); ok {
		s.appendWiFi(ev)
	}
	if ev, ok := parseRadiusLine(line, now); ok {
		s.appendRadius(ev)
	}
}

func (s *Session) loadResolverEvents(path string) {
	for _, line := range readLines(path) {
		if ev, ok := parseResolverLine(line); ok {
			s.appendResolver(ev)
		}
	}
}

func (s *Session) loadDHCPLogEvents(path string) {
	for _, line := range readLines(path) {
		if ev, ok := parseDHCPLogLine(line); ok {
			s.appendDHCP(ev)
		}
	}
}

func (s *Session) loadSessionProfileSource(path, command string) {
	for _, line := range readLines(path) {
		if ev, ok := parseSessionLine(line); ok {
			s.appendSessionProfile(ev)
		}
		if ev, ok := parseRadiusLine(line, time.Now().UTC()); ok {
			s.appendRadius(ev)
		}
	}
	for _, line := range commandOutputLines(command) {
		if ev, ok := parseSessionLine(line); ok {
			s.appendSessionProfile(ev)
		}
	}
}

func parseResolverLine(line string) (ResolverEvent, bool) {
	ip := firstIPv4(line)
	if ip == "" {
		return ResolverEvent{}, false
	}
	query := firstDomain(line)
	return ResolverEvent{
		Timestamp:   time.Now().UTC(),
		ClientIP:    ip,
		Query:       query,
		Category:    domainCategory(query),
		LocalLookup: isLocalName(query),
		SRVLookup:   strings.Contains(strings.ToLower(line), " srv ") || strings.Contains(strings.ToLower(line), "type=srv"),
	}, true
}

func parseDHCPLogLine(line string) (DHCPEvent, bool) {
	mac := firstMAC(line)
	ip := firstIPv4(line)
	if mac == "" && ip == "" {
		return DHCPEvent{}, false
	}
	return DHCPEvent{
		Timestamp:        time.Now().UTC(),
		ClientIP:         ip,
		RequestedIP:      ip,
		ClientMAC:        mac,
		Hostname:         valueAfter(line, "hostname"),
		VendorClass:      valueAfter(line, "vendor"),
		ClientIdentifier: valueAfter(line, "client-id"),
		MessageType:      valueAfter(line, "message"),
	}, true
}

func parseWiFiLine(line string, ts time.Time) (WiFiEvent, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "assoc") && !strings.Contains(lower, "roam") && !strings.Contains(lower, "station") && !strings.Contains(lower, "client") {
		return WiFiEvent{}, false
	}
	mac := firstMAC(line)
	ip := firstIPv4(line)
	if mac == "" && ip == "" {
		return WiFiEvent{}, false
	}
	return WiFiEvent{
		Timestamp:       ts,
		ClientIP:        ip,
		ClientMAC:       mac,
		Hostname:        valueAfter(line, "host"),
		State:           wifiState(lower),
		RSSI:            firstCapture(rssiRegex, line),
		Band:            firstCapture(bandRegex, line),
		Channel:         firstCapture(channelRegex, line),
		SessionDuration: valueAfter(line, "duration"),
		RoamCount:       firstCapture(roamRegex, line),
	}, true
}

func parseRadiusLine(line string, ts time.Time) (RadiusEvent, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "radius") && !strings.Contains(lower, "802.1x") && !strings.Contains(lower, "eap") && !strings.Contains(lower, "auth") {
		return RadiusEvent{}, false
	}
	mac := firstMAC(line)
	ip := firstIPv4(line)
	identity := valueAfter(line, "identity")
	if identity == "" {
		identity = valueAfter(line, "user")
	}
	if mac == "" && ip == "" && identity == "" {
		return RadiusEvent{}, false
	}
	realm := ""
	if idx := strings.Index(identity, "@"); idx >= 0 {
		realm = identity[idx+1:]
	}
	return RadiusEvent{
		Timestamp:  ts,
		ClientIP:   ip,
		ClientMAC:  mac,
		Identity:   identity,
		Realm:      realm,
		EAPType:    valueAfter(line, "eap"),
		VLAN:       valueAfter(line, "vlan"),
		Role:       valueAfter(line, "role"),
		AuthResult: authResult(lower),
	}, true
}

func parseSessionLine(line string) (SessionProfileEvent, bool) {
	ip := firstIPv4(line)
	if ip == "" {
		return SessionProfileEvent{}, false
	}
	lower := strings.ToLower(line)
	return SessionProfileEvent{
		Timestamp:      time.Now().UTC(),
		ClientIP:       ip,
		ClientMAC:      firstMAC(line),
		SessionCount:   parseInt(firstCapture(countRegex, line)),
		ProtocolMix:    protocolMix(lower),
		LongLivedCount: parseInt(firstCapture(longLivedRegex, line)),
		RemoteCategory: remoteCategory(lower),
		Burstiness:     burstiness(lower),
	}, true
}

func readLines(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return splitNonEmptyLines(string(data))
}

func commandOutputLines(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-Command", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitNonEmptyLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func firstMAC(line string) string {
	return normalizeMAC(macRegex.FindString(line))
}

func firstIPv4(line string) string {
	return ipv4Regex.FindString(line)
}

func firstDomain(line string) string {
	return strings.ToLower(strings.TrimSpace(domainRegex.FindString(line)))
}

func firstCapture(re *regexp.Regexp, line string) string {
	m := re.FindStringSubmatch(line)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func valueAfter(line, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return ""
	}
	tokens := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == ',' || r == ';' })
	for _, token := range tokens {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(token, ":", 2)
		}
		if len(parts) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(parts[0])) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func parseInt(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func wifiState(lower string) string {
	switch {
	case strings.Contains(lower, "disassoc"):
		return "disassociated"
	case strings.Contains(lower, "roam"):
		return "roaming"
	case strings.Contains(lower, "assoc"):
		return "associated"
	default:
		return "observed"
	}
}

func authResult(lower string) string {
	switch {
	case strings.Contains(lower, "accept") || strings.Contains(lower, "success"):
		return "accept"
	case strings.Contains(lower, "reject") || strings.Contains(lower, "fail"):
		return "reject"
	default:
		return "observed"
	}
}

func protocolMix(lower string) string {
	seen := map[string]struct{}{}
	for _, proto := range []string{"tcp", "udp", "icmp", "quic", "tls", "http"} {
		if strings.Contains(lower, proto) {
			seen[proto] = struct{}{}
		}
	}
	return protocolListFromStringSet(seen)
}

func remoteCategory(lower string) string {
	switch {
	case strings.Contains(lower, "apple"):
		return "apple"
	case strings.Contains(lower, "google"):
		return "google"
	case strings.Contains(lower, "microsoft"):
		return "microsoft"
	case strings.Contains(lower, "netflix") || strings.Contains(lower, "youtube") || strings.Contains(lower, "spotify"):
		return "media"
	default:
		return "generic"
	}
}

func burstiness(lower string) string {
	switch {
	case strings.Contains(lower, "burst") || strings.Contains(lower, "spike"):
		return "bursty"
	case strings.Contains(lower, "steady") || strings.Contains(lower, "persistent"):
		return "steady"
	default:
		return "unknown"
	}
}
