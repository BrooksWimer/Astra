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
	macRegex            = regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	ipv4Regex           = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1?\d?\d)(?:\.(?:25[0-5]|2[0-4][0-9]|1?\d?\d)){3}\b`)
	domainRegex         = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b`)
	rssiRegex           = regexp.MustCompile(`(?i)rssi[=: ](-?\d+)`)
	bandRegex           = regexp.MustCompile(`(?i)\b(2\.4ghz|5ghz|6ghz)\b`)
	channelRegex        = regexp.MustCompile(`(?i)channel[=: ]([0-9]+)`)
	roamRegex           = regexp.MustCompile(`(?i)roam(?:_count)?[=: ]([0-9]+)`)
	countRegex          = regexp.MustCompile(`(?i)(?:count|sessions)[=: ]([0-9]+)`)
	longLivedRegex      = regexp.MustCompile(`(?i)(?:long_lived|persistent)[=: ]([0-9]+)`)
	syslogPriorityRegex = regexp.MustCompile(`^<\d+>`)
	rfc3339Regex        = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	ymdTimeRegex        = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}`)
	syslogTimeRegex     = regexp.MustCompile(`(?i)\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b`)
	dnsmasqQueryRegex   = regexp.MustCompile(`(?i)query(?:\[(\w+)\])?\s+([^\s]+)\s+from\s+([0-9.]+)`)
	bindQueryRegex      = regexp.MustCompile(`(?i)client(?:\s+@\S+)?\s+([0-9.]+)#\d+\s+\(([^)]+)\):\s+query:\s+([^\s]+)\s+IN\s+([A-Z0-9]+)`)
	conntrackRegex      = regexp.MustCompile(`(?i)^(tcp|udp|icmp|icmpv6)\s+\d+\s+(\d+)\s+\S+\s+src=([0-9.]+)\s+dst=([0-9.]+)`)
	freeradiusUserRegex = regexp.MustCompile(`(?i)\[([^\]]+)\]`)
	freeradiusCLIRegex  = regexp.MustCompile(`(?i)\bcli\s+([0-9a-f:.-]+)`)
	hostapdStationRegex = regexp.MustCompile(`(?i)\bsta\s+([0-9a-f:.-]{17})\b`)
	unifiEventRegex     = regexp.MustCompile(`(?i)\b(client|user)[ _-]?(connected|disconnected|roamed)\b`)
	omadaEventRegex     = regexp.MustCompile(`(?i)\b(station|client)\b.*\b(associate|connected|disconnect|roam)\w*`)
)

func (s *Session) listenSyslog(ctx context.Context, addr, wifiFormat, radiusFormat string) {
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
		s.parseSyslogLine(string(buf[:n]), wifiFormat, radiusFormat)
	}
}

func (s *Session) parseSyslogLine(line, wifiFormat, radiusFormat string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	now := time.Now().UTC()
	if ev, _, ok := parseWiFiLine(line, wifiFormat, now); ok {
		s.appendWiFi(ev)
	}
	if ev, _, ok := parseRadiusLine(line, radiusFormat, now); ok {
		s.appendRadius(ev)
	}
}

func (s *Session) loadResolverEvents(path, format string, lookback time.Duration) {
	now := time.Now().UTC()
	for _, line := range readLines(path) {
		ev, parsedTimestamp, ok := parseResolverLine(line, format, now)
		if !ok || !withinLookback(ev.Timestamp, now, lookback, parsedTimestamp) {
			continue
		}
		s.appendResolver(ev)
	}
}

func (s *Session) loadDHCPLogEvents(path string, lookback time.Duration) {
	now := time.Now().UTC()
	for _, line := range readLines(path) {
		ev, parsedTimestamp, ok := parseDHCPLogLine(line, now)
		if !ok || !withinLookback(ev.Timestamp, now, lookback, parsedTimestamp) {
			continue
		}
		s.appendDHCP(ev)
	}
}

func (s *Session) loadSessionProfileSource(path, command, sessionFormat, radiusFormat string, lookback time.Duration) {
	now := time.Now().UTC()
	for _, line := range readLines(path) {
		if ev, parsedTimestamp, ok := parseSessionLine(line, sessionFormat, now); ok && withinLookback(ev.Timestamp, now, lookback, parsedTimestamp) {
			s.appendSessionProfile(ev)
		}
		if ev, parsedTimestamp, ok := parseRadiusLine(line, radiusFormat, now); ok && withinLookback(ev.Timestamp, now, lookback, parsedTimestamp) {
			s.appendRadius(ev)
		}
	}
	for _, line := range commandOutputLines(command) {
		if ev, parsedTimestamp, ok := parseSessionLine(line, sessionFormat, now); ok && withinLookback(ev.Timestamp, now, lookback, parsedTimestamp) {
			s.appendSessionProfile(ev)
		}
	}
}

func parseResolverLine(line, format string, fallback time.Time) (ResolverEvent, bool, bool) {
	return parseResolverByFormat(strings.TrimSpace(line), normalizeInfraFormat(format), fallback)
}

func parseResolverByFormat(line, format string, fallback time.Time) (ResolverEvent, bool, bool) {
	if line == "" {
		return ResolverEvent{}, false, false
	}
	if format != "auto" {
		return parseResolverWithParser(format, line, fallback)
	}
	for _, candidate := range []string{"adguard", "pihole_ftl", "dnsmasq", "bind_query", "generic"} {
		if ev, parsedTimestamp, ok := parseResolverWithParser(candidate, line, fallback); ok {
			return ev, parsedTimestamp, true
		}
	}
	return ResolverEvent{}, false, false
}

func parseResolverWithParser(format, line string, fallback time.Time) (ResolverEvent, bool, bool) {
	switch format {
	case "adguard", "pihole_ftl", "dnsmasq":
		return parseResolverDnsmasqStyle(line, fallback)
	case "bind_query":
		return parseResolverBindStyle(line, fallback)
	default:
		return parseResolverGeneric(line, fallback)
	}
}

func parseResolverDnsmasqStyle(line string, fallback time.Time) (ResolverEvent, bool, bool) {
	m := dnsmasqQueryRegex.FindStringSubmatch(line)
	if len(m) < 4 {
		return ResolverEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	query := strings.ToLower(strings.TrimSpace(m[2]))
	queryType := strings.ToUpper(strings.TrimSpace(m[1]))
	return ResolverEvent{
		Timestamp:   ts,
		ClientIP:    strings.TrimSpace(m[3]),
		Query:       query,
		QueryType:   queryType,
		Category:    domainCategory(query),
		LocalLookup: isLocalName(query),
		SRVLookup:   strings.EqualFold(queryType, "SRV"),
	}, parsedTimestamp, true
}

func parseResolverBindStyle(line string, fallback time.Time) (ResolverEvent, bool, bool) {
	m := bindQueryRegex.FindStringSubmatch(line)
	if len(m) < 5 {
		return ResolverEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	query := strings.ToLower(strings.TrimSpace(m[3]))
	queryType := strings.ToUpper(strings.TrimSpace(m[4]))
	return ResolverEvent{
		Timestamp:   ts,
		ClientIP:    strings.TrimSpace(m[1]),
		Query:       query,
		QueryType:   queryType,
		Category:    domainCategory(query),
		LocalLookup: isLocalName(query),
		SRVLookup:   strings.EqualFold(queryType, "SRV"),
	}, parsedTimestamp, true
}

func parseResolverGeneric(line string, fallback time.Time) (ResolverEvent, bool, bool) {
	ip := firstIPv4(line)
	query := firstDomain(line)
	if ip == "" || query == "" {
		return ResolverEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	queryType := strings.ToUpper(valueAfter(line, "type"))
	if queryType == "" {
		queryType = strings.ToUpper(valueAfter(line, "qtype"))
	}
	if queryType == "" {
		if m := dnsmasqQueryRegex.FindStringSubmatch(line); len(m) >= 2 {
			queryType = strings.ToUpper(strings.TrimSpace(m[1]))
		}
	}
	return ResolverEvent{
		Timestamp:   ts,
		ClientIP:    ip,
		Query:       query,
		QueryType:   queryType,
		Category:    domainCategory(query),
		LocalLookup: isLocalName(query),
		SRVLookup:   strings.EqualFold(queryType, "SRV") || strings.Contains(strings.ToLower(line), " srv "),
	}, parsedTimestamp, true
}

func parseDHCPLogLine(line string, fallback time.Time) (DHCPEvent, bool, bool) {
	mac := firstMAC(line)
	ip := firstIPv4(line)
	if mac == "" && ip == "" {
		return DHCPEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	prl := splitCSVish(valueAfter(line, "prl"))
	optionOrder := splitCSVish(valueAfter(line, "option_order"))
	event := DHCPEvent{
		Timestamp:        ts,
		ClientIP:         ip,
		RequestedIP:      firstNonEmpty(valueAfter(line, "requested_ip"), valueAfter(line, "requested"), ip),
		ClientMAC:        mac,
		ServerIP:         valueAfter(line, "server"),
		Hostname:         valueAfter(line, "hostname"),
		VendorClass:      firstNonEmpty(valueAfter(line, "vendor_class"), valueAfter(line, "vendor")),
		ClientIdentifier: firstNonEmpty(valueAfter(line, "client-id"), valueAfter(line, "client_id")),
		MessageType:      firstNonEmpty(valueAfter(line, "message"), dhcpMessageTypeFromLine(line)),
		PRL:              prl,
		OptionOrder:      optionOrder,
	}
	return event, parsedTimestamp, true
}

func parseWiFiLine(line, format string, fallback time.Time) (WiFiEvent, bool, bool) {
	return parseWiFiByFormat(strings.TrimSpace(line), normalizeInfraFormat(format), fallback)
}

func parseWiFiByFormat(line, format string, fallback time.Time) (WiFiEvent, bool, bool) {
	if line == "" {
		return WiFiEvent{}, false, false
	}
	if format != "auto" {
		return parseWiFiWithParser(format, line, fallback)
	}
	for _, candidate := range []string{"hostapd", "unifi_syslog", "omada_syslog", "generic"} {
		if ev, parsedTimestamp, ok := parseWiFiWithParser(candidate, line, fallback); ok {
			return ev, parsedTimestamp, true
		}
	}
	return WiFiEvent{}, false, false
}

func parseWiFiWithParser(format, line string, fallback time.Time) (WiFiEvent, bool, bool) {
	switch format {
	case "hostapd":
		return parseWiFiHostapdLine(line, fallback)
	case "unifi_syslog":
		return parseWiFiUniFiLine(line, fallback)
	case "omada_syslog":
		return parseWiFiOmadaLine(line, fallback)
	default:
		return parseWiFiGenericLine(line, fallback)
	}
}

func parseWiFiHostapdLine(line string, fallback time.Time) (WiFiEvent, bool, bool) {
	if !strings.Contains(strings.ToLower(line), "ieee 802.11") && !hostapdStationRegex.MatchString(line) {
		return WiFiEvent{}, false, false
	}
	return parseWiFiGenericLine(line, fallback)
}

func parseWiFiUniFiLine(line string, fallback time.Time) (WiFiEvent, bool, bool) {
	if !unifiEventRegex.MatchString(line) && !strings.Contains(strings.ToLower(line), "unifi") {
		return WiFiEvent{}, false, false
	}
	return parseWiFiGenericLine(line, fallback)
}

func parseWiFiOmadaLine(line string, fallback time.Time) (WiFiEvent, bool, bool) {
	if !omadaEventRegex.MatchString(line) && !strings.Contains(strings.ToLower(line), "omada") {
		return WiFiEvent{}, false, false
	}
	return parseWiFiGenericLine(line, fallback)
}

func parseWiFiGenericLine(line string, fallback time.Time) (WiFiEvent, bool, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "assoc") &&
		!strings.Contains(lower, "roam") &&
		!strings.Contains(lower, "station") &&
		!strings.Contains(lower, "client") &&
		!strings.Contains(lower, "connected") &&
		!strings.Contains(lower, "disconnected") {
		return WiFiEvent{}, false, false
	}
	mac := firstMAC(line)
	ip := firstIPv4(line)
	if mac == "" && ip == "" {
		return WiFiEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	return WiFiEvent{
		Timestamp:       ts,
		ClientIP:        ip,
		ClientMAC:       mac,
		Hostname:        firstNonEmpty(valueAfter(line, "host"), valueAfter(line, "hostname"), valueAfter(line, "name")),
		State:           wifiState(lower),
		RSSI:            firstCapture(rssiRegex, line),
		Band:            firstCapture(bandRegex, line),
		Channel:         firstCapture(channelRegex, line),
		SessionDuration: firstNonEmpty(valueAfter(line, "duration"), valueAfter(line, "session")),
		RoamCount:       firstCapture(roamRegex, line),
	}, parsedTimestamp, true
}

func parseRadiusLine(line, format string, fallback time.Time) (RadiusEvent, bool, bool) {
	return parseRadiusByFormat(strings.TrimSpace(line), normalizeInfraFormat(format), fallback)
}

func parseRadiusByFormat(line, format string, fallback time.Time) (RadiusEvent, bool, bool) {
	if line == "" {
		return RadiusEvent{}, false, false
	}
	if format != "auto" {
		return parseRadiusWithParser(format, line, fallback)
	}
	for _, candidate := range []string{"freeradius", "generic"} {
		if ev, parsedTimestamp, ok := parseRadiusWithParser(candidate, line, fallback); ok {
			return ev, parsedTimestamp, true
		}
	}
	return RadiusEvent{}, false, false
}

func parseRadiusWithParser(format, line string, fallback time.Time) (RadiusEvent, bool, bool) {
	switch format {
	case "freeradius":
		return parseRadiusFreeRADIUSLine(line, fallback)
	default:
		return parseRadiusGenericLine(line, fallback)
	}
}

func parseRadiusFreeRADIUSLine(line string, fallback time.Time) (RadiusEvent, bool, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "freeradius") && !strings.Contains(lower, "login ok") && !strings.Contains(lower, "access-accept") && !strings.Contains(lower, "access-reject") {
		return RadiusEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	identity := strings.TrimSpace(firstCapture(freeradiusUserRegex, line))
	mac := firstNonEmpty(firstCapture(freeradiusCLIRegex, line), firstMAC(line))
	ip := firstIPv4(line)
	realm := ""
	if idx := strings.Index(identity, "@"); idx >= 0 {
		realm = identity[idx+1:]
	}
	return RadiusEvent{
		Timestamp:  ts,
		ClientIP:   ip,
		ClientMAC:  normalizeMAC(mac),
		Identity:   identity,
		Realm:      realm,
		EAPType:    firstNonEmpty(valueAfter(line, "eap"), valueAfter(line, "eap-type")),
		VLAN:       valueAfter(line, "vlan"),
		Role:       valueAfter(line, "role"),
		AuthResult: authResult(lower),
	}, parsedTimestamp, identity != "" || mac != "" || ip != ""
}

func parseRadiusGenericLine(line string, fallback time.Time) (RadiusEvent, bool, bool) {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "radius") && !strings.Contains(lower, "802.1x") && !strings.Contains(lower, "eap") && !strings.Contains(lower, "auth") {
		return RadiusEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	mac := firstMAC(line)
	ip := firstIPv4(line)
	identity := firstNonEmpty(valueAfter(line, "identity"), valueAfter(line, "user"), valueAfter(line, "username"))
	if mac == "" && ip == "" && identity == "" {
		return RadiusEvent{}, false, false
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
		EAPType:    firstNonEmpty(valueAfter(line, "eap"), valueAfter(line, "eap-type")),
		VLAN:       valueAfter(line, "vlan"),
		Role:       valueAfter(line, "role"),
		AuthResult: authResult(lower),
	}, parsedTimestamp, true
}

func parseSessionLine(line, format string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	return parseSessionByFormat(strings.TrimSpace(line), normalizeInfraFormat(format), fallback)
}

func parseSessionByFormat(line, format string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	if line == "" {
		return SessionProfileEvent{}, false, false
	}
	if format != "auto" {
		return parseSessionWithParser(format, line, fallback)
	}
	for _, candidate := range []string{"conntrack", "pfsense", "opnsense", "generic"} {
		if ev, parsedTimestamp, ok := parseSessionWithParser(candidate, line, fallback); ok {
			return ev, parsedTimestamp, true
		}
	}
	return SessionProfileEvent{}, false, false
}

func parseSessionWithParser(format, line string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	switch format {
	case "conntrack":
		return parseSessionConntrackLine(line, fallback)
	case "pfsense", "opnsense":
		return parseSessionKeyValueLine(line, fallback)
	default:
		return parseSessionGenericLine(line, fallback)
	}
}

func parseSessionConntrackLine(line string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	m := conntrackRegex.FindStringSubmatch(line)
	if len(m) < 5 {
		return SessionProfileEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	timeoutSeconds := parseInt(strings.TrimSpace(m[2]))
	return SessionProfileEvent{
		Timestamp:      ts,
		ClientIP:       strings.TrimSpace(m[3]),
		ClientMAC:      firstMAC(line),
		SessionCount:   1,
		ProtocolMix:    strings.ToLower(strings.TrimSpace(m[1])),
		LongLivedCount: boolToInt(timeoutSeconds >= 300),
		RemoteCategory: remoteCategory(strings.ToLower(line)),
		Burstiness:     burstiness(strings.ToLower(line)),
	}, parsedTimestamp, true
}

func parseSessionKeyValueLine(line string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	ip := firstNonEmpty(valueAfter(line, "client"), valueAfter(line, "client_ip"), firstIPv4(line))
	if ip == "" {
		return SessionProfileEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	lower := strings.ToLower(line)
	return SessionProfileEvent{
		Timestamp:      ts,
		ClientIP:       ip,
		ClientMAC:      firstMAC(line),
		SessionCount:   parseInt(firstCapture(countRegex, line)),
		ProtocolMix:    firstNonEmpty(valueAfter(line, "protocol_mix"), protocolMix(lower)),
		LongLivedCount: parseInt(firstCapture(longLivedRegex, line)),
		RemoteCategory: firstNonEmpty(valueAfter(line, "remote_category"), remoteCategory(lower)),
		Burstiness:     firstNonEmpty(valueAfter(line, "burstiness"), burstiness(lower)),
	}, parsedTimestamp, true
}

func parseSessionGenericLine(line string, fallback time.Time) (SessionProfileEvent, bool, bool) {
	ev, parsedTimestamp, ok := parseSessionKeyValueLine(line, fallback)
	if ok {
		return ev, parsedTimestamp, true
	}
	ip := firstIPv4(line)
	if ip == "" {
		return SessionProfileEvent{}, false, false
	}
	ts, parsedTimestamp := extractTimestamp(line, fallback)
	lower := strings.ToLower(line)
	return SessionProfileEvent{
		Timestamp:      ts,
		ClientIP:       ip,
		ClientMAC:      firstMAC(line),
		SessionCount:   maxInt(1, parseInt(firstCapture(countRegex, line))),
		ProtocolMix:    protocolMix(lower),
		LongLivedCount: parseInt(firstCapture(longLivedRegex, line)),
		RemoteCategory: remoteCategory(lower),
		Burstiness:     burstiness(lower),
	}, parsedTimestamp, true
}

func normalizeInfraFormat(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "auto"
	}
	return v
}

func withinLookback(ts, now time.Time, lookback time.Duration, parsedTimestamp bool) bool {
	if !parsedTimestamp || lookback <= 0 {
		return true
	}
	if ts.IsZero() {
		return true
	}
	return !ts.Before(now.Add(-lookback))
}

func extractTimestamp(line string, fallback time.Time) (time.Time, bool) {
	line = strings.TrimSpace(syslogPriorityRegex.ReplaceAllString(strings.TrimSpace(line), ""))
	for _, candidate := range []string{
		rfc3339Regex.FindString(line),
		ymdTimeRegex.FindString(line),
		syslogTimeRegex.FindString(line),
	} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if ts, ok := parseTimestampCandidate(candidate, fallback); ok {
			return ts, true
		}
	}
	if fallback.IsZero() {
		fallback = time.Now().UTC()
	}
	return fallback.UTC(), false
}

func parseTimestampCandidate(candidate string, fallback time.Time) (time.Time, bool) {
	if candidate == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006/01/02 15:04:05",
	} {
		if ts, err := time.Parse(layout, candidate); err == nil {
			return ts.UTC(), true
		}
	}
	if ts, err := time.ParseInLocation("Jan 2 15:04:05", candidate, time.Local); err == nil {
		year := fallback.In(time.Local).Year()
		ts = time.Date(year, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, time.Local)
		return ts.UTC(), true
	}
	return time.Time{}, false
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

func splitCSVish(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == '|' || r == ' '
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func wifiState(lower string) string {
	switch {
	case strings.Contains(lower, "disassoc"), strings.Contains(lower, "disconnected"), strings.Contains(lower, "deauth"):
		return "disassociated"
	case strings.Contains(lower, "roam"):
		return "roaming"
	case strings.Contains(lower, "assoc"), strings.Contains(lower, "connected"):
		return "associated"
	default:
		return "observed"
	}
}

func authResult(lower string) string {
	switch {
	case strings.Contains(lower, "accept") || strings.Contains(lower, "success") || strings.Contains(lower, "ok"):
		return "accept"
	case strings.Contains(lower, "reject") || strings.Contains(lower, "fail") || strings.Contains(lower, "denied"):
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

func dhcpMessageTypeFromLine(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "DHCPDISCOVER"):
		return "discover"
	case strings.Contains(upper, "DHCPREQUEST"):
		return "request"
	case strings.Contains(upper, "DHCPACK"):
		return "ack"
	case strings.Contains(upper, "DHCPNAK"):
		return "nak"
	case strings.Contains(upper, "DHCPINFORM"):
		return "inform"
	case strings.Contains(upper, "DHCPOFFER"):
		return "offer"
	default:
		return ""
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}
