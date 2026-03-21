package strategy

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type MediaDeviceProbe struct{}

func (s *MediaDeviceProbe) Name() string { return "media_device_probe" }

func (s *MediaDeviceProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		mediaDeviceProbeCollectTarget(t, emit)
	}
}

type mediaDeviceProbeObservation struct {
	key     string
	value   string
	details map[string]string
}

func mediaDeviceProbeCollectTarget(t Target, emit ObservationSink) {
	openPorts := []int{80, 443, 554, 7000, 8008, 8009, 8060, 8096, 8200, 8554, 9000, 32400, 5555}
	openLabels := make([]string, 0, len(openPorts))
	for _, port := range openPorts {
		if isTCPPortOpen(t.IP, port, strategyProbeTimeout) {
			openLabels = append(openLabels, strconv.Itoa(port))
		}
	}
	if len(openLabels) == 0 {
		emitObservation(emit, "media_device_probe", t, "ports", "none", nil)
	} else {
		emitObservation(emit, "media_device_probe", t, "ports", strings.Join(openLabels, ","), nil)
	}

	for _, o := range mediaDeviceProbeAirPlay(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeCast(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeJellyfin(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeRoku(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbePlex(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeSonos(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeDLNA(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeRTSP(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, o := range mediaDeviceProbeADB(t.IP) {
		emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
	}
	for _, port := range []int{80, 443, 8008, 8009, 8060, 8096, 8200, 9000, 32400} {
		for _, o := range mediaDeviceProbeHTTPGeneric(t.IP, port) {
			emitObservation(emit, "media_device_probe", t, o.key, o.value, o.details)
		}
	}
}

func mediaDeviceProbeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: strategyProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func mediaDeviceProbeGET(host string, port int, path string) (string, http.Header, []byte, error) {
	scheme := mediaDeviceProbeScheme(port)
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path), nil)
	req.Header.Set("User-Agent", "netwise-media-probe/1.0")
	resp, err := mediaDeviceProbeHTTPClient().Do(req)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	return resp.Status, resp.Header, body, nil
}

func mediaDeviceProbeScheme(port int) string {
	switch port {
	case 443, 8009, 8443, 8843, 9443:
		return "https"
	default:
		return "http"
	}
}

func mediaDeviceProbeAirPlay(host string) []mediaDeviceProbeObservation {
	for _, port := range []int{7000} {
		_, header, body, err := mediaDeviceProbeGET(host, port, "/server-info")
		if err != nil {
			continue
		}
		info := mediaDeviceProbePlistSummary(body)
		out := []mediaDeviceProbeObservation{
			{key: "airplay_server", value: sanitizeMediaValue(header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "airplay_model", value: info["model"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "airplay_name", value: info["name"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "airplay_deviceid", value: info["deviceid"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "airplay_version", value: info["version"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "airplay_features", value: info["features"], details: map[string]string{"port": strconv.Itoa(port)}},
		}
		if hint := mediaDeviceProbeBodyHint(body); hint != "" {
			out = append(out, mediaDeviceProbeObservation{key: "airplay_hint", value: hint, details: map[string]string{"port": strconv.Itoa(port)}})
		}
		out = append(out, mediaDeviceProbeObservation{key: "airplay_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
		return out
	}
	return nil
}

func mediaDeviceProbeCast(host string) []mediaDeviceProbeObservation {
	out := []mediaDeviceProbeObservation{}
	for _, port := range []int{8008, 8009} {
		if _, header, body, err := mediaDeviceProbeGET(host, port, "/setup/eureka_info?params=name,device_info,build_info"); err == nil {
			info := mediaDeviceProbeCastInfo(body)
			out = append(out,
				mediaDeviceProbeObservation{key: "cast_server", value: sanitizeMediaValue(header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_name", value: anyString(info["name"], info["friendly_name"]), details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_model", value: anyString(info["model_name"], info["model"]), details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_manufacturer", value: anyString(info["manufacturer"], info["device_manufacturer"]), details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_udn", value: info["udn"], details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_build", value: anyString(info["build_info"], info["build"]), details: map[string]string{"port": strconv.Itoa(port)}},
			)
			if hint := mediaDeviceProbeBodyHint(body); hint != "" {
				out = append(out, mediaDeviceProbeObservation{key: "cast_hint", value: hint, details: map[string]string{"port": strconv.Itoa(port)}})
			}
		}
		if _, header, body, err := mediaDeviceProbeGET(host, port, "/ssdp/device-desc.xml"); err == nil {
			desc := mediaDeviceProbeUPnPDescription(body)
			out = append(out,
				mediaDeviceProbeObservation{key: "cast_device_type", value: desc["device_type"], details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_friendly_name", value: desc["friendly_name"], details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_manufacturer", value: anyString(desc["manufacturer"], header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
				mediaDeviceProbeObservation{key: "cast_model", value: desc["model_name"], details: map[string]string{"port": strconv.Itoa(port)}},
			)
		}
	}
	if len(out) > 0 {
		out = append(out, mediaDeviceProbeObservation{key: "cast_status", value: "real_data", details: nil})
	}
	return out
}

func mediaDeviceProbeJellyfin(host string) []mediaDeviceProbeObservation {
	for _, port := range []int{8096} {
		_, header, body, err := mediaDeviceProbeGET(host, port, "/System/Info/Public")
		if err != nil {
			continue
		}
		info := map[string]string{}
		_ = json.Unmarshal(body, &info)
		out := []mediaDeviceProbeObservation{
			{key: "media_server_header", value: sanitizeMediaValue(header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "media_server_name", value: anyString(info["ServerName"], info["serverName"]), details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "media_server_product", value: anyString(info["ProductName"], info["productName"], info["ServerName"]), details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "media_server_version", value: anyString(info["Version"], info["version"]), details: map[string]string{"port": strconv.Itoa(port)}},
		}
		if hint := mediaDeviceProbeBodyHint(body); hint != "" {
			out = append(out, mediaDeviceProbeObservation{key: "media_server_hint", value: hint, details: map[string]string{"port": strconv.Itoa(port)}})
		}
		out = append(out, mediaDeviceProbeObservation{key: "media_server_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
		return out
	}
	return nil
}

func mediaDeviceProbeRoku(host string) []mediaDeviceProbeObservation {
	_, _, body, err := mediaDeviceProbeGET(host, 8060, "/query/device-info")
	if err != nil {
		return nil
	}
	info := mediaDeviceProbeXMLFields(body)
	out := []mediaDeviceProbeObservation{
		{key: "roku_name", value: anyString(info["friendly-device-name"], info["friendly_device_name"], info["device-name"]), details: map[string]string{"port": "8060"}},
		{key: "roku_model", value: anyString(info["model-number"], info["model_number"]), details: map[string]string{"port": "8060"}},
		{key: "roku_serial", value: anyString(info["serial-number"], info["serial_number"]), details: map[string]string{"port": "8060"}},
		{key: "roku_version", value: anyString(info["software-version"], info["software_version"]), details: map[string]string{"port": "8060"}},
	}
	out = append(out, mediaDeviceProbeObservation{key: "roku_status", value: "real_data", details: map[string]string{"port": "8060"}})
	return out
}

func mediaDeviceProbePlex(host string) []mediaDeviceProbeObservation {
	_, header, body, err := mediaDeviceProbeGET(host, 32400, "/identity")
	if err != nil {
		return nil
	}
	info := mediaDeviceProbeXMLFields(body)
	out := []mediaDeviceProbeObservation{
		{key: "plex_machine_identifier", value: anyString(info["machineidentifier"], info["machine_identifier"]), details: map[string]string{"port": "32400"}},
		{key: "plex_product", value: anyString(info["product"], info["name"]), details: map[string]string{"port": "32400"}},
		{key: "plex_version", value: anyString(info["version"], header.Get("X-Plex-Version")), details: map[string]string{"port": "32400"}},
	}
	out = append(out, mediaDeviceProbeObservation{key: "plex_status", value: "real_data", details: map[string]string{"port": "32400"}})
	return out
}

func mediaDeviceProbeSonos(host string) []mediaDeviceProbeObservation {
	paths := []string{"/status/info", "/xml/device_description.xml"}
	for _, path := range paths {
		_, header, body, err := mediaDeviceProbeGET(host, 1400, path)
		if err != nil {
			continue
		}
		info := mediaDeviceProbeXMLFields(body)
		out := []mediaDeviceProbeObservation{
			{key: "sonos_name", value: anyString(info["zonename"], info["zone_name"], info["friendlyname"]), details: map[string]string{"path": path}},
			{key: "sonos_model", value: anyString(info["modelnumber"], info["model_number"]), details: map[string]string{"path": path}},
			{key: "sonos_serial", value: anyString(info["serialnumber"], info["serial_number"]), details: map[string]string{"path": path}},
			{key: "sonos_firmware", value: anyString(info["softwareversion"], info["software_version"], header.Get("X-Sonos-Version")), details: map[string]string{"path": path}},
		}
		out = append(out, mediaDeviceProbeObservation{key: "sonos_status", value: "real_data", details: map[string]string{"path": path}})
		return out
	}
	return nil
}

func mediaDeviceProbeDLNA(host string) []mediaDeviceProbeObservation {
	for _, path := range []string{"/rootDesc.xml", "/device.xml", "/description.xml"} {
		_, _, body, err := mediaDeviceProbeGET(host, 8200, path)
		if err != nil {
			continue
		}
		desc := mediaDeviceProbeUPnPDescription(body)
		out := []mediaDeviceProbeObservation{
			{key: "dlna_device_type", value: desc["device_type"], details: map[string]string{"path": path}},
			{key: "dlna_manufacturer", value: desc["manufacturer"], details: map[string]string{"path": path}},
			{key: "dlna_model", value: desc["model_name"], details: map[string]string{"path": path}},
			{key: "dlna_friendly_name", value: desc["friendly_name"], details: map[string]string{"path": path}},
			{key: "dlna_udn", value: desc["udn"], details: map[string]string{"path": path}},
		}
		out = append(out, mediaDeviceProbeObservation{key: "dlna_status", value: "real_data", details: map[string]string{"path": path}})
		return out
	}
	return nil
}

func mediaDeviceProbeRTSP(host string) []mediaDeviceProbeObservation {
	for _, port := range []int{554, 8554} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
		req := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: netwise-media-probe/1.0\r\n\r\n", host, port)
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}
		headers := mediaDeviceProbeHeaderMap(strings.Split(string(buf[:n]), "\n"))
		out := []mediaDeviceProbeObservation{
			{key: "rtsp_server", value: headers["server"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "rtsp_public", value: headers["public"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "rtsp_content_base", value: headers["content-base"], details: map[string]string{"port": strconv.Itoa(port)}},
			{key: "rtsp_realm", value: mediaDeviceProbeRealm(headers["www-authenticate"]), details: map[string]string{"port": strconv.Itoa(port)}},
		}
		if hint := mediaDeviceProbeRTSPHint(string(buf[:n])); hint != "" {
			out = append(out, mediaDeviceProbeObservation{key: "media_stream_path", value: hint, details: map[string]string{"port": strconv.Itoa(port)}})
		}
		out = append(out, mediaDeviceProbeObservation{key: "rtsp_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
		return out
	}
	return nil
}

func mediaDeviceProbeADB(host string) []mediaDeviceProbeObservation {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "5555"), strategyProbeTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
	if _, err := conn.Write([]byte("000Chost:version")); err != nil {
		return []mediaDeviceProbeObservation{{key: "adb_status", value: "write_error", details: map[string]string{"error": err.Error()}}}
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return []mediaDeviceProbeObservation{{key: "adb_status", value: "no_response", details: map[string]string{"error": err.Error()}}}
	}
	text := strings.TrimSpace(string(buf[:n]))
	out := []mediaDeviceProbeObservation{
		{key: "adb_banner", value: text, details: nil},
		{key: "adb_status", value: "real_data", details: nil},
	}
	if len(text) >= 4 {
		out = append(out, mediaDeviceProbeObservation{key: "adb_version", value: text[:4], details: nil})
	}
	return out
}

func mediaDeviceProbeHTTPGeneric(host string, port int) []mediaDeviceProbeObservation {
	if port == 554 || port == 8554 || port == 5555 || port == 7000 || port == 32400 || port == 1400 || port == 8060 || port == 8096 || port == 8200 {
		return nil
	}
	_, header, body, err := mediaDeviceProbeGET(host, port, "/")
	if err != nil {
		return nil
	}
	out := []mediaDeviceProbeObservation{
		{key: "media_server_header", value: sanitizeMediaValue(header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
		{key: "media_server_title", value: mediaDeviceProbeHTMLTitle(string(body)), details: map[string]string{"port": strconv.Itoa(port)}},
	}
	if hint := mediaDeviceProbeBodyHint(body); hint != "" {
		out = append(out, mediaDeviceProbeObservation{key: "media_server_hint", value: hint, details: map[string]string{"port": strconv.Itoa(port)}})
	}
	out = append(out, mediaDeviceProbeObservation{key: "media_server_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
	return out
}

func mediaDeviceProbeCastInfo(body []byte) map[string]string {
	out := map[string]string{}
	var raw any
	if err := json.Unmarshal(body, &raw); err == nil {
		mediaDeviceProbeFlattenJSON("", raw, out)
		if len(out) > 0 {
			return out
		}
	}
	return mediaDeviceProbeXMLFields(body)
}

func mediaDeviceProbeXMLFields(body []byte) map[string]string {
	type element struct {
		XMLName xml.Name
		Inner   string `xml:",chardata"`
	}
	type node struct {
		XMLName xml.Name
		Items   []node `xml:",any"`
		Value   string `xml:",chardata"`
	}
	var root node
	if err := xml.Unmarshal(body, &root); err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	var walk func(node)
	walk = func(n node) {
		key := strings.ToLower(n.XMLName.Local)
		if n.Value != "" {
			out[key] = strings.TrimSpace(n.Value)
		}
		for _, child := range n.Items {
			walk(child)
		}
	}
	walk(root)
	return out
}

func mediaDeviceProbeFlattenJSON(prefix string, value any, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			nextPrefix := strings.ToLower(strings.TrimSpace(key))
			if prefix != "" {
				nextPrefix = prefix + "." + nextPrefix
			}
			mediaDeviceProbeFlattenJSON(nextPrefix, child, out)
		}
	case []any:
		for i, child := range v {
			mediaDeviceProbeFlattenJSON(fmt.Sprintf("%s[%d]", prefix, i), child, out)
		}
	case string:
		if prefix != "" {
			value := strings.TrimSpace(v)
			out[prefix] = value
			if idx := strings.LastIndex(prefix, "."); idx >= 0 && idx+1 < len(prefix) {
				out[prefix[idx+1:]] = value
			} else {
				out[prefix] = value
			}
		}
	case float64:
		if prefix != "" {
			value := strconv.FormatFloat(v, 'f', -1, 64)
			out[prefix] = value
			if idx := strings.LastIndex(prefix, "."); idx >= 0 && idx+1 < len(prefix) {
				out[prefix[idx+1:]] = value
			}
		}
	case bool:
		if prefix != "" {
			value := strconv.FormatBool(v)
			out[prefix] = value
			if idx := strings.LastIndex(prefix, "."); idx >= 0 && idx+1 < len(prefix) {
				out[prefix[idx+1:]] = value
			}
		}
	}
}

func mediaDeviceProbeUPnPDescription(body []byte) map[string]string {
	type item struct {
		DeviceType       string `xml:"deviceType"`
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ManufacturerURL  string `xml:"manufacturerURL"`
		ModelDescription  string `xml:"modelDescription"`
		ModelName        string `xml:"modelName"`
		ModelNumber      string `xml:"modelNumber"`
		UDN              string `xml:"UDN"`
		PresentationURL  string `xml:"presentationURL"`
		SerialNumber     string `xml:"serialNumber"`
		SoftwareVersion  string `xml:"softwareVersion"`
	}
	type root struct {
		Device item `xml:"device"`
	}
	var r root
	if err := xml.Unmarshal(body, &r); err == nil && r.Device.FriendlyName != "" {
		return map[string]string{
			"device_type":      r.Device.DeviceType,
			"friendly_name":    r.Device.FriendlyName,
			"manufacturer":     r.Device.Manufacturer,
			"model_name":       r.Device.ModelName,
			"model_number":     r.Device.ModelNumber,
			"udn":              r.Device.UDN,
			"presentation_url": r.Device.PresentationURL,
		}
	}
	return mediaDeviceProbeXMLFields(body)
}

func mediaDeviceProbePlistSummary(body []byte) map[string]string {
	text := string(body)
	out := map[string]string{}
	for _, key := range []string{"model", "name", "deviceid", "version", "features"} {
		if v := mediaDeviceProbeTagOrPlist(text, key); v != "" {
			out[key] = v
		}
	}
	return out
}

func mediaDeviceProbeTagOrPlist(text, key string) string {
	if v := mediaDeviceProbeTagValue(text, key); v != "" {
		return v
	}
	needle := "<key>" + key + "</key>"
	if idx := strings.Index(strings.ToLower(text), strings.ToLower(needle)); idx >= 0 {
		rest := text[idx+len(needle):]
		if start := strings.Index(rest, "<string>"); start >= 0 {
			start += len("<string>")
			if end := strings.Index(rest[start:], "</string>"); end >= 0 {
				return strings.TrimSpace(rest[start : start+end])
			}
		}
	}
	return ""
}

func mediaDeviceProbeTagValue(text, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	if start := strings.Index(strings.ToLower(text), strings.ToLower(open)); start >= 0 {
		start += len(open)
		if end := strings.Index(strings.ToLower(text[start:]), strings.ToLower(close)); end >= 0 {
			return strings.TrimSpace(text[start : start+end])
		}
	}
	return ""
}

func mediaDeviceProbeHeaderMap(lines []string) map[string]string {
	headers := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(line[:idx]))] = strings.TrimSpace(line[idx+1:])
	}
	return headers
}

func mediaDeviceProbeRealm(v string) string {
	for _, needle := range []string{"realm=\"", "realm="} {
		if idx := strings.Index(v, needle); idx >= 0 {
			start := idx + len(needle)
			rest := v[start:]
			if end := strings.IndexAny(rest, "\";,"); end >= 0 {
				return strings.TrimSpace(rest[:end])
			}
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func mediaDeviceProbeRTSPHint(text string) string {
	lower := strings.ToLower(text)
	for _, needle := range []string{"a=control:", "control:", "stream=", "path="} {
		if idx := strings.Index(lower, needle); idx >= 0 {
			if end := strings.IndexAny(lower[idx:], "\r\n"); end >= 0 {
				return strings.TrimSpace(text[idx : idx+end])
			}
			return strings.TrimSpace(text[idx:])
		}
	}
	return ""
}

func mediaDeviceProbeHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	if start := strings.Index(lower, "<title>"); start >= 0 {
		start += len("<title>")
		if end := strings.Index(lower[start:], "</title>"); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}
	return ""
}

func mediaDeviceProbeBodyHint(body []byte) string {
	text := strings.ToLower(string(body))
	for _, needle := range []string{"airplay", "cast", "roku", "plex", "sonos", "dlna", "onvif", "rtsp", "android tv", "jellyfin"} {
		if strings.Contains(text, needle) {
			return needle
		}
	}
	return ""
}

func sanitizeMediaValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"")
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

func anyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
