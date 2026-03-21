package strategy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SwitchControllerTelemetry struct{}

func (s *SwitchControllerTelemetry) Name() string { return "switch_controller_telemetry" }

func (s *SwitchControllerTelemetry) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		switchControllerTelemetryCollectTarget(t, emit)
	}
}

type switchControllerObservation struct {
	key     string
	value   string
	details map[string]string
}

func switchControllerTelemetryCollectTarget(t Target, emit ObservationSink) {
	for _, port := range []int{8080, 8443, 8843, 9443} {
		for _, o := range switchControllerTelemetryHTTP(t.IP, port) {
			emitObservation(emit, "switch_controller_telemetry", t, o.key, o.value, o.details)
		}
	}
	for _, o := range switchControllerTelemetrySTUN(t.IP, 3478) {
		emitObservation(emit, "switch_controller_telemetry", t, o.key, o.value, o.details)
	}
}

func switchControllerTelemetryHTTP(host string, port int) []switchControllerObservation {
	scheme := "http"
	if port == 8443 || port == 8843 || port == 9443 {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: strategyProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	paths := []string{"/", "/api/info", "/api/status", "/status", "/manage"}
	for _, path := range paths {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path), nil)
		req.Header.Set("User-Agent", "netwise-switch-controller-probe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		title := switchControllerTelemetryHTMLTitle(string(body))
		out := []switchControllerObservation{
			{key: "controller_product", value: switchControllerTelemetryProduct(resp.Header.Get("Server"), string(body)), details: map[string]string{"port": strconv.Itoa(port), "path": path}},
			{key: "controller_version", value: switchControllerTelemetryVersion(resp.Header.Get("Server"), string(body)), details: map[string]string{"port": strconv.Itoa(port), "path": path}},
			{key: "controller_realm", value: resp.Header.Get("WWW-Authenticate"), details: map[string]string{"port": strconv.Itoa(port), "path": path}},
			{key: "controller_http_title", value: title, details: map[string]string{"port": strconv.Itoa(port), "path": path}},
			{key: "controller_http_server", value: resp.Header.Get("Server"), details: map[string]string{"port": strconv.Itoa(port), "path": path}},
		}
		if out[0].value == "" && out[1].value == "" && out[2].value == "" && out[3].value == "" && out[4].value == "" {
			continue
		}
		out = append(out, switchControllerObservation{key: "controller_http_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port), "path": path}})
		return out
	}
	return []switchControllerObservation{{key: "controller_http_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port)}}}
}

func switchControllerTelemetrySTUN(host string, port int) []switchControllerObservation {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
	req := switchControllerTelemetrySTUNRequest()
	if _, err := conn.Write(req); err != nil {
		return []switchControllerObservation{{key: "controller_stun", value: "write_error", details: map[string]string{"error": err.Error()}}}
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return []switchControllerObservation{{key: "controller_stun", value: "no_response", details: map[string]string{"error": err.Error()}}}
	}
	return switchControllerTelemetryParseSTUN(buf[:n])
}

func switchControllerTelemetrySTUNRequest() []byte {
	var txn [12]byte
	copy(txn[:], []byte("switchctrl12"))
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0001))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(0x2112A442))
	buf.Write(txn[:])
	return buf.Bytes()
}

func switchControllerTelemetryParseSTUN(resp []byte) []switchControllerObservation {
	if len(resp) < 20 {
		return []switchControllerObservation{{key: "controller_stun", value: "short_response", details: nil}}
	}
	msgType := binary.BigEndian.Uint16(resp[0:2])
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if 20+msgLen > len(resp) {
		msgLen = len(resp) - 20
	}
	out := []switchControllerObservation{{key: "controller_stun", value: fmt.Sprintf("0x%04x", msgType), details: nil}}
	attrs := resp[20 : 20+msgLen]
	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+attrLen > len(attrs) {
			break
		}
		value := attrs[4 : 4+attrLen]
		switch attrType {
		case 0x8022:
			out = append(out, switchControllerObservation{key: "controller_stun_software", value: strings.TrimSpace(string(value)), details: nil})
		case 0x0020:
			out = append(out, switchControllerObservation{key: "controller_stun_mapped_address", value: switchControllerTelemetryParseMappedAddress(value), details: nil})
		}
		pad := (attrLen + 3) &^ 3
		attrs = attrs[4+pad:]
	}
	out = append(out, switchControllerObservation{key: "controller_stun_status", value: "real_data", details: nil})
	return out
}

func switchControllerTelemetryParseMappedAddress(v []byte) string {
	if len(v) < 8 || v[1] != 0x01 {
		return ""
	}
	port := binary.BigEndian.Uint16(v[2:4]) ^ 0x2112
	ip := []byte{v[4] ^ 0x21, v[5] ^ 0x12, v[6] ^ 0xA4, v[7] ^ 0x42}
	return net.IP(ip).String() + ":" + strconv.Itoa(int(port))
}

func switchControllerTelemetryHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	if start := strings.Index(lower, "<title>"); start >= 0 {
		start += len("<title>")
		if end := strings.Index(lower[start:], "</title>"); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}
	return ""
}

func switchControllerTelemetryProduct(server, body string) string {
	text := strings.TrimSpace(server + " " + body)
	for _, needle := range []string{"UniFi", "Omada", "Aruba", "Cisco", "Mist", "Controller", "Switch"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(needle)) {
			return needle
		}
	}
	return strings.TrimSpace(server)
}

func switchControllerTelemetryVersion(server, body string) string {
	for _, src := range []string{server, body} {
		for _, token := range strings.Fields(src) {
			if strings.Count(token, ".") >= 1 && len(token) <= 24 {
				return strings.Trim(token, ",;")
			}
		}
	}
	return ""
}
