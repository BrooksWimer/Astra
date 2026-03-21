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

type PrinterProbe struct{}

func (s *PrinterProbe) Name() string { return "printer_probe" }

func (s *PrinterProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		printerProbeCollectTarget(t, emit)
	}
}

type printerProbeObservation struct {
	key     string
	value   string
	details map[string]string
}

func printerProbeCollectTarget(t Target, emit ObservationSink) {
	httpPorts := []int{80, 443, 631}
	for _, port := range httpPorts {
		for _, o := range printerProbeHTTP(t.IP, port) {
			emitObservation(emit, "printer_probe", t, o.key, o.value, o.details)
		}
	}
	for _, o := range printerProbeIPP(t.IP) {
		emitObservation(emit, "printer_probe", t, o.key, o.value, o.details)
	}
	for _, o := range printerProbePJL(t.IP) {
		emitObservation(emit, "printer_probe", t, o.key, o.value, o.details)
	}
}

func printerProbeHTTP(host string, port int) []printerProbeObservation {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: strategyProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s:%d/", scheme, host, port), nil)
	req.Header.Set("User-Agent", "netwise-printer-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return []printerProbeObservation{{key: "printer_http_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme, "error": err.Error()}}}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	title := printerProbeHTMLTitle(string(body))
	out := []printerProbeObservation{
		{key: "printer_http_server", value: strings.TrimSpace(resp.Header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
		{key: "printer_http_title", value: title, details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
		{key: "printer_http_authenticate", value: strings.TrimSpace(resp.Header.Get("WWW-Authenticate")), details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
	}
	if out[0].value == "" && out[1].value == "" && out[2].value == "" {
		out = append(out, printerProbeObservation{key: "printer_http_status", value: "empty", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}})
	} else {
		out = append(out, printerProbeObservation{key: "printer_http_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}})
	}
	return out
}

func printerProbeIPP(host string) []printerProbeObservation {
	paths := []string{"/ipp/print", "/ipp/printer"}
	out := []printerProbeObservation{}
	for _, path := range paths {
		reqBody := printerProbeIPPRequest("ipp://" + host + path)
		req, _ := http.NewRequest(http.MethodPost, "http://"+net.JoinHostPort(host, "631")+path, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/ipp")
		req.Header.Set("User-Agent", "netwise-printer-probe/1.0")
		client := &http.Client{Timeout: strategyProbeTimeout}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		attrs := printerProbeIPPAttributes(body)
		for _, key := range []string{"printer-name", "printer-info", "printer-make-and-model", "printer-uuid", "printer-state", "printer-uri-supported", "printer-command-set-supported"} {
			if v := attrs[key]; v != "" {
				out = append(out, printerProbeObservation{key: printerProbeIPPKey(key), value: v, details: map[string]string{"path": path}})
			}
		}
		if len(attrs) > 0 {
			out = append(out, printerProbeObservation{key: "printer_ipp_status", value: "real_data", details: map[string]string{"path": path}})
			return out
		}
	}
	if len(out) == 0 {
		out = append(out, printerProbeObservation{key: "printer_ipp_status", value: "no_response", details: nil})
	}
	return out
}

func printerProbeIPPRequest(printerURI string) []byte {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{0x01, 0x01})
	_ = binary.Write(buf, binary.BigEndian, uint16(0x000B))
	_ = binary.Write(buf, binary.BigEndian, uint32(1))
	buf.WriteByte(0x01) // operation-attributes-tag
	printerProbeIPPTextAttr(buf, 0x47, "attributes-charset", "utf-8")
	printerProbeIPPTextAttr(buf, 0x48, "attributes-natural-language", "en")
	printerProbeIPPTextAttr(buf, 0x45, "printer-uri", printerURI)
	buf.WriteByte(0x03)
	return buf.Bytes()
}

func printerProbeIPPTextAttr(buf *bytes.Buffer, tag byte, name, value string) {
	buf.WriteByte(tag)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(name)))
	buf.WriteString(name)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(value)))
	buf.WriteString(value)
}

func printerProbeIPPAttributes(data []byte) map[string]string {
	if len(data) < 8 {
		return nil
	}
	out := map[string]string{}
	i := 8
	var current string
	for i < len(data) {
		tag := data[i]
		i++
		if tag == 0x03 {
			break
		}
		if tag == 0x01 || tag == 0x02 || tag == 0x04 {
			continue
		}
		if i+2 > len(data) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
		var name string
		if nameLen > 0 {
			if i+nameLen > len(data) {
				break
			}
			name = string(data[i : i+nameLen])
			current = name
			i += nameLen
		} else {
			name = current
		}
		if i+2 > len(data) {
			break
		}
		valueLen := int(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
		if i+valueLen > len(data) {
			break
		}
		value := string(data[i : i+valueLen])
		i += valueLen
		if name != "" && value != "" {
			out[name] = value
		}
	}
	return out
}

func printerProbePJL(host string) []printerProbeObservation {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "9100"), strategyProbeTimeout)
	if err != nil {
		return []printerProbeObservation{{key: "printer_pjl_status", value: "no_response", details: map[string]string{"port": "9100", "error": err.Error()}}}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))

	_, _ = conn.Write([]byte("\x1b%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n@PJL INFO CONFIG\r\n"))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return []printerProbeObservation{{key: "printer_pjl_status", value: "no_response", details: map[string]string{"port": "9100", "error": err.Error()}}}
	}
	text := strings.TrimSpace(string(buf[:n]))
	if text == "" {
		return []printerProbeObservation{{key: "printer_pjl_status", value: "empty", details: map[string]string{"port": "9100"}}}
	}
	out := []printerProbeObservation{{key: "printer_pjl_id", value: printerProbeExtractPJL(text, "ID"), details: map[string]string{"port": "9100"}}}
	if v := printerProbeExtractPJL(text, "STATUS"); v != "" {
		out = append(out, printerProbeObservation{key: "printer_pjl_status_text", value: v, details: map[string]string{"port": "9100"}})
	}
	if v := printerProbeExtractPJL(text, "CONFIG"); v != "" {
		out = append(out, printerProbeObservation{key: "printer_pjl_config", value: v, details: map[string]string{"port": "9100"}})
	}
	out = append(out, printerProbeObservation{key: "printer_pjl_status", value: "real_data", details: map[string]string{"port": "9100"}})
	return out
}

func printerProbeExtractPJL(text, field string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		for _, prefix := range []string{"@PJL INFO " + field, "@PJL " + field} {
			if strings.HasPrefix(upper, prefix) {
				return strings.TrimSpace(line[len(prefix):])
			}
		}
	}
	return ""
}

func printerProbeHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	if start := strings.Index(lower, "<title>"); start >= 0 {
		start += len("<title>")
		if end := strings.Index(lower[start:], "</title>"); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}
	return ""
}

func printerProbeIPPKey(key string) string {
	switch key {
	case "printer-name":
		return "printer_name"
	case "printer-info":
		return "printer_info"
	case "printer-make-and-model":
		return "printer_make_model"
	case "printer-uuid":
		return "printer_uuid"
	case "printer-state":
		return "printer_state"
	case "printer-uri-supported":
		return "printer_uri_supported"
	case "printer-command-set-supported":
		return "printer_command_set"
	default:
		return "printer_" + strings.ReplaceAll(key, "-", "_")
	}
}
