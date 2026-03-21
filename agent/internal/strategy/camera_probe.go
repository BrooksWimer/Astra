package strategy

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type CameraProbe struct{}

func (s *CameraProbe) Name() string { return "camera_probe" }

func (s *CameraProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		cameraProbeCollectTarget(t, emit)
	}
}

type cameraProbeObservation struct {
	key     string
	value   string
	details map[string]string
}

func cameraProbeCollectTarget(t Target, emit ObservationSink) {
	for _, port := range []int{80, 443, 554, 8554, 9000, 8080} {
		for _, o := range cameraProbeHTTP(t.IP, port) {
			emitObservation(emit, "camera_probe", t, o.key, o.value, o.details)
		}
		for _, o := range cameraProbeRTSP(t.IP, port) {
			emitObservation(emit, "camera_probe", t, o.key, o.value, o.details)
		}
		for _, o := range cameraProbeONVIF(t.IP, port) {
			emitObservation(emit, "camera_probe", t, o.key, o.value, o.details)
		}
	}
}

func cameraProbeHTTP(host string, port int) []cameraProbeObservation {
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
	req.Header.Set("User-Agent", "netwise-camera-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return []cameraProbeObservation{{key: "camera_http_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme, "error": err.Error()}}}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	title := cameraProbeHTMLTitle(string(body))
	out := []cameraProbeObservation{
		{key: "camera_http_server", value: strings.TrimSpace(resp.Header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
		{key: "camera_http_title", value: title, details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
		{key: "camera_http_realm", value: strings.TrimSpace(resp.Header.Get("WWW-Authenticate")), details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}},
	}
	if out[0].value == "" && out[1].value == "" && out[2].value == "" {
		out = append(out, cameraProbeObservation{key: "camera_http_status", value: "empty", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}})
	} else {
		out = append(out, cameraProbeObservation{key: "camera_http_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port), "scheme": scheme}})
	}
	return out
}

func cameraProbeRTSP(host string, port int) []cameraProbeObservation {
	if port != 554 && port != 8554 {
		return nil
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
	if err != nil {
		return []cameraProbeObservation{{key: "camera_rtsp_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "error": err.Error()}}}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))

	req := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: netwise-camera-probe/1.0\r\n\r\n", host, port)
	if _, err := conn.Write([]byte(req)); err != nil {
		return []cameraProbeObservation{{key: "camera_rtsp_status", value: "write_error", details: map[string]string{"port": strconv.Itoa(port), "error": err.Error()}}}
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return []cameraProbeObservation{{key: "camera_rtsp_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "error": err.Error()}}}
	}
	return cameraProbeParseRTSP(buf[:n], port)
}

func cameraProbeParseRTSP(resp []byte, port int) []cameraProbeObservation {
	text := string(resp)
	headers := cameraProbeHeaderMap(strings.Split(text, "\n"))
	out := []cameraProbeObservation{
		{key: "camera_rtsp_server", value: headers["server"], details: map[string]string{"port": strconv.Itoa(port)}},
		{key: "camera_rtsp_public", value: headers["public"], details: map[string]string{"port": strconv.Itoa(port)}},
		{key: "camera_rtsp_content_base", value: headers["content-base"], details: map[string]string{"port": strconv.Itoa(port)}},
		{key: "camera_rtsp_realm", value: cameraProbeRealm(headers["www-authenticate"]), details: map[string]string{"port": strconv.Itoa(port)}},
	}
	if body := cameraProbeRTSPBodyHint(text); body != "" {
		out = append(out, cameraProbeObservation{key: "camera_stream_path", value: body, details: map[string]string{"port": strconv.Itoa(port)}})
	}
	if out[0].value == "" && out[1].value == "" && out[2].value == "" && out[3].value == "" {
		out = append(out, cameraProbeObservation{key: "camera_rtsp_status", value: "unparsed", details: map[string]string{"port": strconv.Itoa(port)}})
	} else {
		out = append(out, cameraProbeObservation{key: "camera_rtsp_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
	}
	return out
}

func cameraProbeONVIF(host string, port int) []cameraProbeObservation {
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
	endpoints := []string{
		fmt.Sprintf("%s://%s:%d/onvif/device_service", scheme, host, port),
		fmt.Sprintf("%s://%s:%d/DeviceService", scheme, host, port),
	}
	for _, endpoint := range endpoints {
		reqBody := cameraProbeONVIFRequest()
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
		req.Header.Set("User-Agent", "netwise-camera-probe/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		attrs := cameraProbeONVIFAttributes(body)
		if len(attrs) == 0 {
			continue
		}
		out := []cameraProbeObservation{}
		keyMap := map[string]string{
			"manufacturer":    "camera_onvif_manufacturer",
			"model":           "camera_onvif_model",
			"firmwareversion": "camera_onvif_firmware_version",
			"serialnumber":    "camera_onvif_serial_number",
			"hardwareid":      "camera_onvif_hardware_id",
		}
		for _, key := range []string{"manufacturer", "model", "firmwareversion", "serialnumber", "hardwareid"} {
			if v := attrs[key]; v != "" {
				out = append(out, cameraProbeObservation{key: keyMap[key], value: v, details: map[string]string{"endpoint": endpoint}})
			}
		}
		if len(out) > 0 {
			out = append(out,
				cameraProbeObservation{key: "camera_vendor", value: attrs["manufacturer"], details: map[string]string{"endpoint": endpoint}},
				cameraProbeObservation{key: "camera_onvif_status", value: "real_data", details: map[string]string{"endpoint": endpoint}},
			)
			return out
		}
	}
	return nil
}

func cameraProbeONVIFRequest() []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>`)
}

func cameraProbeONVIFAttributes(data []byte) map[string]string {
	type info struct {
		Manufacturer   string `xml:"Manufacturer"`
		Model          string `xml:"Model"`
		FirmwareVersion string `xml:"FirmwareVersion"`
		SerialNumber   string `xml:"SerialNumber"`
		HardwareId     string `xml:"HardwareId"`
	}
	type env struct {
		Body struct {
			Response info `xml:"GetDeviceInformationResponse"`
		} `xml:"Body"`
	}
	var parsed env
	if err := xml.Unmarshal(data, &parsed); err == nil {
		if parsed.Body.Response.Manufacturer != "" || parsed.Body.Response.Model != "" {
			return map[string]string{
				"manufacturer":    parsed.Body.Response.Manufacturer,
				"model":           parsed.Body.Response.Model,
				"firmwareversion": parsed.Body.Response.FirmwareVersion,
				"serialnumber":    parsed.Body.Response.SerialNumber,
				"hardwareid":      parsed.Body.Response.HardwareId,
			}
		}
	}
	text := string(data)
	out := map[string]string{}
	for _, tag := range []string{"Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"} {
		if v := cameraProbeTagValue(text, tag); v != "" {
			out[strings.ToLower(tag)] = v
		}
	}
	return out
}

func cameraProbeTagValue(text, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	if start := strings.Index(text, open); start >= 0 {
		start += len(open)
		if end := strings.Index(text[start:], close); end >= 0 {
			return strings.TrimSpace(text[start : start+end])
		}
	}
	return ""
}

func cameraProbeHeaderMap(lines []string) map[string]string {
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

func cameraProbeRealm(v string) string {
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

func cameraProbeRTSPBodyHint(text string) string {
	lower := strings.ToLower(text)
	for _, needle := range []string{"a=control:", "control:", "stream=", "path="} {
		if idx := strings.Index(lower, needle); idx >= 0 {
			lineStart := idx
			if lineStart > 0 {
				if prev := strings.LastIndex(lower[:idx], "\n"); prev >= 0 {
					lineStart = prev + 1
				}
			}
			if end := strings.IndexAny(lower[idx:], "\r\n"); end >= 0 {
				return strings.TrimSpace(text[idx : idx+end])
			}
			return strings.TrimSpace(text[lineStart:])
		}
	}
	return ""
}

func cameraProbeHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	if start := strings.Index(lower, "<title>"); start >= 0 {
		start += len("<title>")
		if end := strings.Index(lower[start:], "</title>"); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}
	return ""
}
