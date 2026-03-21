package strategy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type VoipTelemetryProbe struct{}

func (s *VoipTelemetryProbe) Name() string { return "voip_telemetry_probe" }

func (s *VoipTelemetryProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		voipTelemetryProbeCollectTarget(t, emit)
	}
}

type voipTelemetryObservation struct {
	key     string
	value   string
	details map[string]string
}

func voipTelemetryProbeCollectTarget(t Target, emit ObservationSink) {
	probes := []struct {
		port      int
		transport string
		kind      string
	}{
		{port: 5060, transport: "udp", kind: "sip"},
		{port: 5061, transport: "tls", kind: "sip"},
		{port: 10000, transport: "tcp", kind: "sip"},
		{port: 3478, transport: "udp", kind: "stun"},
		{port: 5349, transport: "tls", kind: "stun"},
	}

	for _, probe := range probes {
		switch probe.kind {
		case "sip":
			for _, o := range voipTelemetryProbeSIP(t.IP, probe.port, probe.transport) {
				emitObservation(emit, "voip_telemetry_probe", t, o.key, o.value, o.details)
			}
		case "stun":
			for _, o := range voipTelemetryProbeSTUN(t.IP, probe.port, probe.transport) {
				emitObservation(emit, "voip_telemetry_probe", t, o.key, o.value, o.details)
			}
		}
	}
}

func voipTelemetryProbeSIP(host string, port int, transport string) []voipTelemetryObservation {
	msg := voipTelemetryProbeSIPRequest(host, port, transport)
	var resp []byte
	var err error

	switch transport {
	case "udp":
		var conn net.Conn
		conn, err = net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
			_, err = conn.Write(msg)
			if err == nil {
				buf := make([]byte, 8192)
				var n int
				n, err = conn.Read(buf)
				if err == nil {
					resp = buf[:n]
				}
			}
		}
	case "tls":
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			if err = tlsConn.Handshake(); err == nil {
				_, err = tlsConn.Write(msg)
				if err == nil {
					buf := make([]byte, 8192)
					var n int
					n, err = tlsConn.Read(buf)
					if err == nil {
						resp = buf[:n]
					}
				}
			}
		}
	default:
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
			_, err = conn.Write(msg)
			if err == nil {
				buf := make([]byte, 8192)
				var n int
				n, err = conn.Read(buf)
				if err == nil {
					resp = buf[:n]
				}
			}
		}
	}

	if err != nil {
		return []voipTelemetryObservation{{key: "sip_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "transport": transport, "error": err.Error()}}}
	}

	return voipTelemetryProbeParseSIP(resp, port, transport)
}

func voipTelemetryProbeSIPRequest(host string, port int, transport string) []byte {
	branch := voipTelemetryProbeTransactionID()
	local := "127.0.0.1"
	if host != "" {
		local = host
	}
	req := strings.Join([]string{
		fmt.Sprintf("OPTIONS sip:%s SIP/2.0", host),
		fmt.Sprintf("Via: SIP/2.0/%s %s:%d;branch=%s;rport", strings.ToUpper(transport), local, port, branch),
		"Max-Forwards: 70",
		"From: <sip:netwise@" + local + ">;tag=netwise",
		"To: <sip:" + host + ">",
		"Call-ID: " + branch + "@" + local,
		"CSeq: 1 OPTIONS",
		"Contact: <sip:netwise@" + local + ">",
		"Accept: application/sdp",
		"User-Agent: netwise-voip-probe/1.0",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	return []byte(req)
}

func voipTelemetryProbeParseSIP(resp []byte, port int, transport string) []voipTelemetryObservation {
	text := string(resp)
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return []voipTelemetryObservation{{key: "sip_status", value: "empty", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}}}
	}

	statusCode := ""
	if fields := strings.Fields(strings.TrimSpace(lines[0])); len(fields) >= 2 {
		statusCode = fields[1]
	}

	headers := voipTelemetryProbeHeaderMap(lines[1:])
	out := []voipTelemetryObservation{
		{key: "sip_transport", value: transport, details: map[string]string{"port": strconv.Itoa(port)}},
	}
	if statusCode != "" {
		out = append(out, voipTelemetryObservation{key: "sip_response_code", value: statusCode, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["server"]; v != "" {
		out = append(out, voipTelemetryObservation{key: "sip_server", value: v, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["user-agent"]; v != "" {
		out = append(out, voipTelemetryObservation{key: "sip_user_agent", value: v, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["allow"]; v != "" {
		out = append(out, voipTelemetryObservation{key: "sip_allow", value: v, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["supported"]; v != "" {
		out = append(out, voipTelemetryObservation{key: "sip_supported", value: v, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["contact"]; v != "" {
		out = append(out, voipTelemetryObservation{key: "sip_contact", value: v, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	if v := headers["www-authenticate"]; v != "" {
		if realm := voipTelemetryProbeRealm(v); realm != "" {
			out = append(out, voipTelemetryObservation{key: "sip_realm", value: realm, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
		}
	}
	if v := headers["proxy-authenticate"]; v != "" {
		if realm := voipTelemetryProbeRealm(v); realm != "" {
			out = append(out, voipTelemetryObservation{key: "sip_realm", value: realm, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
		}
	}

	if len(out) == 1 {
		out = append(out, voipTelemetryObservation{key: "sip_status", value: "unparsed", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	} else {
		out = append(out, voipTelemetryObservation{key: "sip_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	return out
}

func voipTelemetryProbeHeaderMap(lines []string) map[string]string {
	headers := map[string]string{}
	var current string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if current != "" {
				headers[current] = strings.TrimSpace(headers[current] + " " + line)
			}
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		headers[key] = value
		current = key
	}
	return headers
}

func voipTelemetryProbeRealm(v string) string {
	for _, needle := range []string{"realm=\"", "realm=", "Realm=\"", "Realm="} {
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

func voipTelemetryProbeTransactionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return fmt.Sprintf("%x", b[:])
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func voipTelemetryProbeSTUN(host string, port int, transport string) []voipTelemetryObservation {
	req := voipTelemetryProbeSTUNRequest()
	var resp []byte
	var err error

	switch transport {
	case "tls":
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			if err = tlsConn.Handshake(); err == nil {
				_, err = tlsConn.Write(req)
				if err == nil {
					buf := make([]byte, 2048)
					var n int
					n, err = tlsConn.Read(buf)
					if err == nil {
						resp = buf[:n]
					}
				}
			}
		}
	default:
		var conn net.Conn
		conn, err = net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
			_, err = conn.Write(req)
			if err == nil {
				buf := make([]byte, 2048)
				var n int
				n, err = conn.Read(buf)
				if err == nil {
					resp = buf[:n]
				}
			}
		}
	}

	if err != nil {
		return []voipTelemetryObservation{{key: "stun_status", value: "no_response", details: map[string]string{"port": strconv.Itoa(port), "transport": transport, "error": err.Error()}}}
	}

	return voipTelemetryProbeParseSTUN(resp, port, transport)
}

func voipTelemetryProbeSTUNRequest() []byte {
	var txn [12]byte
	if _, err := rand.Read(txn[:]); err != nil {
		copy(txn[:], []byte("netwisevoip!"))
	}

	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0001))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint32(0x2112A442))
	buf.Write(txn[:])
	return buf.Bytes()
}

func voipTelemetryProbeParseSTUN(resp []byte, port int, transport string) []voipTelemetryObservation {
	if len(resp) < 20 {
		return []voipTelemetryObservation{{key: "stun_status", value: "short_response", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}}}
	}

	msgType := binary.BigEndian.Uint16(resp[0:2])
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if 20+msgLen > len(resp) {
		msgLen = len(resp) - 20
	}
	out := []voipTelemetryObservation{
		{key: "stun_response_type", value: fmt.Sprintf("0x%04x", msgType), details: map[string]string{"port": strconv.Itoa(port), "transport": transport}},
	}

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
			out = append(out, voipTelemetryObservation{key: "stun_software", value: strings.TrimSpace(string(value)), details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
		case 0x0020:
			if mapped := voipTelemetryProbeParseXORMappedAddress(value); mapped != "" {
				out = append(out, voipTelemetryObservation{key: "stun_xor_mapped_address", value: mapped, details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
			}
		}
		pad := (attrLen + 3) &^ 3
		attrs = attrs[4+pad:]
	}
	if len(out) == 1 {
		out = append(out, voipTelemetryObservation{key: "stun_status", value: "unparsed", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	} else {
		out = append(out, voipTelemetryObservation{key: "stun_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port), "transport": transport}})
	}
	return out
}

func voipTelemetryProbeParseXORMappedAddress(v []byte) string {
	if len(v) < 8 {
		return ""
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4]) ^ 0x2112
	switch family {
	case 0x01:
		if len(v) < 8 {
			return ""
		}
		ip := []byte{v[4] ^ 0x21, v[5] ^ 0x12, v[6] ^ 0xA4, v[7] ^ 0x42}
		return net.IP(ip).String() + ":" + strconv.Itoa(int(port))
	default:
		return ""
	}
}
