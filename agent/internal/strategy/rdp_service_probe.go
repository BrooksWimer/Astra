package strategy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type RdpServiceProbe struct{}

func (s *RdpServiceProbe) Name() string { return "rdp_service_probe" }

func (s *RdpServiceProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		rdpServiceProbeCollectTarget(t, emit)
	}
}

type rdpServiceProbeObservation struct {
	key     string
	value   string
	details map[string]string
}

func rdpServiceProbeCollectTarget(t Target, emit ObservationSink) {
	if !isTCPPortOpen(t.IP, 3389, strategyProbeTimeout) {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "closed", nil)
		return
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(t.IP, "3389"), strategyProbeTimeout)
	if err != nil {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "no_response", map[string]string{"error": err.Error()})
		return
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "deadline_error", map[string]string{"error": err.Error()})
		return
	}

	if _, err := conn.Write(rdpServiceProbeRequest()); err != nil {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "write_error", map[string]string{"error": err.Error()})
		return
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "no_response", map[string]string{"error": err.Error()})
		return
	}

	protocol := rdpServiceProbeSelectedProtocol(buf[:n])
	if protocol == "" {
		emitObservation(emit, "rdp_service_probe", t, "rdp_status", "response", nil)
		return
	}

	details := map[string]string{"selected_protocol": protocol}
	emitObservation(emit, "rdp_service_probe", t, "rdp_protocol", protocol, details)
	emitObservation(emit, "rdp_service_probe", t, "rdp_tls", strconv.FormatBool(rdpServiceProbeNeedsTLS(protocol)), details)
	emitObservation(emit, "rdp_service_probe", t, "rdp_nla", strconv.FormatBool(strings.Contains(protocol, "nla")), details)
	emitObservation(emit, "rdp_service_probe", t, "rdp_status", "real_data", details)

	if rdpServiceProbeNeedsTLS(protocol) {
		for _, o := range rdpServiceProbeTLSMetadata(t) {
			emitObservation(emit, "rdp_service_probe", t, o.key, o.value, o.details)
		}
	}
}

func rdpServiceProbeRequest() []byte {
	cookie := "Cookie: mstshash=netwise\r\n"
	body := bytes.NewBuffer(nil)
	body.WriteByte(0x0E)
	body.Write([]byte{0xE0, 0x00, 0x00, 0x00, 0x00, 0x00})
	body.WriteString(cookie)
	body.Write([]byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00})

	tpktLen := 4 + body.Len()
	packet := bytes.NewBuffer(nil)
	packet.Write([]byte{0x03, 0x00, byte(tpktLen >> 8), byte(tpktLen)})
	packet.Write(body.Bytes())
	return packet.Bytes()
}

func rdpServiceProbeSelectedProtocol(resp []byte) string {
	idx := bytes.Index(resp, []byte{0x02, 0x00, 0x08, 0x00})
	if idx >= 0 && idx+8 <= len(resp) {
		selected := binary.LittleEndian.Uint32(resp[idx+4 : idx+8])
		return rdpServiceProbeProtocolLabel(selected)
	}
	idx = bytes.Index(resp, []byte{0x03, 0x00, 0x08, 0x00})
	if idx >= 0 && idx+8 <= len(resp) {
		selected := binary.LittleEndian.Uint32(resp[idx+4 : idx+8])
		return rdpServiceProbeProtocolLabel(selected)
	}
	return ""
}

func rdpServiceProbeProtocolLabel(v uint32) string {
	switch v {
	case 0:
		return "rdp"
	case 1:
		return "tls"
	case 2:
		return "nla"
	case 8:
		return "hybrid_ex"
	default:
		return fmt.Sprintf("0x%08x", v)
	}
}

func rdpServiceProbeNeedsTLS(protocol string) bool {
	return strings.Contains(protocol, "tls") || strings.Contains(protocol, "nla") || strings.Contains(protocol, "hybrid")
}

func rdpServiceProbeTLSMetadata(t Target) []rdpServiceProbeObservation {
	cloned, err := net.DialTimeout("tcp", net.JoinHostPort(t.IP, "3389"), strategyProbeTimeout)
	if err != nil {
		return nil
	}
	defer cloned.Close()

	if err := cloned.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		return nil
	}
	if _, err := cloned.Write(rdpServiceProbeRequest()); err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := cloned.Read(buf)
	if err != nil {
		return nil
	}
	if !rdpServiceProbeNeedsTLS(rdpServiceProbeSelectedProtocol(buf[:n])) {
		return nil
	}

	tlsConn := tls.Client(cloned, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		return nil
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	out := []rdpServiceProbeObservation{
		{key: "rdp_cert_subject", value: cert.Subject.String()},
		{key: "rdp_cert_issuer", value: cert.Issuer.String()},
		{key: "rdp_cert_sans", value: strings.Join(cert.DNSNames, ",")},
		{key: "rdp_tls_version", value: tlsVersionLabel(state.Version)},
		{key: "rdp_tls_cipher", value: tls.CipherSuiteName(state.CipherSuite)},
	}
	if len(cert.DNSNames) > 0 {
		out = append(out, rdpServiceProbeObservation{key: "rdp_ntlm_target", value: cert.DNSNames[0]})
	} else if cert.Subject.CommonName != "" {
		out = append(out, rdpServiceProbeObservation{key: "rdp_ntlm_target", value: cert.Subject.CommonName})
	}
	return out
}

func tlsVersionLabel(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "tls1.0"
	case tls.VersionTLS11:
		return "tls1.1"
	case tls.VersionTLS12:
		return "tls1.2"
	case tls.VersionTLS13:
		return "tls1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

