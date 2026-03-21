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

type FirewallTrafficProfile struct{}

func (s *FirewallTrafficProfile) Name() string { return "firewall_traffic_profile" }

func (s *FirewallTrafficProfile) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		firewallTrafficProfileCollectTarget(t, emit)
	}
}

type firewallTrafficObservation struct {
	key     string
	value   string
	details map[string]string
}

func firewallTrafficProfileCollectTarget(t Target, emit ObservationSink) {
	for _, o := range firewallTrafficProfileDNS(t.IP) {
		emitObservation(emit, "firewall_traffic_profile", t, o.key, o.value, o.details)
	}
	for _, port := range []int{80, 443, 8080, 8443} {
		for _, o := range firewallTrafficProfileHTTP(t.IP, port) {
			emitObservation(emit, "firewall_traffic_profile", t, o.key, o.value, o.details)
		}
	}
	for _, o := range firewallTrafficProfileSSH(t.IP) {
		emitObservation(emit, "firewall_traffic_profile", t, o.key, o.value, o.details)
	}
}

func firewallTrafficProfileDNS(host string) []firewallTrafficObservation {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "53"), strategyProbeTimeout)
	if err != nil {
		return []firewallTrafficObservation{{key: "dns_version_bind", value: "no_response", details: map[string]string{"error": err.Error()}}}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(strategyProbeTimeout))
	if _, err := conn.Write(firewallTrafficProfileDNSQuery()); err != nil {
		return []firewallTrafficObservation{{key: "dns_version_bind", value: "write_error", details: map[string]string{"error": err.Error()}}}
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return []firewallTrafficObservation{{key: "dns_version_bind", value: "no_response", details: map[string]string{"error": err.Error()}}}
	}
	txt := firewallTrafficProfileParseDNSVersionBind(buf[:n])
	if txt == "" {
		return []firewallTrafficObservation{{key: "dns_version_bind", value: "unparsed", details: nil}}
	}
	return []firewallTrafficObservation{{key: "dns_version_bind", value: txt, details: nil}}
}

func firewallTrafficProfileDNSQuery() []byte {
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.BigEndian, uint16(0x1234))
	_ = binary.Write(buf, binary.BigEndian, uint16(0x0100))
	_ = binary.Write(buf, binary.BigEndian, uint16(1))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	_ = binary.Write(buf, binary.BigEndian, uint16(0))
	for _, label := range strings.Split("version.bind", ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	_ = binary.Write(buf, binary.BigEndian, uint16(16)) // TXT
	_ = binary.Write(buf, binary.BigEndian, uint16(3))  // CHAOS
	return buf.Bytes()
}

func firewallTrafficProfileParseDNSVersionBind(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		off = firewallTrafficProfileSkipDNSName(resp, off)
		if off+4 > len(resp) {
			return ""
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		off = firewallTrafficProfileSkipDNSName(resp, off)
		if off+10 > len(resp) {
			return ""
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		off += 2
		_ = binary.BigEndian.Uint16(resp[off : off+2])
		off += 2
		off += 4
		rdlen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2
		if off+rdlen > len(resp) {
			return ""
		}
		if typ == 16 && rdlen > 0 {
			parts := []string{}
			rdata := resp[off : off+rdlen]
			for len(rdata) > 0 {
				l := int(rdata[0])
				rdata = rdata[1:]
				if l > len(rdata) {
					break
				}
				parts = append(parts, string(rdata[:l]))
				rdata = rdata[l:]
			}
			return strings.Join(parts, " ")
		}
		off += rdlen
	}
	return ""
}

func firewallTrafficProfileSkipDNSName(resp []byte, off int) int {
	for off < len(resp) {
		l := int(resp[off])
		off++
		if l == 0 {
			return off
		}
		if l&0xC0 == 0xC0 {
			return off + 1
		}
		off += l
	}
	return off
}

func firewallTrafficProfileHTTP(host string, port int) []firewallTrafficObservation {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: strategyProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s:%d/", scheme, host, port), nil)
	req.Header.Set("User-Agent", "netwise-firewall-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	out := []firewallTrafficObservation{
		{key: "firewall_http_server", value: strings.TrimSpace(resp.Header.Get("Server")), details: map[string]string{"port": strconv.Itoa(port)}},
		{key: "firewall_http_title", value: firewallTrafficProfileHTMLTitle(string(body)), details: map[string]string{"port": strconv.Itoa(port)}},
	}
	if v := strings.TrimSpace(resp.Header.Get("WWW-Authenticate")); v != "" {
		out = append(out, firewallTrafficObservation{key: "firewall_http_authenticate", value: v, details: map[string]string{"port": strconv.Itoa(port)}})
	}
	if scheme == "https" {
		if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: strategyProbeTimeout}, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true}); err == nil {
			state := conn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				out = append(out,
					firewallTrafficObservation{key: "firewall_tls_subject", value: cert.Subject.String(), details: map[string]string{"port": strconv.Itoa(port)}},
					firewallTrafficObservation{key: "firewall_tls_issuer", value: cert.Issuer.String(), details: map[string]string{"port": strconv.Itoa(port)}},
				)
			}
			conn.Close()
		}
	}
	out = append(out, firewallTrafficObservation{key: "firewall_http_status", value: "real_data", details: map[string]string{"port": strconv.Itoa(port)}})
	return out
}

func firewallTrafficProfileSSH(host string) []firewallTrafficObservation {
	banner := readTCPServiceBanner(host, 22)
	if banner == "" {
		return nil
	}
	return []firewallTrafficObservation{
		{key: "firewall_ssh_banner", value: banner, details: map[string]string{"port": "22"}},
		{key: "firewall_ssh_status", value: "real_data", details: map[string]string{"port": "22"}},
	}
}

func firewallTrafficProfileHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	if start := strings.Index(lower, "<title>"); start >= 0 {
		start += len("<title>")
		if end := strings.Index(lower[start:], "</title>"); end >= 0 {
			return strings.TrimSpace(body[start : start+end])
		}
	}
	return ""
}
