package passive

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *Session) parsePacket(packet gopacket.Packet) {
	ts := packet.Metadata().Timestamp.UTC()
	srcMAC, dstMAC := ethernetPair(packet)
	srcIP, dstIP := ipPair(packet)
	if srcIP == "" && dstIP == "" {
		return
	}
	transport, srcPort, dstPort, payload := transportPayload(packet)
	if transport != "" {
		s.appendFlow(FlowEvent{
			Timestamp: ts,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			Transport: transport,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  protocolHint(transport, srcPort, dstPort, payload),
		})
	}
	if len(payload) == 0 {
		if strings.Contains(srcIP, ":") || strings.Contains(dstIP, ":") {
			s.appendIPv6(IPv6Event{
				Timestamp:      ts,
				SrcIP:          srcIP,
				DstIP:          dstIP,
				SrcMAC:         srcMAC,
				DstMAC:         dstMAC,
				Role:           "observed",
				PrivacyAddress: isIPv6PrivacyAddress(srcIP),
				SLAACBehavior:  ipv6Behavior(srcIP),
			})
		}
		return
	}

	switch {
	case transport == "udp" && (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68):
		if ev, ok := parseDHCP(payload, ts, srcIP, dstIP, srcMAC); ok {
			s.appendDHCP(ev)
		}
	case (transport == "udp" || transport == "tcp") && (srcPort == 53 || dstPort == 53):
		for _, ev := range parseDNS(payload, transport, ts, srcIP, srcMAC, dstIP) {
			s.appendDNS(ev)
		}
	case transport == "udp" && (srcPort == 5353 || dstPort == 5353):
		for _, ev := range parseMDNS(payload, ts, srcIP, srcMAC) {
			s.appendMDNS(ev)
		}
	case transport == "udp" && (srcPort == 1900 || dstPort == 1900):
		if ev, ok := parseSSDP(payload, ts, srcIP, srcMAC); ok {
			s.appendSSDP(ev)
		}
	case transport == "tcp":
		if ev, ok := parseHTTP(payload, ts, srcIP, dstIP, srcMAC, dstMAC); ok {
			s.appendHTTP(ev)
		}
		if ev, ok := parseSSH(payload, ts, srcIP, dstIP, srcMAC, dstMAC); ok {
			s.appendSSH(ev)
		}
		if client, server := parseTLS(payload, ts, srcIP, dstIP, srcMAC, dstMAC); client != nil {
			s.appendTLSClient(*client)
		} else if server != nil {
			s.appendTLSServer(*server)
		}
	case transport == "udp" && (srcPort == 443 || dstPort == 443):
		if ev, ok := parseQUIC(payload, ts, srcIP, dstIP, srcMAC, dstMAC); ok {
			s.appendQUIC(ev)
		}
	}
	if strings.Contains(srcIP, ":") || strings.Contains(dstIP, ":") {
		s.appendIPv6(IPv6Event{
			Timestamp:      ts,
			SrcIP:          srcIP,
			DstIP:          dstIP,
			SrcMAC:         srcMAC,
			DstMAC:         dstMAC,
			Role:           "observed",
			PrivacyAddress: isIPv6PrivacyAddress(srcIP),
			SLAACBehavior:  ipv6Behavior(srcIP),
		})
	}
}

func ethernetPair(packet gopacket.Packet) (string, string) {
	layer := packet.Layer(layers.LayerTypeEthernet)
	if layer == nil {
		return "", ""
	}
	eth := layer.(*layers.Ethernet)
	return normalizeMAC(eth.SrcMAC.String()), normalizeMAC(eth.DstMAC.String())
}

func ipPair(packet gopacket.Packet) (string, string) {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip := layer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	return "", ""
}

func transportPayload(packet gopacket.Packet) (string, int, int, []byte) {
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp := layer.(*layers.TCP)
		return "tcp", int(tcp.SrcPort), int(tcp.DstPort), tcp.Payload
	}
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		return "udp", int(udp.SrcPort), int(udp.DstPort), udp.Payload
	}
	return "", 0, 0, nil
}

func protocolHint(transport string, srcPort, dstPort int, payload []byte) string {
	switch {
	case srcPort == 53 || dstPort == 53:
		return "dns"
	case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
		return "dhcp"
	case srcPort == 5353 || dstPort == 5353:
		return "mdns"
	case srcPort == 1900 || dstPort == 1900:
		return "ssdp"
	case srcPort == 22 || dstPort == 22:
		return "ssh"
	case srcPort == 443 || dstPort == 443:
		if looksLikeTLS(payload) {
			return "tls"
		}
		if looksLikeQUIC(payload) {
			return "quic"
		}
	case looksLikeHTTP(payload):
		return "http"
	}
	return transport
}

func parseDHCP(payload []byte, ts time.Time, srcIP, dstIP, srcMAC string) (DHCPEvent, bool) {
	var dhcp layers.DHCPv4
	if err := dhcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return DHCPEvent{}, false
	}
	ev := DHCPEvent{
		Timestamp: ts,
		ClientIP:  srcIP,
		ClientMAC: normalizeMAC(dhcp.ClientHWAddr.String()),
		ServerIP:  dstIP,
	}
	if ev.ClientMAC == "" {
		ev.ClientMAC = normalizeMAC(srcMAC)
	}
	for _, opt := range dhcp.Options {
		code := int(opt.Type)
		ev.OptionOrder = append(ev.OptionOrder, strconv.Itoa(code))
		switch code {
		case 12:
			ev.Hostname = strings.TrimSpace(string(opt.Data))
		case 50:
			if len(opt.Data) == 4 {
				ev.RequestedIP = net.IP(opt.Data).String()
			}
		case 53:
			if len(opt.Data) > 0 {
				ev.MessageType = dhcpMessageType(opt.Data[0])
			}
		case 55:
			ev.PRL = bytesToStringSlice(opt.Data)
		case 60:
			ev.VendorClass = strings.TrimSpace(string(opt.Data))
		case 61:
			ev.ClientIdentifier = hex.EncodeToString(opt.Data)
		}
	}
	if ev.ClientIP == "" || ev.ClientIP == "0.0.0.0" {
		ev.ClientIP = ev.RequestedIP
	}
	return ev, true
}

func parseDNS(payload []byte, transport string, ts time.Time, srcIP, srcMAC, dstIP string) []DNSEvent {
	if transport == "tcp" && len(payload) > 2 {
		length := int(binary.BigEndian.Uint16(payload[:2]))
		if length > 0 && 2+length <= len(payload) {
			payload = payload[2 : 2+length]
		}
	}
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	out := make([]DNSEvent, 0, len(dns.Questions))
	for _, q := range dns.Questions {
		name := strings.TrimSuffix(strings.ToLower(string(q.Name)), ".")
		out = append(out, DNSEvent{
			Timestamp:  ts,
			ClientIP:   srcIP,
			ClientMAC:  normalizeMAC(srcMAC),
			ResolverIP: dstIP,
			Query:      name,
			QueryType:  dnsTypeString(q.Type),
			Transport:  transport,
			Category:   domainCategory(name),
			IsReverse:  strings.HasSuffix(name, ".arpa"),
			IsLocal:    isLocalName(name),
		})
	}
	return out
}

func parseMDNS(payload []byte, ts time.Time, srcIP, srcMAC string) []MDNSEvent {
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	out := []MDNSEvent{}
	if !dns.QR {
		for _, q := range dns.Questions {
			name := strings.TrimSuffix(strings.ToLower(string(q.Name)), ".")
			out = append(out, MDNSEvent{
				Timestamp:     ts,
				SrcIP:         srcIP,
				SrcMAC:        normalizeMAC(srcMAC),
				MessageType:   "query",
				Name:          name,
				QueryType:     dnsTypeString(q.Type),
				ServiceFamily: mdnsServiceFamily(name),
			})
		}
		return out
	}
	for _, rr := range dns.Answers {
		name := strings.TrimSuffix(strings.ToLower(string(rr.Name)), ".")
		out = append(out, MDNSEvent{
			Timestamp:     ts,
			SrcIP:         srcIP,
			SrcMAC:        normalizeMAC(srcMAC),
			MessageType:   "announcement",
			Name:          name,
			QueryType:     dnsTypeString(rr.Type),
			ServiceFamily: mdnsServiceFamily(name),
			TTL:           rr.TTL,
			Instance:      instanceFromMDNSName(name),
			Hostname:      name,
		})
	}
	return out
}

func parseSSDP(payload []byte, ts time.Time, srcIP, srcMAC string) (SSDPEVent, bool) {
	text := string(payload)
	if !strings.Contains(text, "HTTP/1.1") && !strings.HasPrefix(text, "NOTIFY") && !strings.HasPrefix(text, "M-SEARCH") {
		return SSDPEVent{}, false
	}
	ev := SSDPEVent{
		Timestamp:   ts,
		SrcIP:       srcIP,
		SrcMAC:      normalizeMAC(srcMAC),
		MessageType: "response",
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 {
		first := strings.TrimSpace(lines[0])
		switch {
		case strings.HasPrefix(first, "NOTIFY"):
			ev.MessageType = "notify"
		case strings.HasPrefix(first, "M-SEARCH"):
			ev.MessageType = "search"
		}
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "st:"):
			ev.ST = strings.TrimSpace(line[3:])
		case strings.HasPrefix(lower, "nt:"):
			ev.NT = strings.TrimSpace(line[3:])
		case strings.HasPrefix(lower, "nts:"):
			ev.NTS = strings.TrimSpace(line[4:])
		case strings.HasPrefix(lower, "usn:"):
			ev.USN = strings.TrimSpace(line[4:])
		case strings.HasPrefix(lower, "server:"):
			ev.Server = strings.TrimSpace(line[7:])
		case strings.HasPrefix(lower, "location:"):
			ev.Location = strings.TrimSpace(line[9:])
		case strings.HasPrefix(lower, "cache-control:"):
			ev.CacheControl = strings.TrimSpace(line[len("cache-control:"):])
		}
	}
	return ev, true
}

func parseHTTP(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) (HTTPEvent, bool) {
	text := string(payload)
	if !looksLikeHTTP(payload) {
		return HTTPEvent{}, false
	}
	ev := HTTPEvent{Timestamp: ts, SrcIP: srcIP, DstIP: dstIP, SrcMAC: normalizeMAC(srcMAC), DstMAC: normalizeMAC(dstMAC)}
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return HTTPEvent{}, false
	}
	first := strings.TrimSpace(lines[0])
	if strings.HasPrefix(first, "HTTP/") {
		ev.Role = "response"
		fields := strings.Fields(first)
		if len(fields) >= 2 {
			ev.StatusCode, _ = strconv.Atoi(fields[1])
		}
	} else {
		ev.Role = "request"
		fields := strings.Fields(first)
		if len(fields) >= 2 {
			ev.PathHint = strings.TrimSpace(fields[1])
		}
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "host:"):
			ev.Host = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "user-agent:"):
			ev.UserAgent = strings.TrimSpace(line[len("user-agent:"):])
		case strings.HasPrefix(lower, "server:"):
			ev.Server = strings.TrimSpace(line[7:])
		}
	}
	return ev, true
}

func parseSSH(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) (SSHEvent, bool) {
	line := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(line, "SSH-") {
		return SSHEvent{}, false
	}
	ev := SSHEvent{Timestamp: ts, SrcIP: srcIP, DstIP: dstIP, SrcMAC: normalizeMAC(srcMAC), DstMAC: normalizeMAC(dstMAC), Banner: line}
	parts := strings.Split(line, "-")
	if len(parts) >= 2 {
		ev.Proto = parts[1]
	}
	if len(parts) >= 3 {
		ev.Software = strings.Join(parts[2:], "-")
	}
	return ev, true
}

func parseTLS(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) (*TLSClientEvent, *TLSServerEvent) {
	if !looksLikeTLS(payload) || len(payload) < 9 || payload[0] != 22 {
		return nil, nil
	}
	if payload[5] == 1 {
		return parseTLSClientHello(payload, ts, srcIP, dstIP, srcMAC, dstMAC), nil
	}
	return nil, parseTLSServerRecord(payload, ts, srcIP, dstIP, srcMAC, dstMAC)
}

func parseTLSClientHello(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) *TLSClientEvent {
	if len(payload) < 11 || payload[5] != 1 {
		return nil
	}
	bodyLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	if bodyLen <= 0 || 9+bodyLen > len(payload) {
		return nil
	}
	body := payload[9 : 9+bodyLen]
	if len(body) < 34 {
		return nil
	}
	offset := 34
	if offset >= len(body) {
		return nil
	}
	sessionLen := int(body[offset])
	offset++
	if offset+sessionLen+2 > len(body) {
		return nil
	}
	offset += sessionLen
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+cipherLen > len(body) {
		return nil
	}
	ciphers := []string{}
	for i := offset; i+1 < offset+cipherLen; i += 2 {
		ciphers = append(ciphers, strconv.Itoa(int(binary.BigEndian.Uint16(body[i:i+2]))))
	}
	offset += cipherLen
	if offset >= len(body) {
		return nil
	}
	compressionLen := int(body[offset])
	offset++
	offset += compressionLen
	if offset+2 > len(body) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extLen > len(body) {
		return nil
	}
	extensions := body[offset : offset+extLen]
	extIDs := []string{}
	alpn := ""
	sni := ""
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extSize := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extSize > len(extensions) {
			break
		}
		extData := extensions[:extSize]
		extensions = extensions[extSize:]
		extIDs = append(extIDs, strconv.Itoa(int(extType)))
		switch extType {
		case 0:
			sni = parseTLSSNI(extData)
		case 16:
			alpn = parseTLSALPN(extData)
		}
	}
	return &TLSClientEvent{
		Timestamp:          ts,
		SrcIP:              srcIP,
		DstIP:              dstIP,
		SrcMAC:             normalizeMAC(srcMAC),
		DstMAC:             normalizeMAC(dstMAC),
		JA3:                md5Hex(strings.Join([]string{tlsVersionString(binary.BigEndian.Uint16(body[0:2])), strings.Join(ciphers, "-"), strings.Join(extIDs, "-")}, ",")),
		Version:            tlsVersionString(binary.BigEndian.Uint16(body[0:2])),
		ALPN:               alpn,
		SNI:                sni,
		SNICategory:        domainCategory(sni),
		CipherOrderHash:    md5Hex(strings.Join(ciphers, "-")),
		ExtensionOrderHash: md5Hex(strings.Join(extIDs, "-")),
	}
}

func parseTLSServerRecord(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) *TLSServerEvent {
	ev := &TLSServerEvent{Timestamp: ts, SrcIP: srcIP, DstIP: dstIP, SrcMAC: normalizeMAC(srcMAC), DstMAC: normalizeMAC(dstMAC), Version: tlsVersionString(binary.BigEndian.Uint16(payload[1:3]))}
	switch payload[5] {
	case 2:
		bodyLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
		if 9+bodyLen <= len(payload) && bodyLen >= 38 {
			body := payload[9 : 9+bodyLen]
			ev.Version = tlsVersionString(binary.BigEndian.Uint16(body[0:2]))
			offset := 34
			sessionLen := int(body[offset])
			offset++
			if offset+sessionLen+2 <= len(body) {
				offset += sessionLen
				ev.Cipher = strconv.Itoa(int(binary.BigEndian.Uint16(body[offset : offset+2])))
			}
		}
	case 11:
		ev.CertSubject, ev.CertIssuer = parseTLSCertificate(payload)
	}
	return ev
}

func parseQUIC(payload []byte, ts time.Time, srcIP, dstIP, srcMAC, dstMAC string) (QUICEvent, bool) {
	if !looksLikeQUIC(payload) || len(payload) < 6 {
		return QUICEvent{}, false
	}
	version := binary.BigEndian.Uint32(payload[1:5])
	n := len(payload)
	if n > 48 {
		n = 48
	}
	return QUICEvent{
		Timestamp:       ts,
		SrcIP:           srcIP,
		DstIP:           dstIP,
		SrcMAC:          normalizeMAC(srcMAC),
		DstMAC:          normalizeMAC(dstMAC),
		Version:         fmt.Sprintf("0x%08x", version),
		SNICategory:     "web",
		FingerprintHash: md5Hex(string(payload[:n])),
	}, true
}

func parseTLSSNI(data []byte) string {
	if len(data) < 5 || len(data) < 5+int(binary.BigEndian.Uint16(data[3:5])) {
		return ""
	}
	offset := 5
	for offset+3 <= len(data) {
		nameType := data[offset]
		nameLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3
		if offset+nameLen > len(data) {
			break
		}
		if nameType == 0 {
			return strings.TrimSpace(string(data[offset : offset+nameLen]))
		}
		offset += nameLen
	}
	return ""
}

func parseTLSALPN(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	offset := 2
	protos := []string{}
	for offset < len(data) {
		l := int(data[offset])
		offset++
		if offset+l > len(data) {
			break
		}
		protos = append(protos, string(data[offset:offset+l]))
		offset += l
	}
	return strings.Join(protos, ",")
}

func parseTLSCertificate(payload []byte) (string, string) {
	for i := 0; i+9 < len(payload); i++ {
		if payload[i] != 22 || payload[i+5] != 11 {
			continue
		}
		bodyLen := int(payload[i+6])<<16 | int(payload[i+7])<<8 | int(payload[i+8])
		if i+9+bodyLen > len(payload) || bodyLen < 9 {
			continue
		}
		body := payload[i+9 : i+9+bodyLen]
		certsLen := int(body[3])<<16 | int(body[4])<<8 | int(body[5])
		if 6+certsLen > len(body) || certsLen < 3 {
			continue
		}
		firstLen := int(body[6])<<16 | int(body[7])<<8 | int(body[8])
		if 9+firstLen > len(body) {
			continue
		}
		cert, err := x509.ParseCertificate(body[9 : 9+firstLen])
		if err != nil {
			continue
		}
		subject := strings.TrimSpace(cert.Subject.CommonName)
		if subject == "" {
			subject = strings.TrimSpace(cert.Subject.String())
		}
		issuer := strings.TrimSpace(cert.Issuer.CommonName)
		if issuer == "" {
			issuer = strings.TrimSpace(cert.Issuer.String())
		}
		return subject, issuer
	}
	return "", ""
}

func looksLikeHTTP(payload []byte) bool {
	text := string(payload)
	return strings.HasPrefix(text, "GET ") || strings.HasPrefix(text, "POST ") || strings.HasPrefix(text, "PUT ") || strings.HasPrefix(text, "HEAD ") || strings.HasPrefix(text, "HTTP/1.")
}

func looksLikeTLS(payload []byte) bool {
	return len(payload) > 5 && payload[0] == 22 && payload[1] == 3
}

func looksLikeQUIC(payload []byte) bool {
	return len(payload) > 5 && payload[0]&0x80 != 0 && binary.BigEndian.Uint32(payload[1:5]) != 0
}

func normalizeMAC(mac string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(mac)), "-", ":")
}

func bytesToStringSlice(data []byte) []string {
	out := make([]string, 0, len(data))
	for _, b := range data {
		out = append(out, strconv.Itoa(int(b)))
	}
	return out
}

func dhcpMessageType(v byte) string {
	switch v {
	case 1:
		return "discover"
	case 2:
		return "offer"
	case 3:
		return "request"
	case 5:
		return "ack"
	default:
		return strconv.Itoa(int(v))
	}
}

func dnsTypeString(v layers.DNSType) string {
	switch v {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeTXT:
		return "TXT"
	default:
		return strconv.Itoa(int(v))
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "tls1.0"
	case 0x0302:
		return "tls1.1"
	case 0x0303:
		return "tls1.2"
	case 0x0304:
		return "tls1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func domainCategory(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	switch {
	case name == "":
		return "unknown"
	case strings.Contains(name, "apple") || strings.Contains(name, "icloud") || strings.Contains(name, "mzstatic") || strings.Contains(name, "push.apple"):
		return "apple"
	case strings.Contains(name, "google") || strings.Contains(name, "gvt") || strings.Contains(name, "googleapis"):
		return "google"
	case strings.Contains(name, "microsoft") || strings.Contains(name, "office"):
		return "microsoft"
	case strings.Contains(name, "netflix") || strings.Contains(name, "youtube") || strings.Contains(name, "spotify"):
		return "media"
	case isLocalName(name):
		return "local"
	default:
		return "generic"
	}
}

func isLocalName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".lan") || strings.HasSuffix(name, ".home") || strings.HasSuffix(name, ".arpa")
}

func mdnsServiceFamily(name string) string {
	switch {
	case strings.Contains(name, "_airplay") || strings.Contains(name, "_raop"):
		return "airplay"
	case strings.Contains(name, "_googlecast"):
		return "cast"
	case strings.Contains(name, "_ipp") || strings.Contains(name, "_printer"):
		return "printer"
	case strings.Contains(name, "_hap"):
		return "homekit"
	default:
		return "service"
	}
}

func instanceFromMDNSName(name string) string {
	parts := strings.Split(name, "._")
	if len(parts) > 0 {
		return parts[0]
	}
	return name
}

func isIPv6PrivacyAddress(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To16() == nil || parsed.To4() != nil || parsed.IsLinkLocalUnicast() {
		return false
	}
	b := parsed.To16()
	return b[8]&0x02 == 0
}

func ipv6Behavior(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To16() == nil || parsed.To4() != nil {
		return ""
	}
	switch {
	case parsed.IsLinkLocalUnicast():
		return "link_local"
	case isIPv6PrivacyAddress(ip):
		return "privacy_slaac"
	default:
		return "stable_ipv6"
	}
}

func md5Hex(v string) string {
	sum := md5.Sum([]byte(v))
	return hex.EncodeToString(sum[:])
}

func protocolListFromStringSet(values map[string]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	out := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
