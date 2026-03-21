package strategy

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type SnmpSystemIdentity struct{}

type snmpOIDDefinition struct {
	key string
	oid []int
}

var snmpIdentityOIDs = []snmpOIDDefinition{
	{key: "snmp_sysdescr", oid: []int{1, 3, 6, 1, 2, 1, 1, 1, 0}},
	{key: "snmp_sysobjectid", oid: []int{1, 3, 6, 1, 2, 1, 1, 2, 0}},
	{key: "snmp_sysname", oid: []int{1, 3, 6, 1, 2, 1, 1, 5, 0}},
	{key: "snmp_syscontact", oid: []int{1, 3, 6, 1, 2, 1, 1, 4, 0}},
	{key: "snmp_syslocation", oid: []int{1, 3, 6, 1, 2, 1, 1, 6, 0}},
	{key: "snmp_sysuptime", oid: []int{1, 3, 6, 1, 2, 1, 1, 3, 0}},
}

var snmpCommunities = []string{"public", "private", "snmp", "community"}

func (s *SnmpSystemIdentity) Name() string {
	return "snmp_system_identity"
}

func (s *SnmpSystemIdentity) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		hits := 0
		responsive := false
		for _, candidate := range snmpCommunities {
			values := map[string]string{}
			for _, def := range snmpIdentityOIDs {
				value, kind, err := snmpGetValue(t.IP, candidate, def.oid, strategyProbeTimeout)
				if err != nil || value == "" {
					continue
				}
				responsive = true
				hits++
				values[def.key] = value
				emitObservation(emit, s.Name(), t, def.key, value, map[string]string{
					"community": candidate,
					"oid":       snmpOIDString(def.oid),
					"type":      kind,
				})
				if def.key == "snmp_sysobjectid" {
					if enterprise := snmpEnterpriseOID(value); enterprise != "" {
						emitObservation(emit, s.Name(), t, "snmp_enterprise", enterprise, map[string]string{
							"community": candidate,
							"oid":       value,
						})
					}
				}
			}
			if responsive {
				emitObservation(emit, s.Name(), t, "udp_161", "responsive", map[string]string{
					"community": candidate,
				})
				emitObservation(emit, s.Name(), t, "snmp_system", "responsive", map[string]string{
					"community": candidate,
					"oid_hits":  strconv.Itoa(hits),
				})
				if descr, ok := values["snmp_sysdescr"]; ok {
					emitObservation(emit, s.Name(), t, "snmp_vendor_hint", snmpVendorHint(descr, values["snmp_sysobjectid"]), map[string]string{
						"community": candidate,
					})
				}
				break
			}
		}
		if !responsive {
			emitObservation(emit, s.Name(), t, "udp_161", "no_response", map[string]string{
				"reason": "no_snmp_response",
			})
			emitObservation(emit, s.Name(), t, "snmp_system", "unavailable", map[string]string{
				"reason": "no_snmp_response",
			})
			continue
		}
	}
}

func snmpGetValue(ip, community string, oid []int, timeout time.Duration) (string, string, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "161"), timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", "", err
	}

	requestID := int(time.Now().UnixNano() & 0x7fffffff)
	packet := buildSNMPGetPacket(community, oid, requestID)
	if _, err := conn.Write(packet); err != nil {
		return "", "", err
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", err
	}

	return parseSNMPGetResponse(buf[:n], requestID)
}

func buildSNMPGetPacket(community string, oid []int, requestID int) []byte {
	varBind := snmpEncodeTLV(0x30, append(snmpEncodeOID(oid), snmpEncodeTLV(0x05, nil)...))
	varBindList := snmpEncodeTLV(0x30, varBind)
	pdu := snmpEncodeTLV(0xA0, append(append(append(
		snmpEncodeInteger(requestID),
		snmpEncodeInteger(0)...),
		snmpEncodeInteger(0)...),
		varBindList...,
	))
	message := append(append(snmpEncodeInteger(0), snmpEncodeOctetString(community)...), pdu...)
	return snmpEncodeTLV(0x30, message)
}

func parseSNMPGetResponse(packet []byte, requestID int) (string, string, error) {
	idx := 0
	tag, top, err := snmpReadTLV(packet, &idx)
	if err != nil {
		return "", "", err
	}
	if tag != 0x30 {
		return "", "", fmt.Errorf("unexpected snmp top-level tag 0x%02x", tag)
	}

	topIdx := 0
	if _, _, err := snmpReadTLV(top, &topIdx); err != nil {
		return "", "", err
	}
	if _, _, err := snmpReadTLV(top, &topIdx); err != nil {
		return "", "", err
	}

	pduTag, pduValue, err := snmpReadTLV(top, &topIdx)
	if err != nil {
		return "", "", err
	}
	if pduTag != 0xA2 {
		return "", "", fmt.Errorf("unexpected snmp pdu tag 0x%02x", pduTag)
	}

	pduIdx := 0
	_, reqIDValue, err := snmpReadTLV(pduValue, &pduIdx)
	if err != nil {
		return "", "", err
	}
	if snmpDecodeInteger(reqIDValue) != requestID {
		return "", "", fmt.Errorf("unexpected snmp request id")
	}

	_, errStatus, err := snmpReadTLV(pduValue, &pduIdx)
	if err != nil {
		return "", "", err
	}
	if snmpDecodeInteger(errStatus) != 0 {
		return "", "", fmt.Errorf("snmp error status %d", snmpDecodeInteger(errStatus))
	}
	if _, _, err := snmpReadTLV(pduValue, &pduIdx); err != nil {
		return "", "", err
	}

	listTag, listValue, err := snmpReadTLV(pduValue, &pduIdx)
	if err != nil {
		return "", "", err
	}
	if listTag != 0x30 {
		return "", "", fmt.Errorf("unexpected snmp varbind list tag 0x%02x", listTag)
	}

	listIdx := 0
	_, bindValue, err := snmpReadTLV(listValue, &listIdx)
	if err != nil {
		return "", "", err
	}

	bindIdx := 0
	if _, _, err := snmpReadTLV(bindValue, &bindIdx); err != nil {
		return "", "", err
	}
	valueTag, rawValue, err := snmpReadTLV(bindValue, &bindIdx)
	if err != nil {
		return "", "", err
	}

	return snmpFormatValue(valueTag, rawValue)
}

func snmpReadTLV(data []byte, idx *int) (byte, []byte, error) {
	if *idx >= len(data) {
		return 0, nil, fmt.Errorf("snmp truncated tlv")
	}
	tag := data[*idx]
	*idx = *idx + 1
	length, err := snmpReadLength(data, idx)
	if err != nil {
		return 0, nil, err
	}
	if *idx+length > len(data) {
		return 0, nil, fmt.Errorf("snmp tlv length exceeds packet")
	}
	value := data[*idx : *idx+length]
	*idx += length
	return tag, value, nil
}

func snmpReadLength(data []byte, idx *int) (int, error) {
	if *idx >= len(data) {
		return 0, fmt.Errorf("snmp truncated length")
	}
	b := data[*idx]
	*idx = *idx + 1
	if b&0x80 == 0 {
		return int(b), nil
	}
	count := int(b & 0x7f)
	if count == 0 || count > 4 || *idx+count > len(data) {
		return 0, fmt.Errorf("snmp invalid length encoding")
	}
	value := 0
	for i := 0; i < count; i++ {
		value = (value << 8) | int(data[*idx+i])
	}
	*idx += count
	return value, nil
}

func snmpEncodeTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	out = append(out, snmpEncodeLength(len(value))...)
	out = append(out, value...)
	return out
}

func snmpEncodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	tmp := []byte{}
	for value := n; value > 0; value >>= 8 {
		tmp = append([]byte{byte(value & 0xff)}, tmp...)
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func snmpEncodeInteger(v int) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	tmp := []byte{}
	for value := v; value > 0; value >>= 8 {
		tmp = append([]byte{byte(value & 0xff)}, tmp...)
	}
	if tmp[0]&0x80 != 0 {
		tmp = append([]byte{0x00}, tmp...)
	}
	return snmpEncodeTLV(0x02, tmp)
}

func snmpEncodeOctetString(value string) []byte {
	return snmpEncodeTLV(0x04, []byte(value))
}

func snmpEncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return snmpEncodeTLV(0x06, []byte{})
	}
	content := []byte{byte(oid[0]*40 + oid[1])}
	for _, part := range oid[2:] {
		content = append(content, snmpEncodeBase128(part)...)
	}
	return snmpEncodeTLV(0x06, content)
}

func snmpEncodeBase128(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := []byte{}
	for v > 0 {
		out = append([]byte{byte(v & 0x7f)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func snmpDecodeInteger(value []byte) int {
	out := 0
	for _, b := range value {
		out = (out << 8) | int(b)
	}
	return out
}

func snmpFormatValue(tag byte, raw []byte) (string, string, error) {
	switch tag {
	case 0x04:
		return snmpSanitizeValue(string(raw)), "octet_string", nil
	case 0x06:
		return snmpParseOID(raw), "object_identifier", nil
	case 0x02:
		return strconv.Itoa(snmpDecodeInteger(raw)), "integer", nil
	case 0x43:
		return strconv.Itoa(snmpDecodeInteger(raw)), "timeticks", nil
	case 0x40:
		if len(raw) == 4 {
			return net.IP(raw).String(), "ipaddress", nil
		}
		return hex.EncodeToString(raw), "ipaddress", nil
	default:
		return snmpSanitizeValue(hex.EncodeToString(raw)), fmt.Sprintf("tag_0x%02x", tag), nil
	}
}

func snmpParseOID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	parts := []string{
		strconv.Itoa(int(raw[0]) / 40),
		strconv.Itoa(int(raw[0]) % 40),
	}
	value := 0
	for _, b := range raw[1:] {
		value = (value << 7) | int(b&0x7f)
		if b&0x80 == 0 {
			parts = append(parts, strconv.Itoa(value))
			value = 0
		}
	}
	return strings.Join(parts, ".")
}

func snmpOIDString(oid []int) string {
	parts := make([]string, 0, len(oid))
	for _, part := range oid {
		parts = append(parts, strconv.Itoa(part))
	}
	return strings.Join(parts, ".")
}

func snmpEnterpriseOID(oid string) string {
	const prefix = "1.3.6.1.4.1."
	if !strings.HasPrefix(oid, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(oid, prefix)
	if rest == "" {
		return ""
	}
	if idx := strings.IndexByte(rest, '.'); idx >= 0 {
		rest = rest[:idx]
	}
	return rest
}

func snmpSanitizeValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func snmpVendorHint(sysDescr, sysObjectID string) string {
	lower := strings.ToLower(sysDescr + " " + sysObjectID)
	switch {
	case strings.Contains(lower, "eero"):
		return "eero"
	case strings.Contains(lower, "cisco"):
		return "cisco"
	case strings.Contains(lower, "ubiquiti") || strings.Contains(lower, "unifi"):
		return "ubiquiti"
	case strings.Contains(lower, "netgear"):
		return "netgear"
	case strings.Contains(lower, "tp-link") || strings.Contains(lower, "tplink"):
		return "tp-link"
	case strings.Contains(lower, "mikrotik"):
		return "mikrotik"
	case strings.Contains(lower, "hp") || strings.Contains(lower, "hewlett"):
		return "hp"
	case strings.Contains(lower, "brother"):
		return "brother"
	case strings.Contains(lower, "canon"):
		return "canon"
	case strings.Contains(lower, "axis"):
		return "axis"
	case strings.Contains(lower, "hikvision"):
		return "hikvision"
	default:
		return "unknown"
	}
}
