package strategy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type SmbNbnsActive struct{}

func (s *SmbNbnsActive) Name() string { return "smb_nbns_active" }

func (s *SmbNbnsActive) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		smbNbnsActiveCollectTarget(t, emit)
	}
}

func smbNbnsActiveCollectTarget(t Target, emit ObservationSink) {
	names := []string{"*"}
	if host := strings.TrimSpace(t.Hostname); host != "" {
		names = append([]string{host}, names...)
	}

	for _, name := range names {
		resp, err := smbNbnsActiveQuery(t.IP, name)
		if err != nil {
			emitObservation(emit, "smb_nbns_active", t, "nbns_status", "no_response", map[string]string{
				"query_name": name,
				"error":      err.Error(),
			})
			continue
		}

		parsed := smbNbnsActiveParseResponse(resp, name)
		if len(parsed) == 0 {
			emitObservation(emit, "smb_nbns_active", t, "nbns_status", "unparsed", map[string]string{"query_name": name})
			continue
		}
		for _, o := range parsed {
			emitObservation(emit, "smb_nbns_active", t, o.key, o.value, o.details)
		}
	}
}

type smbNbnsObservation struct {
	key     string
	value   string
	details map[string]string
}

func smbNbnsActiveQuery(host, name string) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "137"), strategyProbeTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		return nil, err
	}

	packet := smbNbnsActiveBuildNodeStatusQuery(name)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func smbNbnsActiveBuildNodeStatusQuery(name string) []byte {
	qname := smbNbnsEncodeName(name, 0x00)
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(packet[2:4], 0x0000)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, qname...)
	packet = append(packet, 0x00, 0x21, 0x00, 0x01)
	return packet
}

func smbNbnsEncodeName(name string, suffix byte) []byte {
	label := strings.ToUpper(strings.TrimSpace(name))
	if label == "" || label == "*" {
		label = "*"
	}
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = ' '
	}
	copy(raw, []byte(label))
	if len(label) > 15 {
		copy(raw, []byte(label[:15]))
	}
	raw[15] = suffix

	encoded := make([]byte, 0, 34)
	encoded = append(encoded, 32)
	for _, b := range raw {
		encoded = append(encoded, 'A'+((b>>4)&0x0F), 'A'+(b&0x0F))
	}
	encoded = append(encoded, 0x00)
	return encoded
}

func smbNbnsActiveParseResponse(resp []byte, queryName string) []smbNbnsObservation {
	if len(resp) < 57 {
		return nil
	}

	off := 12
	off = smbNbnsSkipName(resp, off)
	if off+4 > len(resp) {
		return nil
	}
	off += 4

	// Answer RR header.
	if off+10 > len(resp) {
		return nil
	}
	off += 2 // name pointer
	rrType := binary.BigEndian.Uint16(resp[off : off+2])
	off += 2
	_ = rrType
	off += 2 // class
	off += 4 // ttl
	rdLength := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2
	if off+rdLength > len(resp) || rdLength < 7 {
		return nil
	}

	count := int(resp[off])
	off++
	out := make([]smbNbnsObservation, 0, count)
	for i := 0; i < count; i++ {
		if off+18 > len(resp) {
			break
		}
		nameBytes := resp[off : off+15]
		off += 15
		suffix := resp[off]
		off++
		flags := binary.BigEndian.Uint16(resp[off : off+2])
		off += 2
		name := strings.TrimSpace(string(bytesTrim(nameBytes)))
		if name == "" {
			name = queryName
		}
		out = append(out,
			smbNbnsObservation{key: "nbns_name", value: name, details: map[string]string{"query_name": queryName}},
			smbNbnsObservation{key: "nbns_suffix", value: fmt.Sprintf("0x%02X", suffix), details: map[string]string{"query_name": queryName}},
			smbNbnsObservation{key: "nbns_group", value: strconv.FormatBool(flags&0x8000 != 0), details: map[string]string{"query_name": queryName}},
			smbNbnsObservation{key: "nbns_role", value: smbNbnsRoleFromFlags(flags), details: map[string]string{"query_name": queryName}},
		)
	}

	if off+6 <= len(resp) {
		mac := strings.ToLower(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", resp[off], resp[off+1], resp[off+2], resp[off+3], resp[off+4], resp[off+5]))
		out = append(out, smbNbnsObservation{key: "nbns_mac", value: mac, details: map[string]string{"query_name": queryName}})
	}

	if len(out) > 0 {
		out = append(out, smbNbnsObservation{key: "nbns_status", value: "real_data", details: map[string]string{"query_name": queryName}})
	}
	return out
}

func smbNbnsSkipName(b []byte, off int) int {
	if off >= len(b) {
		return len(b)
	}
	if b[off] == 0x20 && off+33 < len(b) {
		off += 34
	} else {
		for off < len(b) {
			l := int(b[off])
			off++
			if l == 0 {
				break
			}
			off += l
			if off > len(b) {
				return len(b)
			}
		}
	}
	return off
}

func smbNbnsRoleFromFlags(flags uint16) string {
	switch {
	case flags&0x8000 != 0:
		return "group"
	case flags&0x0400 != 0:
		return "special"
	default:
		return "unique"
	}
}

func bytesTrim(in []byte) []byte {
	start := 0
	end := len(in)
	for start < end && in[start] == ' ' {
		start++
	}
	for end > start && in[end-1] == ' ' {
		end--
	}
	return in[start:end]
}

