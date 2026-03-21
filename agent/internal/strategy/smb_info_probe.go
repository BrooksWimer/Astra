package strategy

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type SmbInfoProbe struct{}

func (s *SmbInfoProbe) Name() string { return "smb_info_probe" }

func (s *SmbInfoProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		smbInfoProbeCollectTarget(t, emit)
	}
}

type smbInfoProbeObservation struct {
	key     string
	value   string
	details map[string]string
}

func smbInfoProbeCollectTarget(t Target, emit ObservationSink) {
	for _, port := range []int{445, 139} {
		if !isTCPPortOpen(t.IP, port, strategyProbeTimeout) {
			emitObservation(emit, "smb_info_probe", t, "smb_status", "closed", map[string]string{"port": strconv.Itoa(port)})
			continue
		}

		obs, err := smbInfoProbeNegotiate(t.IP, port)
		if err != nil {
			emitObservation(emit, "smb_info_probe", t, "smb_status", "no_response", map[string]string{
				"port":  strconv.Itoa(port),
				"error": err.Error(),
			})
			continue
		}

		for _, o := range obs {
			emitObservation(emit, "smb_info_probe", t, o.key, o.value, o.details)
		}
	}
}

func smbInfoProbeNegotiate(host string, port int) ([]smbInfoProbeObservation, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), strategyProbeTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(smbInfoProbeBuildNegotiateRequest(port)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return smbInfoProbeParseResponse(buf[:n], port), nil
}

func smbInfoProbeBuildNegotiateRequest(port int) []byte {
	clientGuid := make([]byte, 16)
	if _, err := rand.Read(clientGuid); err != nil {
		copy(clientGuid, []byte("netwise-smbprobe"))
	}

	body := &bytes.Buffer{}
	body.Write([]byte{0xFE, 'S', 'M', 'B'})
	_ = binary.Write(body, binary.LittleEndian, uint16(64))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = binary.Write(body, binary.LittleEndian, uint64(time.Now().UnixNano()))
	_ = binary.Write(body, binary.LittleEndian, uint64(0))
	body.Write(make([]byte, 16))

	neg := &bytes.Buffer{}
	_ = binary.Write(neg, binary.LittleEndian, uint16(36))
	_ = binary.Write(neg, binary.LittleEndian, uint16(4))
	_ = binary.Write(neg, binary.LittleEndian, uint16(1))
	_ = binary.Write(neg, binary.LittleEndian, uint16(0))
	_ = binary.Write(neg, binary.LittleEndian, uint32(0))
	neg.Write(clientGuid)
	_ = binary.Write(neg, binary.LittleEndian, uint32(0))
	_ = binary.Write(neg, binary.LittleEndian, uint16(0))
	_ = binary.Write(neg, binary.LittleEndian, uint16(0))
	for _, dialect := range []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311} {
		_ = binary.Write(neg, binary.LittleEndian, dialect)
	}

	payload := append(body.Bytes(), neg.Bytes()...)
	if port == 139 {
		framed := make([]byte, 4+len(payload))
		framed[0] = 0x00
		framed[1] = byte(len(payload) >> 16)
		framed[2] = byte(len(payload) >> 8)
		framed[3] = byte(len(payload))
		copy(framed[4:], payload)
		return framed
	}
	return payload
}

func smbInfoProbeParseResponse(resp []byte, port int) []smbInfoProbeObservation {
	trimmed := smbInfoProbeStripNetBIOS(resp)
	obs := []smbInfoProbeObservation{{
		key:   "smb_transport",
		value: smbInfoProbeTransportLabel(port),
		details: map[string]string{
			"port": strconv.Itoa(port),
		},
	}}

	if len(trimmed) < 4 {
		obs = append(obs, smbInfoProbeObservation{key: "smb_status", value: "short_response", details: map[string]string{"port": strconv.Itoa(port)}})
		return obs
	}

	switch {
	case bytes.HasPrefix(trimmed, []byte{0xFE, 'S', 'M', 'B'}):
		obs = append(obs, smbInfoProbeParseSMB2(trimmed)...)
	case bytes.HasPrefix(trimmed, []byte{0xFF, 'S', 'M', 'B'}):
		obs = append(obs,
			smbInfoProbeObservation{key: "smb_protocol", value: "smb1", details: map[string]string{"port": strconv.Itoa(port)}},
			smbInfoProbeObservation{key: "smb_status", value: "legacy_response", details: map[string]string{"port": strconv.Itoa(port)}},
		)
	default:
		obs = append(obs, smbInfoProbeObservation{key: "smb_status", value: "unknown_response", details: map[string]string{
			"port":  strconv.Itoa(port),
			"first4": hex.EncodeToString(trimmed[:4]),
		}})
	}

	obs = append(obs, smbInfoProbeObservation{
		key:   "smb_target_info",
		value: smbInfoProbeSummaryFromObservations(obs),
		details: map[string]string{
			"port": strconv.Itoa(port),
		},
	})
	return obs
}

func smbInfoProbeStripNetBIOS(resp []byte) []byte {
	if len(resp) < 4 {
		return resp
	}
	if resp[0] == 0x00 {
		l := int(resp[1])<<16 | int(resp[2])<<8 | int(resp[3])
		if l > 0 && l <= len(resp)-4 {
			return resp[4 : 4+l]
		}
	}
	return resp
}

func smbInfoProbeParseSMB2(resp []byte) []smbInfoProbeObservation {
	if len(resp) < 128 {
		return []smbInfoProbeObservation{{key: "smb_status", value: "short_smb2_response", details: nil}}
	}

	securityMode := binary.LittleEndian.Uint16(resp[66:68])
	dialect := binary.LittleEndian.Uint16(resp[68:70])
	serverGUID := hex.EncodeToString(resp[72:88])
	capabilities := binary.LittleEndian.Uint32(resp[88:92])
	maxTransact := binary.LittleEndian.Uint32(resp[92:96])
	maxRead := binary.LittleEndian.Uint32(resp[96:100])
	maxWrite := binary.LittleEndian.Uint32(resp[100:104])
	systemTime := binary.LittleEndian.Uint64(resp[104:112])
	startTime := binary.LittleEndian.Uint64(resp[112:120])

	obs := []smbInfoProbeObservation{
		{key: "smb_protocol", value: "smb2", details: nil},
		{key: "smb_dialect", value: smbInfoProbeDialectLabel(dialect), details: map[string]string{"dialect_hex": fmt.Sprintf("0x%04x", dialect)}},
		{key: "smb_signing", value: smbInfoProbeSigningLabel(securityMode), details: map[string]string{"security_mode": fmt.Sprintf("0x%04x", securityMode)}},
		{key: "smb_guid", value: serverGUID, details: nil},
		{key: "smb_capabilities", value: smbInfoProbeCapabilitiesLabel(capabilities), details: map[string]string{"capabilities_hex": fmt.Sprintf("0x%08x", capabilities)}},
		{key: "smb_max_transact", value: strconv.FormatUint(uint64(maxTransact), 10), details: nil},
		{key: "smb_max_read", value: strconv.FormatUint(uint64(maxRead), 10), details: nil},
		{key: "smb_max_write", value: strconv.FormatUint(uint64(maxWrite), 10), details: nil},
		{key: "smb_target_info", value: smbInfoProbeTargetSummary(dialect, securityMode, capabilities, serverGUID), details: nil},
	}

	if ts := smbInfoProbeFileTimeToRFC3339(systemTime); ts != "" {
		obs = append(obs, smbInfoProbeObservation{key: "smb_server_time", value: ts, details: nil})
	}
	if ts := smbInfoProbeFileTimeToRFC3339(startTime); ts != "" {
		obs = append(obs, smbInfoProbeObservation{key: "smb_server_start_time", value: ts, details: nil})
	}
	return obs
}

func smbInfoProbeSummaryFromObservations(obs []smbInfoProbeObservation) string {
	parts := make([]string, 0, len(obs))
	for _, o := range obs {
		if o.key == "smb_target_info" || o.value == "" {
			continue
		}
		parts = append(parts, o.key+"="+o.value)
	}
	return strings.Join(parts, ";")
}

func smbInfoProbeTransportLabel(port int) string {
	if port == 139 {
		return "netbios_session"
	}
	return "direct_tcp"
}

func smbInfoProbeDialectLabel(dialect uint16) string {
	switch dialect {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("0x%04x", dialect)
	}
}

func smbInfoProbeSigningLabel(securityMode uint16) string {
	switch {
	case securityMode&0x02 != 0:
		return "required"
	case securityMode&0x01 != 0:
		return "enabled"
	default:
		return "disabled"
	}
}

func smbInfoProbeCapabilitiesLabel(capabilities uint32) string {
	out := make([]string, 0, 8)
	if capabilities&0x00000001 != 0 {
		out = append(out, "dfs")
	}
	if capabilities&0x00000002 != 0 {
		out = append(out, "leasing")
	}
	if capabilities&0x00000004 != 0 {
		out = append(out, "large_mtu")
	}
	if capabilities&0x00000008 != 0 {
		out = append(out, "multi_channel")
	}
	if capabilities&0x00000010 != 0 {
		out = append(out, "persistent_handles")
	}
	if capabilities&0x00000020 != 0 {
		out = append(out, "directory_leasing")
	}
	if capabilities&0x00000040 != 0 {
		out = append(out, "encryption")
	}
	if capabilities&0x00000080 != 0 {
		out = append(out, "compression")
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

func smbInfoProbeTargetSummary(dialect, securityMode uint16, capabilities uint32, guid string) string {
	return strings.Join([]string{
		"dialect=" + smbInfoProbeDialectLabel(dialect),
		"signing=" + smbInfoProbeSigningLabel(securityMode),
		"capabilities=" + smbInfoProbeCapabilitiesLabel(capabilities),
		"guid=" + guid,
	}, ";")
}

func smbInfoProbeFileTimeToRFC3339(filetime uint64) string {
	if filetime == 0 {
		return ""
	}
	const windowsToUnix = 116444736000000000
	if filetime < windowsToUnix {
		return ""
	}
	unix100ns := int64(filetime - windowsToUnix)
	sec := unix100ns / 10000000
	nsec := (unix100ns % 10000000) * 100
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339)
}

