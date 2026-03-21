package strategy

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type ipv6ULAPrefixHintsStrategy struct{}

func NewIPv6ULAPrefixHints() Strategy    { return ipv6ULAPrefixHintsStrategy{} }
func NewIPv6UlaPrefixHints() Strategy    { return ipv6ULAPrefixHintsStrategy{} }
func NewIPv6ULAPrefixHint() Strategy     { return ipv6ULAPrefixHintsStrategy{} }

func (s ipv6ULAPrefixHintsStrategy) Name() string { return "ipv6_ula_prefix_hints" }

func (s ipv6ULAPrefixHintsStrategy) Collect(targets []Target, emit ObservationSink) {
	found := false
	for _, target := range targets {
		raw := fmt.Sprint(target)
		ips := extractIPv6Candidates(raw)
		if len(ips) == 0 {
			continue
		}
		for _, ip := range ips {
			if ip == nil || ip.To16() == nil || ip.To4() != nil {
				continue
			}
			found = true
			emitIPv6Hint(s.Name(), ip, emit)
		}
	}
	if !found {
		emit(Observation{Strategy: s.Name(), Key: "not_ipv6", Value: "true"})
	}
}

var ipv6CandidatePattern = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}\b`)

func extractIPv6Candidates(raw string) []net.IP {
	matches := ipv6CandidatePattern.FindAllString(raw, -1)
	out := make([]net.IP, 0, len(matches))
	for _, match := range matches {
		candidate := net.ParseIP(strings.Trim(match, "[](),"))
		if candidate == nil || candidate.To16() == nil {
			continue
		}
		if candidate.To4() != nil {
			continue
		}
		out = append(out, candidate.To16())
	}
	return out
}

func emitIPv6Hint(strategyName string, ip net.IP, emit ObservationSink) {
	normalized := ip.To16()
	if normalized == nil {
		return
	}
	scope := ipv6Scope(normalized)
	isULA := isULAIPv6(normalized)
	iid := normalized[8:]
	hexIID := strings.ToLower(hex.EncodeToString(iid))
	iidStyle := classifyIIDStyle(iid)

	emit(Observation{Strategy: strategyName, Key: "ipv6_scope", Value: scope})
	emit(Observation{Strategy: strategyName, Key: "iid_style", Value: iidStyle})
	emit(Observation{Strategy: strategyName, Key: "iid_hex", Value: hexIID})

	if !isULA {
		emit(Observation{Strategy: strategyName, Key: "ipv6_ula", Value: "false"})
		emit(Observation{Strategy: strategyName, Key: "ula_kind", Value: "non_ula"})
		return
	}

	prefix48 := normalized.Mask(net.CIDRMask(48, 128))
	prefix64 := normalized.Mask(net.CIDRMask(64, 128))
	emit(Observation{Strategy: strategyName, Key: "ipv6_ula", Value: "true"})
	emit(Observation{Strategy: strategyName, Key: "ula_kind", Value: iidStyle})
	emit(Observation{Strategy: strategyName, Key: "ipv6_prefix_48", Value: fmt.Sprintf("%s/48", prefix48.String())})
	emit(Observation{Strategy: strategyName, Key: "ipv6_prefix_64", Value: fmt.Sprintf("%s/64", prefix64.String())})
	emit(Observation{Strategy: strategyName, Key: "ula_prefix", Value: fmt.Sprintf("%s/48", prefix48.String())})
	emit(Observation{Strategy: strategyName, Key: "ula_prefix_64", Value: fmt.Sprintf("%s/64", prefix64.String())})
}

func ipv6Scope(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsMulticast():
		return "multicast"
	case ip.IsLinkLocalUnicast():
		return "link_local"
	case isULAIPv6(ip):
		return "unique_local"
	default:
		return "global_unicast"
	}
}

func isULAIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	return ip[0]&0xfe == 0xfc
}

func classifyIIDStyle(iid []byte) string {
	if len(iid) != 8 {
		return "unknown"
	}
	if allZeroBytes(iid) {
		return "zero"
	}
	if len(iid) >= 8 && iid[3] == 0xff && iid[4] == 0xfe {
		return "eui64"
	}
	if iid[0]&0x02 == 0x02 {
		return "stable_or_privacy"
	}
	if looksEmbeddedIPv4(iid) {
		return "embedded_ipv4"
	}
	return "opaque"
}

func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func looksEmbeddedIPv4(iid []byte) bool {
	if len(iid) != 8 {
		return false
	}
	return iid[0] == 0 && iid[1] == 0 && iid[2] == 0 && iid[3] == 0 && (iid[4] != 0 || iid[5] != 0 || iid[6] != 0 || iid[7] != 0)
}
