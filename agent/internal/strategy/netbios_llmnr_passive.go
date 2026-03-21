package strategy

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type NetbiosLlmnrPassive struct{}

func (s *NetbiosLlmnrPassive) Name() string {
	return "netbios_llmnr_passive"
}

func (s *NetbiosLlmnrPassive) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		netbiosLLMNRPassiveCollectTarget(t, emit)
	}
}

var netbiosRecordPattern = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_.\-]+)\s*<([0-9A-F]{2})>\s+(UNIQUE|GROUP)\s+(.+)$`)
var netbiosMACPattern = regexp.MustCompile(`(?i)MAC Address\s*=\s*([0-9A-F:-]+)`)

func netbiosLLMNRPassiveCollectTarget(target Target, emit ObservationSink) {
	if runtime.GOOS != "windows" {
		emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status", "unsupported", map[string]string{
			"platform":  runtime.GOOS,
			"target_ip": target.IP,
		})
		emitObservation(emit, "netbios_llmnr_passive", target, "netbios_source", "platform", map[string]string{
			"platform": runtime.GOOS,
		})
		return
	}
	if strings.TrimSpace(target.IP) == "" {
		emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status", "no_target_ip", map[string]string{
			"platform": runtime.GOOS,
		})
		return
	}
	out, err := exec.Command("nbtstat", "-A", target.IP).CombinedOutput()
	if err != nil && len(out) == 0 {
		emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status", "no_response", map[string]string{
			"target_ip": target.IP,
			"error":     err.Error(),
		})
		return
	}
	emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status", "observed", map[string]string{
		"target_ip": target.IP,
		"source":    "nbtstat",
	})
	emitObservation(emit, "netbios_llmnr_passive", target, "netbios_source", "nbtstat", map[string]string{
		"target_ip": target.IP,
	})
	text := string(out)
	foundAny := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := netbiosRecordPattern.FindStringSubmatch(line); len(m) == 5 {
			name := strings.TrimSpace(m[1])
			suffix := strings.ToUpper(strings.TrimSpace(m[2]))
			recordType := strings.ToUpper(strings.TrimSpace(m[3]))
			status := strings.TrimSpace(m[4])
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_name", name, map[string]string{
				"suffix":       suffix,
				"record_type":  recordType,
				"status_detail": status,
			})
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_suffix", suffix, map[string]string{
				"name":        name,
				"record_type": recordType,
			})
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_record_type", recordType, map[string]string{
				"name":   name,
				"suffix": suffix,
			})
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_role", netbiosRoleFromSuffix(suffix), map[string]string{
				"name":   name,
				"suffix": suffix,
			})
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status_detail", status, map[string]string{
				"name":        name,
				"suffix":      suffix,
				"record_type": recordType,
			})
			foundAny = true
			continue
		}
		if m := netbiosMACPattern.FindStringSubmatch(line); len(m) == 2 {
			emitObservation(emit, "netbios_llmnr_passive", target, "netbios_mac", strings.TrimSpace(m[1]), map[string]string{
				"target_ip": target.IP,
				"source":    "nbtstat",
			})
			foundAny = true
		}
	}
	if !foundAny {
		emitObservation(emit, "netbios_llmnr_passive", target, "netbios_status", "no_records", map[string]string{
			"target_ip": target.IP,
			"source":    "nbtstat",
		})
	}
}

func netbiosRoleFromSuffix(suffix string) string {
	switch strings.ToUpper(strings.TrimSpace(suffix)) {
	case "00":
		return "workstation"
	case "20":
		return "file_server"
	case "1D":
		return "master_browser"
	case "1B":
		return "domain_master_browser"
	case "03":
		return "messenger"
	case "1C":
		return "domain_controller"
	default:
		return fmt.Sprintf("suffix_%s", strings.ToLower(strings.TrimSpace(suffix)))
	}
}
