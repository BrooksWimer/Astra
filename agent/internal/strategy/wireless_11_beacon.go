package strategy

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

type Wireless11Beacon struct{}

func (s *Wireless11Beacon) Name() string {
	return "wireless_11_beacon"
}

func (s *Wireless11Beacon) Collect(targets []Target, emit ObservationSink) {
	records, source, status := collectWirelessBeaconRecords(context.Background())
	for _, t := range targets {
		matchedRecords := filterWirelessRecordsForTarget(records, t)
		targetStatus := status
		if len(records) > 0 && len(matchedRecords) == 0 {
			targetStatus = "no_target_match"
		}
		emitObservation(emit, "wireless_11_beacon", t, "wireless_status", targetStatus, map[string]string{
			"source":         source,
			"target_ip":      t.IP,
			"target_hostname": t.Hostname,
		})
		emitObservation(emit, "wireless_11_beacon", t, "wireless_source", source, map[string]string{
			"target_ip":      t.IP,
			"target_hostname": t.Hostname,
		})
		if len(matchedRecords) == 0 {
			emitObservation(emit, "wireless_11_beacon", t, "wireless_record_count", "0", map[string]string{
				"source": source,
			})
			continue
		}
		emitObservation(emit, "wireless_11_beacon", t, "wireless_record_count", strconv.Itoa(len(matchedRecords)), map[string]string{
			"source": source,
		})
		for _, record := range matchedRecords {
			emitObservation(emit, "wireless_11_beacon", t, "wireless_observation_mode", "local_scan", map[string]string{
				"source": record.Source,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_ssid", record.SSID, map[string]string{
				"source": record.Source,
				"bssid":  record.BSSID,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_bssid", record.BSSID, map[string]string{
				"source": record.Source,
				"ssid":   record.SSID,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_signal", record.Signal, map[string]string{
				"source": record.Source,
				"ssid":   record.SSID,
				"bssid":  record.BSSID,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_channel", record.Channel, map[string]string{
				"source": record.Source,
				"ssid":   record.SSID,
				"bssid":  record.BSSID,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_security", record.Security, map[string]string{
				"source": record.Source,
				"ssid":   record.SSID,
				"bssid":  record.BSSID,
			})
			emitObservation(emit, "wireless_11_beacon", t, "wireless_radio", record.Radio, map[string]string{
				"source": record.Source,
				"ssid":   record.SSID,
				"bssid":  record.BSSID,
			})
		}
	}
}

func filterWirelessRecordsForTarget(records []wirelessBeaconRecord, target Target) []wirelessBeaconRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]wirelessBeaconRecord, 0, len(records))
	for _, record := range records {
		if wirelessRecordMatchesTarget(record, target) {
			out = append(out, record)
		}
	}
	return out
}

func wirelessRecordMatchesTarget(record wirelessBeaconRecord, target Target) bool {
	targetMAC := normalizeARPNeighborMAC(target.MAC)
	recordBSSID := normalizeARPNeighborMAC(record.BSSID)
	if targetMAC != "" && recordBSSID != "" && targetMAC == recordBSSID {
		return true
	}
	targetHostname := strings.ToLower(strings.TrimSpace(target.Hostname))
	if targetHostname != "" {
		ssid := strings.ToLower(strings.TrimSpace(record.SSID))
		if ssid != "" && strings.Contains(ssid, targetHostname) {
			return true
		}
	}
	return false
}

type wirelessBeaconRecord struct {
	SSID     string
	BSSID    string
	Signal   string
	Channel  string
	Security string
	Radio    string
	Source   string
}

var airportBSSIDPattern = regexp.MustCompile(`(?i)([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})`)

func collectWirelessBeaconRecords(ctx context.Context) ([]wirelessBeaconRecord, string, string) {
	_ = ctx
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid").CombinedOutput()
		if err != nil && len(out) == 0 {
			return nil, "netsh", "no_signal"
		}
		return parseNetshWireless(string(out)), "netsh", "observed"
	case "darwin":
		out, err := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s").CombinedOutput()
		if err != nil && len(out) == 0 {
			return nil, "airport", "no_signal"
		}
		return parseAirportWireless(string(out)), "airport", "observed"
	default:
		out, err := exec.Command("nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list").CombinedOutput()
		if err != nil && len(out) == 0 {
			return nil, "nmcli", "no_signal"
		}
		return parseNmcliWireless(string(out)), "nmcli", "observed"
	}
}

func parseNetshWireless(text string) []wirelessBeaconRecord {
	var records []wirelessBeaconRecord
	var currentSSID string
	var current *wirelessBeaconRecord
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "ssid ") && strings.Contains(line, " : ") {
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) == 2 {
				currentSSID = strings.TrimSpace(parts[1])
			}
			continue
		}
		if strings.HasPrefix(lower, "bssid ") && strings.Contains(line, " : ") {
			if current != nil {
				records = append(records, *current)
			}
			parts := strings.SplitN(line, " : ", 2)
			current = &wirelessBeaconRecord{SSID: currentSSID, BSSID: strings.TrimSpace(parts[1]), Source: "netsh"}
			continue
		}
		if current == nil {
			continue
		}
		if strings.Contains(lower, "signal") && strings.Contains(line, " : ") {
			current.Signal = strings.TrimSpace(strings.SplitN(line, " : ", 2)[1])
		}
		if strings.Contains(lower, "channel") && strings.Contains(line, " : ") {
			current.Channel = strings.TrimSpace(strings.SplitN(line, " : ", 2)[1])
		}
		if strings.Contains(lower, "authentication") && strings.Contains(line, " : ") {
			current.Security = strings.TrimSpace(strings.SplitN(line, " : ", 2)[1])
		}
		if strings.Contains(lower, "encryption") && strings.Contains(line, " : ") {
			enc := strings.TrimSpace(strings.SplitN(line, " : ", 2)[1])
			if current.Security == "" {
				current.Security = enc
			} else {
				current.Security = current.Security + "; " + enc
			}
		}
		if strings.Contains(lower, "radio type") && strings.Contains(line, " : ") {
			current.Radio = strings.TrimSpace(strings.SplitN(line, " : ", 2)[1])
		}
	}
	if current != nil {
		records = append(records, *current)
	}
	return records
}

func parseNmcliWireless(text string) []wirelessBeaconRecord {
	var records []wirelessBeaconRecord
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}
		records = append(records, wirelessBeaconRecord{
			SSID:     strings.TrimSpace(parts[0]),
			BSSID:    strings.TrimSpace(parts[1]),
			Channel:  strings.TrimSpace(parts[2]),
			Signal:   strings.TrimSpace(parts[3]),
			Security: strings.Join(parts[4:], ":"),
			Source:   "nmcli",
		})
	}
	return records
}

func parseAirportWireless(text string) []wirelessBeaconRecord {
	var records []wirelessBeaconRecord
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "SSID") {
			continue
		}
		match := airportBSSIDPattern.FindString(line)
		if match == "" {
			continue
		}
		lower := strings.ToLower(line)
		idx := strings.Index(lower, strings.ToLower(match))
		if idx < 0 {
			continue
		}
		ssid := strings.TrimSpace(line[:idx])
		rest := strings.Fields(strings.TrimSpace(line[idx+len(match):]))
		signal := ""
		channel := ""
		security := "airport"
		if len(rest) > 0 {
			signal = rest[0]
		}
		if len(rest) > 1 {
			channel = rest[1]
		}
		if len(rest) > 4 {
			security = strings.Join(rest[4:], " ")
		} else if len(rest) > 2 {
			security = strings.Join(rest[2:], " ")
		}
		records = append(records, wirelessBeaconRecord{SSID: ssid, BSSID: match, Signal: signal, Channel: channel, Security: security, Source: "airport"})
	}
	return records
}
