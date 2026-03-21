//go:build windows

package arp

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

func readARPTable() (map[string]string, error) {
	data, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}
	return parseArpAWindows(string(data))
}

// parseArpAWindows parses "arp -a" output. Format:
//
//	Interface: 10.0.0.95 --- 0x12
//	  Internet Address      Physical Address      Type
//	  10.0.0.1              00-11-22-33-44-55     dynamic
func parseArpAWindows(s string) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ipStr := fields[0]
		macStr := fields[1]
		// Skip header line
		if ipStr == "Internet" || ipStr == "Address" {
			continue
		}
		if net.ParseIP(ipStr) == nil {
			continue
		}
		// Windows uses dashes (00-11-22-33-44-55); normalize to colons
		macStr = strings.ReplaceAll(macStr, "-", ":")
		if macStr == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		out[ipStr] = macStr
	}
	return out, sc.Err()
}
