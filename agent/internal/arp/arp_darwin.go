//go:build darwin

package arp

import (
	"bufio"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

func readARPTable() (map[string]string, error) {
	data, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	return parseArpAnOutput(string(data))
}

var arpLine = regexp.MustCompile(`\? \(([0-9.]+)\) at ([0-9a-fA-F:]+)`)

func parseArpAnOutput(s string) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		matches := arpLine.FindStringSubmatch(line)
		if len(matches) == 3 {
			ip, mac := matches[1], matches[2]
			if net.ParseIP(ip) != nil && mac != "ff:ff:ff:ff:ff:ff" {
				out[ip] = mac
			}
		}
	}
	return out, sc.Err()
}
