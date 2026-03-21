//go:build linux

package arp

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func readARPTable() (map[string]string, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNetARP(f)
}

func parseProcNetARP(f *os.File) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return out, nil
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		if mac == "00:00:00:00:00:00" || mac == "0" {
			continue
		}
		if net.ParseIP(ip) != nil {
			out[ip] = mac
		}
	}
	return out, sc.Err()
}
