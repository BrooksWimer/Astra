//go:build linux

package network

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

func getDefaultGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Skip header
	if !sc.Scan() {
		return ""
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		hex := fields[2]
		if len(hex) != 8 {
			continue
		}
		var a, b, c, d int64
		if _, err := strconv.ParseInt(hex[6:8], 16, 64); err == nil {
			a, _ = strconv.ParseInt(hex[6:8], 16, 64)
			b, _ = strconv.ParseInt(hex[4:6], 16, 64)
			c, _ = strconv.ParseInt(hex[2:4], 16, 64)
			d, _ = strconv.ParseInt(hex[0:2], 16, 64)
		}
		ip := net.IPv4(byte(a), byte(b), byte(c), byte(d))
		if !ip.IsUnspecified() {
			return ip.String()
		}
	}
	return ""
}
