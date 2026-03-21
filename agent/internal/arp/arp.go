package arp

import (
	"context"
	"net"
)

// Table returns IP -> MAC from the system ARP table.
// Implemented per OS via build tags.
func Table() (map[string]string, error) {
	return readARPTable()
}

// Sweep performs active discovery (e.g. ping sweep on Windows to populate ARP table), then returns the ARP table.
// Implemented per OS; unsupported platforms return the current table (no active sweep).
func Sweep(ctx context.Context, ips []net.IP) (map[string]string, error) {
	return sweepImpl(ctx, ips)
}
