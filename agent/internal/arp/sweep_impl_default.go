//go:build !windows

package arp

import (
	"context"
	"net"
)

func sweepImpl(ctx context.Context, _ []net.IP) (map[string]string, error) {
	return readARPTable()
}
