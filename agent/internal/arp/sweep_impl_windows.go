//go:build windows

package arp

import (
	"context"
	"net"
	"os/exec"
	"sync"
	"time"
)

const sweepConcurrency = 20

// sweepImpl pings each IP to populate the ARP table, then returns the table.
func sweepImpl(ctx context.Context, ips []net.IP) (map[string]string, error) {
	ch := make(chan net.IP, len(ips))
	for _, ip := range ips {
		ch <- ip
	}
	close(ch)
	var wg sync.WaitGroup
	for i := 0; i < sweepConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ch {
				if ctx.Err() != nil {
					return
				}
				_ = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "300", ip.String()).Run()
			}
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	return readARPTable()
}
