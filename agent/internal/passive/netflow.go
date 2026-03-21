package passive

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"time"
)

func (s *Session) captureNetflow(ctx context.Context) {
	done := make(chan struct{}, 2)
	for _, port := range []int{2055, 4739} {
		go func(port int) {
			defer func() { done <- struct{}{} }()
			s.listenNetflow(ctx, port)
		}(port)
	}
	<-done
	<-done
}

func (s *Session) listenNetflow(ctx context.Context, port int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		for _, ev := range parseNetflow(buf[:n], src) {
			s.appendNetflow(ev)
		}
	}
}

func parseNetflow(data []byte, src *net.UDPAddr) []NetflowEvent {
	if len(data) < 2 {
		return nil
	}
	version := int(binary.BigEndian.Uint16(data[0:2]))
	ev := NetflowEvent{
		Timestamp: time.Now().UTC(),
		Version:   version,
	}
	if src != nil {
		ev.ExporterIP = src.IP.String()
	}
	switch version {
	case 5:
		if len(data) >= 24 {
			ev.ObservationDomain = strconv.Itoa(int(data[20])) + ":" + strconv.Itoa(int(data[21]))
		}
		if len(data) >= 72 {
			rec := data[24:72]
			ev.SrcIP = net.IP(rec[0:4]).String()
			ev.DstIP = net.IP(rec[4:8]).String()
			ev.SrcPort = int(binary.BigEndian.Uint16(rec[32:34]))
			ev.DstPort = int(binary.BigEndian.Uint16(rec[34:36]))
			ev.Protocol = strconv.Itoa(int(rec[37]))
		}
	case 9, 10:
		if len(data) >= 16 {
			ev.ObservationDomain = strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[12:16])), 10)
		}
	}
	return []NetflowEvent{ev}
}
