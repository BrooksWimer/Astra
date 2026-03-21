package ssdp

import (
	"bufio"
	"context"
	"encoding/xml"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	multicastAddr = "239.255.255.250:1900"
	searchTarget  = "ssdp:all"
)

// Entry is a discovered SSDP device: IP and service headers.
type Entry struct {
	IP       string
	ST       string // Search target / service type
	USN      string
	Location string
	Server   string
}

// DeviceDescription is parsed from a LOCATION URL (UPnP device description XML).
type DeviceDescription struct {
	Manufacturer  string
	ModelName     string
	FriendlyName  string
	ModelNumber   string
}

// Discover sends M-SEARCH and collects unicast responses until ctx is done or timeout.
// If bindIP is non-empty, the UDP socket is bound to that address (use primary interface IP on Windows so multicast goes out the right NIC).
func Discover(ctx context.Context, bindIP string, timeout time.Duration) []Entry {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	listenAddr := ":0"
	if bindIP != "" {
		listenAddr = net.JoinHostPort(bindIP, "0")
	}
	conn, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		log.Printf("SSDP: listen on %s: %v", listenAddr, err)
		return nil
	}
	defer conn.Close()

	raddr, err := net.ResolveUDPAddr("udp4", multicastAddr)
	if err != nil {
		log.Printf("SSDP: resolve multicast: %v", err)
		return nil
	}

	req := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + searchTarget + "\r\n\r\n"
	if _, err := conn.WriteTo([]byte(req), raddr); err != nil {
		log.Printf("SSDP: write M-SEARCH: %v", err)
		return nil
	}

	var entries []Entry
	seen := make(map[string]struct{})
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			continue
		}
		ip := ""
		if from != nil {
			ip, _, _ = net.SplitHostPort(from.String())
		}
		st, usn, loc, srv := parseSSDPResponse(string(buf[:n]))
		if ip == "" {
			// Fallback: parse from LOCATION
			u, _ := url.Parse(loc)
			if u != nil && u.Host != "" {
				ip, _, _ = net.SplitHostPort(u.Host)
				if ip == "" {
					ip = u.Host
				}
			}
		}
		if ip == "" {
			continue
		}
		key := ip + "\t" + st + "\t" + usn
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, Entry{IP: ip, ST: st, USN: usn, Location: loc, Server: srv})
		if time.Now().After(deadline) {
			break
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	}
	return entries
}

// upnpRoot and upnpDevice match UPnP device-1-0 schema.
type upnpRoot struct {
	XMLName xml.Name   `xml:"root"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	Manufacturer  string `xml:"manufacturer"`
	ModelName     string `xml:"modelName"`
	FriendlyName  string `xml:"friendlyName"`
	ModelNumber   string `xml:"modelNumber"`
}

// FetchDeviceDescription fetches the LOCATION URL and parses the UPnP device description XML.
// Returns nil if fetch or parse fails. Call with a short timeout (e.g. 3s).
func FetchDeviceDescription(ctx context.Context, locationURL string, timeout time.Duration) *DeviceDescription {
	if locationURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locationURL, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var root upnpRoot
	if err := xml.NewDecoder(resp.Body).Decode(&root); err != nil {
		return nil
	}
	d := &DeviceDescription{
		Manufacturer: strings.TrimSpace(root.Device.Manufacturer),
		ModelName:    strings.TrimSpace(root.Device.ModelName),
		FriendlyName: strings.TrimSpace(root.Device.FriendlyName),
		ModelNumber:  strings.TrimSpace(root.Device.ModelNumber),
	}
	if d.Manufacturer == "" && d.ModelName == "" && d.FriendlyName == "" && d.ModelNumber == "" {
		return nil
	}
	return d
}

func parseSSDPResponse(body string) (st, usn, location, server string) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "location:") {
			location = strings.TrimSpace(line[len("location:"):])
		}
		if strings.HasPrefix(lower, "server:") {
			server = strings.TrimSpace(line[len("server:"):])
		}
		if strings.HasPrefix(lower, "st:") {
			st = strings.TrimSpace(line[len("st:"):])
		}
		if strings.HasPrefix(lower, "usn:") {
			usn = strings.TrimSpace(line[len("usn:"):])
		}
	}
	return st, usn, location, server
}
