package passive

import (
	"testing"
	"time"
)

func TestParseResolverLineFormats(t *testing.T) {
	fallback := time.Date(2026, time.March, 23, 14, 5, 0, 0, time.UTC)
	tests := []struct {
		name     string
		format   string
		line     string
		clientIP string
		query    string
		qtype    string
	}{
		{
			name:     "adguard",
			format:   "adguard",
			line:     "2026-03-23T14:05:00Z query[A] setup.icloud.com from 192.168.4.23",
			clientIP: "192.168.4.23",
			query:    "setup.icloud.com",
			qtype:    "A",
		},
		{
			name:     "pihole",
			format:   "pihole_ftl",
			line:     "Mar 23 14:05:00 dnsmasq[123]: query[AAAA] mesh.local from 192.168.4.5",
			clientIP: "192.168.4.5",
			query:    "mesh.local",
			qtype:    "AAAA",
		},
		{
			name:     "bind",
			format:   "bind_query",
			line:     "2026-03-23T14:05:00Z client 192.168.4.44#53211 (printer.local): query: printer.local IN PTR +",
			clientIP: "192.168.4.44",
			query:    "printer.local",
			qtype:    "PTR",
		},
		{
			name:     "generic",
			format:   "generic",
			line:     "2026-03-23 14:05:00 client=192.168.4.99 query=time.apple.com type=A",
			clientIP: "192.168.4.99",
			query:    "time.apple.com",
			qtype:    "A",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, _, ok := parseResolverLine(tc.line, tc.format, fallback)
			if !ok {
				t.Fatalf("expected resolver line to parse")
			}
			if ev.ClientIP != tc.clientIP {
				t.Fatalf("client ip mismatch: got %q want %q", ev.ClientIP, tc.clientIP)
			}
			if ev.Query != tc.query {
				t.Fatalf("query mismatch: got %q want %q", ev.Query, tc.query)
			}
			if ev.QueryType != tc.qtype {
				t.Fatalf("query type mismatch: got %q want %q", ev.QueryType, tc.qtype)
			}
		})
	}
}

func TestParseSessionLineFormats(t *testing.T) {
	fallback := time.Date(2026, time.March, 23, 14, 5, 0, 0, time.UTC)

	conntrack, _, ok := parseSessionLine("tcp 6 431999 ESTABLISHED src=192.168.4.21 dst=17.253.144.10 sport=55734 dport=443 [ASSURED]", "conntrack", fallback)
	if !ok {
		t.Fatalf("expected conntrack line to parse")
	}
	if conntrack.ClientIP != "192.168.4.21" || conntrack.ProtocolMix != "tcp" || conntrack.SessionCount != 1 {
		t.Fatalf("unexpected conntrack parse: %+v", conntrack)
	}

	generic, _, ok := parseSessionLine("2026-03-23 14:05:00 client=192.168.4.8 sessions=12 long_lived=3 remote=apple burst=steady proto=tcp", "generic", fallback)
	if !ok {
		t.Fatalf("expected generic session line to parse")
	}
	if generic.ClientIP != "192.168.4.8" || generic.SessionCount != 12 || generic.LongLivedCount != 3 {
		t.Fatalf("unexpected generic session parse: %+v", generic)
	}
}

func TestParseWiFiLineFormats(t *testing.T) {
	fallback := time.Date(2026, time.March, 23, 14, 5, 0, 0, time.UTC)

	hostapd, _, ok := parseWiFiLine("Mar 23 14:05:00 hostapd: wlan0: STA AA:BB:CC:DD:EE:FF IEEE 802.11: associated", "hostapd", fallback)
	if !ok {
		t.Fatalf("expected hostapd line to parse")
	}
	if hostapd.ClientMAC != "aa:bb:cc:dd:ee:ff" || hostapd.State != "associated" {
		t.Fatalf("unexpected hostapd parse: %+v", hostapd)
	}

	unifi, _, ok := parseWiFiLine("2026-03-23 14:05:00 unifi EVT_AP_ClientConnected client aa:bb:cc:dd:ee:11 rssi=-54 channel=36 5GHz host=iPhone", "unifi_syslog", fallback)
	if !ok {
		t.Fatalf("expected unifi line to parse")
	}
	if unifi.ClientMAC != "aa:bb:cc:dd:ee:11" || unifi.RSSI != "-54" || unifi.Channel != "36" {
		t.Fatalf("unexpected unifi parse: %+v", unifi)
	}
}

func TestParseRadiusLineFormats(t *testing.T) {
	fallback := time.Date(2026, time.March, 23, 14, 5, 0, 0, time.UTC)

	freeradius, _, ok := parseRadiusLine("2026-03-23T14:05:00Z freeradius: Login OK: [alice@example.com] (from client ap1 port 0 cli aa:bb:cc:dd:ee:ff)", "freeradius", fallback)
	if !ok {
		t.Fatalf("expected freeradius line to parse")
	}
	if freeradius.Identity != "alice@example.com" || freeradius.Realm != "example.com" || freeradius.AuthResult != "accept" {
		t.Fatalf("unexpected freeradius parse: %+v", freeradius)
	}

	generic, _, ok := parseRadiusLine("radius auth success identity=bob@corp.local mac=aa:bb:cc:dd:ee:11 vlan=20 role=staff eap=peap", "generic", fallback)
	if !ok {
		t.Fatalf("expected generic radius line to parse")
	}
	if generic.Identity != "bob@corp.local" || generic.VLAN != "20" || generic.Role != "staff" {
		t.Fatalf("unexpected generic radius parse: %+v", generic)
	}
}
