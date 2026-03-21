package ssdp

import "testing"

func TestParseSSDPResponse(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\n" +
		"ST: ssdp:all\r\n" +
		"USN: uuid:device-1\r\n" +
		"LOCATION: http://192.168.1.25:80/desc.xml\r\n" +
		"SERVER: Linux/5.4 UPnP/1.1 MyDevice/1.0\r\n" +
		"\r\n"

	st, usn, loc, srv := parseSSDPResponse(body)
	if st != "ssdp:all" {
		t.Fatalf("st = %q, want ssdp:all", st)
	}
	if usn != "uuid:device-1" {
		t.Fatalf("usn = %q, want uuid:device-1", usn)
	}
	if loc != "http://192.168.1.25:80/desc.xml" {
		t.Fatalf("location = %q, want http://192.168.1.25:80/desc.xml", loc)
	}
	if srv != "Linux/5.4 UPnP/1.1 MyDevice/1.0" {
		t.Fatalf("server = %q, want Linux/5.4 UPnP/1.1 MyDevice/1.0", srv)
	}
}
