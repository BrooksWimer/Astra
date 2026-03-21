package network

import (
	"net"
	"testing"
)

func TestMaskToString(t *testing.T) {
	tests := []struct {
		mask net.IPMask
		want string
	}{
		{net.IPv4Mask(255, 255, 255, 0), "255.255.255.0"},
		{net.IPv4Mask(255, 255, 0, 0), "255.255.0.0"},
		{net.IPv4Mask(255, 0, 0, 0), "255.0.0.0"},
	}
	for _, tt := range tests {
		got := maskToString(tt.mask)
		if got != tt.want {
			t.Errorf("maskToString(%v) = %q, want %q", tt.mask, got, tt.want)
		}
	}
}

func TestBroadcastAddr(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	got := broadcastAddr(ipnet)
	if got != "10.0.0.255" {
		t.Errorf("broadcastAddr(10.0.0.0/24) = %q, want 10.0.0.255", got)
	}
	_, ipnet2, _ := net.ParseCIDR("192.168.1.0/24")
	got2 := broadcastAddr(ipnet2)
	if got2 != "192.168.1.255" {
		t.Errorf("broadcastAddr(192.168.1.0/24) = %q, want 192.168.1.255", got2)
	}
}

func TestEnumerateSubnet(t *testing.T) {
	ips, err := EnumerateSubnet("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// Should get .1 through .254 (254 usable IPs; exclude network and broadcast)
	if len(ips) != 254 {
		t.Errorf("EnumerateSubnet(10.0.0.0/24) len = %d, want 254", len(ips))
	}
	if len(ips) > 0 && ips[0].String() != "10.0.0.1" {
		t.Errorf("first IP = %s, want 10.0.0.1", ips[0])
	}
	if len(ips) > 0 && ips[len(ips)-1].String() != "10.0.0.254" {
		t.Errorf("last IP = %s, want 10.0.0.254", ips[len(ips)-1])
	}
}

func TestEnumerateSubnetSmall(t *testing.T) {
	ips, err := EnumerateSubnet("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	// /30 has 2 usable: .1 and .2
	if len(ips) != 2 {
		t.Errorf("EnumerateSubnet(192.168.1.0/30) len = %d, want 2", len(ips))
	}
}
