//go:build darwin

package arp

import (
	"testing"
)

func TestParseArpAnOutputDarwin(t *testing.T) {
	input := `? (10.0.0.1) at aa:bb:cc:dd:ee:ff
? (10.0.0.2) at 11:22:33:44:55:66
? (192.168.1.1) at ff:ff:ff:ff:ff:ff
`
	out, err := parseArpAnOutput(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 entries (skip broadcast), got %d", len(out))
	}
	if out["10.0.0.1"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("10.0.0.1 = %q", out["10.0.0.1"])
	}
	if out["10.0.0.2"] != "11:22:33:44:55:66" {
		t.Errorf("10.0.0.2 = %q", out["10.0.0.2"])
	}
}
