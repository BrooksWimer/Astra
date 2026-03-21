//go:build windows

package arp

import (
	"testing"
)

func TestParseArpAWindows(t *testing.T) {
	input := `Interface: 10.0.0.95 --- 0x12
  Internet Address      Physical Address      Type
  10.0.0.1              00-11-22-33-44-55     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
`
	out, err := parseArpAWindows(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("expected 1 entry (skip broadcast), got %d", len(out))
	}
	if out["10.0.0.1"] != "00:11:22:33:44:55" {
		t.Errorf("10.0.0.1 = %q, want 00:11:22:33:44:55", out["10.0.0.1"])
	}
}
