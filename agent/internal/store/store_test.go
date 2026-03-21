package store

import (
	"testing"
)

func TestMergeStringSlices(t *testing.T) {
	a := []string{"arp", "mdns"}
	b := []string{"tcp_probe", "arp"}
	got := mergeStringSlices(a, b)
	if len(got) != 3 {
		t.Errorf("merge len = %d, want 3", len(got))
	}
	m := make(map[string]bool)
	for _, s := range got {
		m[s] = true
	}
	for _, s := range []string{"arp", "mdns", "tcp_probe"} {
		if !m[s] {
			t.Errorf("missing %q", s)
		}
	}
}
