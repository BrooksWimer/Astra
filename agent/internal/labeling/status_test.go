package labeling

import (
	"testing"

	"github.com/netwise/agent/internal/store"
)

func TestClassifyObservationStatus(t *testing.T) {
	tests := []struct {
		name string
		obs  store.Observation
		want ObservationStatus
	}{
		{
			name: "real data",
			obs:  store.Observation{Strategy: "http_header_probe", Key: "server", Value: "nginx/1.26"},
			want: ObservationStatusRealData,
		},
		{
			name: "no response marker",
			obs:  store.Observation{Strategy: "snmp_system_identity", Key: "snmp_system", Value: "no_response"},
			want: ObservationStatusNoResponse,
		},
		{
			name: "unsupported marker",
			obs:  store.Observation{Strategy: "snmp_system_identity", Key: "status", Value: "unsupported"},
			want: ObservationStatusUnsupported,
		},
		{
			name: "not applicable marker",
			obs:  store.Observation{Strategy: "ipv6_ula_prefix_hints", Key: "status", Value: "n/a"},
			want: ObservationStatusNotApplicable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyObservationStatus(tc.obs); got != tc.want {
				t.Fatalf("ClassifyObservationStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestActionableObservationsFiltersStatusMarkers(t *testing.T) {
	observations := []store.Observation{
		{Strategy: "http_header_probe", Key: "server", Value: "nginx/1.26"},
		{Strategy: "snmp_system_identity", Key: "snmp_system", Value: "no_response"},
		{Strategy: "wsd_discovery", Key: "status", Value: "unsupported"},
	}

	actionable := ActionableObservations(observations)
	if len(actionable) != 1 {
		t.Fatalf("ActionableObservations() len = %d, want 1", len(actionable))
	}
	if actionable[0].Key != "server" {
		t.Fatalf("ActionableObservations() first key = %q, want server", actionable[0].Key)
	}
}
