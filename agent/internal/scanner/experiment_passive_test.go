package scanner

import (
	"testing"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/passive"
)

func TestPassiveCorpusReport(t *testing.T) {
	cfg := config.Default()
	corpus := passive.Corpus{
		CapturePoint:         "pcap:test0",
		Interface:            "test0",
		Window:               2 * time.Minute,
		InfraLookback:        15 * time.Minute,
		StartedAt:            time.Date(2026, time.March, 23, 14, 0, 0, 0, time.UTC),
		FinishedAt:           time.Date(2026, time.March, 23, 14, 2, 0, 0, time.UTC),
		HostCaptureEnabled:   true,
		HostCaptureAvailable: true,
		InfraEnabled:         true,
		Resolver: []passive.ResolverEvent{
			{Timestamp: time.Date(2026, time.March, 23, 14, 1, 0, 0, time.UTC), ClientIP: "192.168.4.21", Query: "time.apple.com", QueryType: "A"},
		},
	}

	report := passiveCorpusReport(corpus, cfg)
	if report == nil {
		t.Fatalf("expected passive corpus report")
	}
	if report.Window != "2m0s" || report.InfraLookback != "15m0s" {
		t.Fatalf("unexpected window serialization: %+v", report)
	}
	if len(report.Resolver) != 1 || report.Resolver[0].Query != "time.apple.com" {
		t.Fatalf("unexpected resolver export: %+v", report.Resolver)
	}
}
