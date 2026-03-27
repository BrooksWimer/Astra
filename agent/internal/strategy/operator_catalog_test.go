package strategy

import "testing"

func TestBuildOperatorCatalogIncludesAllStrategies(t *testing.T) {
	catalog := BuildOperatorCatalog()
	if got, want := len(catalog.Strategies), len(StrategyMetadataCatalog()); got != want {
		t.Fatalf("strategy count mismatch: got %d want %d", got, want)
	}
	if got, want := len(catalog.Profiles), 4; got != want {
		t.Fatalf("profile count mismatch: got %d want %d", got, want)
	}
	for _, strategy := range catalog.Strategies {
		if len(strategy.IncludedInProfiles) == 0 {
			t.Fatalf("strategy %q should be included in at least one profile", strategy.Name)
		}
		last := strategy.IncludedInProfiles[len(strategy.IncludedInProfiles)-1]
		if last != "full" {
			t.Fatalf("strategy %q should end with full profile membership, got %v", strategy.Name, strategy.IncludedInProfiles)
		}
	}
}

func TestBuildOperatorCatalogProfileOrderAndCounts(t *testing.T) {
	catalog := BuildOperatorCatalog()
	expected := []struct {
		name  string
		count int
	}{
		{name: "label_core", count: 7},
		{name: "fast", count: 11},
		{name: "medium", count: 42},
		{name: "full", count: len(AllStrategies())},
	}
	for i, want := range expected {
		if catalog.Profiles[i].Name != want.name {
			t.Fatalf("profile %d mismatch: got %q want %q", i, catalog.Profiles[i].Name, want.name)
		}
		if catalog.Profiles[i].StrategyCount != want.count {
			t.Fatalf("profile %q strategy count mismatch: got %d want %d", want.name, catalog.Profiles[i].StrategyCount, want.count)
		}
		if len(catalog.Profiles[i].StrategyNames) != want.count {
			t.Fatalf("profile %q strategy names length mismatch: got %d want %d", want.name, len(catalog.Profiles[i].StrategyNames), want.count)
		}
	}
}
