package strategy

import "sort"

type OperatorCatalog struct {
	Profiles   []OperatorProfile  `json:"profiles"`
	Strategies []OperatorStrategy `json:"strategies"`
}

type OperatorProfile struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	StrategyCount int      `json:"strategy_count"`
	StrategyNames []string `json:"strategy_names"`
}

type OperatorStrategy struct {
	Name                string         `json:"name"`
	Purpose             string         `json:"purpose,omitempty"`
	Mode                string         `json:"mode"`
	ExecutionClass      ExecutionClass `json:"execution_class"`
	SpeedCost           SpeedCost      `json:"speed_cost"`
	DiscoveryValue      int            `json:"discovery_value"`
	LabelingValue       int            `json:"labeling_value"`
	DefaultPlacement    StrategyTier   `json:"default_placement"`
	RequiresPrivilege   bool           `json:"requires_privilege,omitempty"`
	SupportsCredentials bool           `json:"supports_credentials,omitempty"`
	LikelyInputs        []string       `json:"likely_inputs,omitempty"`
	LikelyOutputs       []string       `json:"likely_outputs,omitempty"`
	IncludedInProfiles  []string       `json:"included_in_profiles,omitempty"`
}

func BuildOperatorCatalog() OperatorCatalog {
	profiles := buildOperatorProfiles()
	profileMembership := make(map[string][]string, len(StrategyMetadataCatalog()))
	for _, profile := range profiles {
		for _, strategyName := range profile.StrategyNames {
			profileMembership[strategyName] = append(profileMembership[strategyName], profile.Name)
		}
	}

	strategies := make([]OperatorStrategy, 0, len(StrategyMetadataCatalog()))
	for _, metadata := range StrategyMetadataCatalog() {
		audit, ok := StrategyAuditForName(metadata.Name)
		if !ok {
			continue
		}
		strategies = append(strategies, OperatorStrategy{
			Name:                metadata.Name,
			Purpose:             audit.Notes,
			Mode:                metadata.Mode,
			ExecutionClass:      audit.ExecutionClass,
			SpeedCost:           audit.SpeedCost,
			DiscoveryValue:      audit.DiscoveryValue,
			LabelingValue:       audit.LabelingValue,
			DefaultPlacement:    audit.Recommendation,
			RequiresPrivilege:   metadata.RequiresPrivilege,
			SupportsCredentials: metadata.SupportsCredentials,
			LikelyInputs:        append([]string{}, metadata.Transports...),
			LikelyOutputs:       append([]string{}, metadata.ExpectedKeys...),
			IncludedInProfiles:  append([]string{}, profileMembership[metadata.Name]...),
		})
	}
	sort.Slice(strategies, func(i, j int) bool {
		return strategies[i].Name < strategies[j].Name
	})

	return OperatorCatalog{
		Profiles:   profiles,
		Strategies: strategies,
	}
}

func buildOperatorProfiles() []OperatorProfile {
	rawProfiles := StrategyProfiles()
	profilesByName := make(map[string]StrategyProfile, len(rawProfiles))
	for _, profile := range rawProfiles {
		profilesByName[profile.Name] = profile
	}

	orderedNames := []string{"label_core", "fast", "medium", "full"}
	profiles := make([]OperatorProfile, 0, len(rawProfiles))
	seen := make(map[string]struct{}, len(rawProfiles))
	for _, name := range orderedNames {
		profile, ok := profilesByName[name]
		if !ok {
			continue
		}
		profiles = append(profiles, OperatorProfile{
			Name:          profile.Name,
			Description:   profile.Description,
			StrategyCount: len(profile.StrategyNames),
			StrategyNames: append([]string{}, profile.StrategyNames...),
		})
		seen[name] = struct{}{}
	}

	remaining := make([]string, 0, len(rawProfiles))
	for _, profile := range rawProfiles {
		if _, ok := seen[profile.Name]; ok {
			continue
		}
		remaining = append(remaining, profile.Name)
	}
	sort.Strings(remaining)
	for _, name := range remaining {
		profile := profilesByName[name]
		profiles = append(profiles, OperatorProfile{
			Name:          profile.Name,
			Description:   profile.Description,
			StrategyCount: len(profile.StrategyNames),
			StrategyNames: append([]string{}, profile.StrategyNames...),
		})
	}
	return profiles
}
