package eval

import "github.com/netwise/agent/internal/config"

type QualityGateResult struct {
	Passed                   bool     `json:"passed"`
	SampleCount              int      `json:"sample_count"`
	MacroF1                  float64  `json:"macro_f1"`
	ExpectedCalibrationError float64  `json:"expected_calibration_error"`
	Reasons                  []string `json:"reasons,omitempty"`
}

func EvaluateQualityGate(report EvaluationReport, cfg *config.Config) QualityGateResult {
	if cfg == nil {
		cfg = config.Default()
	}
	result := QualityGateResult{
		Passed:                   true,
		SampleCount:              confusionSampleCount(report.Confusion),
		MacroF1:                  report.Metrics.Macro.F1,
		ExpectedCalibrationError: report.Calibration.ExpectedCalibrationError,
	}
	if !cfg.QualityGateEnabled {
		result.Reasons = append(result.Reasons, "quality gate disabled")
		return result
	}
	if result.SampleCount < cfg.QualityGateMinDevices {
		result.Passed = false
		result.Reasons = append(result.Reasons, "insufficient_ground_truth_samples")
	}
	if result.MacroF1 < cfg.QualityGateMinMacroF1 {
		result.Passed = false
		result.Reasons = append(result.Reasons, "macro_f1_below_threshold")
	}
	if result.ExpectedCalibrationError > cfg.QualityGateMaxECE {
		result.Passed = false
		result.Reasons = append(result.Reasons, "ece_above_threshold")
	}
	return result
}

func confusionSampleCount(confusion ConfusionMatrix) int {
	total := 0
	for _, row := range confusion.Counts {
		for _, count := range row {
			total += count
		}
	}
	return total
}
