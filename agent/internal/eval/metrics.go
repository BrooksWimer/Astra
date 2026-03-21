package eval

import (
	"math"
	"sort"
	"strings"
)

type Prediction struct {
	Actual     string  `json:"actual"`
	Predicted  string  `json:"predicted"`
	Confidence float64 `json:"confidence"`
}

type MetricTriple struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

type ClassMetrics struct {
	Label          string       `json:"label"`
	Support        int          `json:"support"`
	TruePositives  int          `json:"true_positives"`
	FalsePositives int          `json:"false_positives"`
	FalseNegatives int          `json:"false_negatives"`
	Metrics        MetricTriple `json:"metrics"`
}

type ClassificationMetrics struct {
	Accuracy float64        `json:"accuracy"`
	Macro    MetricTriple   `json:"macro"`
	Weighted MetricTriple   `json:"weighted"`
	PerClass []ClassMetrics `json:"per_class,omitempty"`
}

type ConfusionMatrix struct {
	Labels []string                  `json:"labels"`
	Counts map[string]map[string]int `json:"counts"`
}

type CalibrationBin struct {
	Lower          float64 `json:"lower"`
	Upper          float64 `json:"upper"`
	Count          int     `json:"count"`
	Accuracy       float64 `json:"accuracy"`
	MeanConfidence float64 `json:"mean_confidence"`
	Gap            float64 `json:"gap"`
}

type CalibrationCurve struct {
	Bins                     []CalibrationBin `json:"bins"`
	ExpectedCalibrationError float64          `json:"expected_calibration_error"`
}

func PrecisionRecallF1(actual, predicted []string, positive string) (precision, recall, f1 float64) {
	if len(actual) != len(predicted) || len(actual) == 0 {
		return 0, 0, 0
	}
	positive = normalizeEvalLabel(positive)
	var tp, fp, fn float64
	for i := range actual {
		a := normalizeEvalLabel(actual[i])
		p := normalizeEvalLabel(predicted[i])
		if p == positive && a == positive {
			tp++
		}
		if p == positive && a != positive {
			fp++
		}
		if a == positive && p != positive {
			fn++
		}
	}
	precision = safeDivide(tp, tp+fp)
	recall = safeDivide(tp, tp+fn)
	f1 = harmonicMean(precision, recall)
	return precision, recall, f1
}

func SummarizePredictions(predictions []Prediction) ClassificationMetrics {
	if len(predictions) == 0 {
		return ClassificationMetrics{}
	}

	labelSet := map[string]struct{}{}
	perClass := map[string]*ClassMetrics{}
	var total int
	var correct int

	for _, prediction := range predictions {
		actual := normalizeEvalLabel(prediction.Actual)
		predicted := normalizeEvalLabel(prediction.Predicted)
		if actual == "" && predicted == "" {
			continue
		}
		if actual != "" {
			labelSet[actual] = struct{}{}
		}
		if predicted != "" {
			labelSet[predicted] = struct{}{}
		}
		total++
		if actual == predicted && actual != "" {
			correct++
		}
		if _, ok := perClass[actual]; !ok && actual != "" {
			perClass[actual] = &ClassMetrics{Label: actual}
		}
		if _, ok := perClass[predicted]; !ok && predicted != "" {
			perClass[predicted] = &ClassMetrics{Label: predicted}
		}
		if actual != "" {
			perClass[actual].Support++
		}
		if actual == predicted && actual != "" {
			perClass[actual].TruePositives++
		} else {
			if predicted != "" {
				perClass[predicted].FalsePositives++
			}
			if actual != "" {
				perClass[actual].FalseNegatives++
			}
		}
	}

	labels := sortedLabelSet(labelSet)
	out := make([]ClassMetrics, 0, len(labels))
	var macroPrecision, macroRecall, macroF1 float64
	var weightedPrecision, weightedRecall, weightedF1 float64
	var supportTotal float64
	for _, label := range labels {
		class := perClass[label]
		if class == nil {
			class = &ClassMetrics{Label: label}
		}
		class.Metrics.Precision = safeDivide(float64(class.TruePositives), float64(class.TruePositives+class.FalsePositives))
		class.Metrics.Recall = safeDivide(float64(class.TruePositives), float64(class.TruePositives+class.FalseNegatives))
		class.Metrics.F1 = harmonicMean(class.Metrics.Precision, class.Metrics.Recall)
		out = append(out, *class)
		macroPrecision += class.Metrics.Precision
		macroRecall += class.Metrics.Recall
		macroF1 += class.Metrics.F1
		support := float64(class.Support)
		supportTotal += support
		weightedPrecision += class.Metrics.Precision * support
		weightedRecall += class.Metrics.Recall * support
		weightedF1 += class.Metrics.F1 * support
	}
	if len(labels) > 0 {
		divisor := float64(len(labels))
		macroPrecision /= divisor
		macroRecall /= divisor
		macroF1 /= divisor
	}
	if supportTotal > 0 {
		weightedPrecision /= supportTotal
		weightedRecall /= supportTotal
		weightedF1 /= supportTotal
	}

	return ClassificationMetrics{
		Accuracy: safeDivide(float64(correct), float64(total)),
		Macro: MetricTriple{
			Precision: macroPrecision,
			Recall:    macroRecall,
			F1:        macroF1,
		},
		Weighted: MetricTriple{
			Precision: weightedPrecision,
			Recall:    weightedRecall,
			F1:        weightedF1,
		},
		PerClass: out,
	}
}

func NewConfusionMatrix(predictions []Prediction) ConfusionMatrix {
	matrix := map[string]map[string]int{}
	labels := map[string]struct{}{}
	for _, prediction := range predictions {
		actual := normalizeEvalLabel(prediction.Actual)
		predicted := normalizeEvalLabel(prediction.Predicted)
		if actual == "" && predicted == "" {
			continue
		}
		labels[actual] = struct{}{}
		labels[predicted] = struct{}{}
		if _, ok := matrix[actual]; !ok {
			matrix[actual] = map[string]int{}
		}
		matrix[actual][predicted]++
	}
	return ConfusionMatrix{
		Labels: sortedLabelSet(labels),
		Counts: matrix,
	}
}

func (cm ConfusionMatrix) Count(actual, predicted string) int {
	if cm.Counts == nil {
		return 0
	}
	actual = normalizeEvalLabel(actual)
	predicted = normalizeEvalLabel(predicted)
	if row, ok := cm.Counts[actual]; ok {
		return row[predicted]
	}
	return 0
}

func BrierScore(predictions []Prediction) float64 {
	if len(predictions) == 0 {
		return 0
	}
	var total float64
	for _, prediction := range predictions {
		confidence := clamp01(prediction.Confidence)
		target := 0.0
		if normalizeEvalLabel(prediction.Actual) != "" && normalizeEvalLabel(prediction.Actual) == normalizeEvalLabel(prediction.Predicted) {
			target = 1.0
		}
		diff := confidence - target
		total += diff * diff
	}
	return total / float64(len(predictions))
}

func normalizeEvalLabel(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func harmonicMean(a, b float64) float64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	return 2 * a * b / (a + b)
}

func safeDivide(num, den float64) float64 {
	if den == 0 {
		return 0
	}
	return num / den
}

func clamp01(v float64) float64 {
	return math.Max(0, math.Min(1, v))
}

func sortedLabelSet(set map[string]struct{}) []string {
	labels := make([]string, 0, len(set))
	for label := range set {
		if label == "" {
			continue
		}
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}
