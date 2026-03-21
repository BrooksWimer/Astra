package eval

import "math"

func CalibrationECE(predictions []Prediction, bins int) CalibrationCurve {
	if bins <= 0 {
		bins = 10
	}
	curve := CalibrationCurve{
		Bins: make([]CalibrationBin, bins),
	}
	if len(predictions) == 0 {
		return curve
	}

	total := float64(len(predictions))
	correctPerBin := make([]float64, bins)
	confidencePerBin := make([]float64, bins)
	countPerBin := make([]int, bins)
	ece := 0.0

	for i := range curve.Bins {
		curve.Bins[i].Lower = float64(i) / float64(bins)
		curve.Bins[i].Upper = float64(i+1) / float64(bins)
	}

	for _, prediction := range predictions {
		confidence := clamp01(prediction.Confidence)
		bin := int(math.Floor(confidence * float64(bins)))
		if bin >= bins {
			bin = bins - 1
		}
		countPerBin[bin]++
		confidencePerBin[bin] += confidence
		if normalizeEvalLabel(prediction.Actual) != "" && normalizeEvalLabel(prediction.Actual) == normalizeEvalLabel(prediction.Predicted) {
			correctPerBin[bin]++
		}
	}

	for i := range curve.Bins {
		if countPerBin[i] == 0 {
			continue
		}
		count := float64(countPerBin[i])
		accuracy := correctPerBin[i] / count
		meanConfidence := confidencePerBin[i] / count
		gap := math.Abs(accuracy - meanConfidence)
		curve.Bins[i].Count = countPerBin[i]
		curve.Bins[i].Accuracy = accuracy
		curve.Bins[i].MeanConfidence = meanConfidence
		curve.Bins[i].Gap = gap
		ece += (count / total) * gap
	}

	curve.ExpectedCalibrationError = ece
	return curve
}
