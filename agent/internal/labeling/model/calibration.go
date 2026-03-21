package model

import (
	"sort"
	"strings"

	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/store"
)

type Prediction struct {
	Label        string
	Score        float64
	Evidence     []string
	SupportTiers map[string]int
}

type Backend interface {
	Name() string
	Predict(profile evidence.Profile, d store.Device) []Prediction
}

type BackendFunc func(profile evidence.Profile, d store.Device) []Prediction

func (f BackendFunc) Name() string { return "backend_func" }

func (f BackendFunc) Predict(profile evidence.Profile, d store.Device) []Prediction {
	if f == nil {
		return nil
	}
	return f(profile, d)
}

type Point struct {
	Raw        float64
	Calibrated float64
	Weight     float64
}

type Calibrator struct {
	points []Point
}

func NewCalibrator(points ...Point) *Calibrator {
	c := &Calibrator{}
	if len(points) == 0 {
		c.points = defaultCalibrationPoints()
		return c
	}
	c.points = fitIsotonic(points)
	if len(c.points) == 0 {
		c.points = defaultCalibrationPoints()
	}
	return c
}

func DefaultCalibrator() *Calibrator {
	return NewCalibrator()
}

func (c *Calibrator) Fit(points ...Point) {
	if c == nil {
		return
	}
	if len(points) == 0 {
		c.points = defaultCalibrationPoints()
		return
	}
	c.points = fitIsotonic(points)
	if len(c.points) == 0 {
		c.points = defaultCalibrationPoints()
	}
}

func (c *Calibrator) Calibrate(raw float64) float64 {
	if c == nil || len(c.points) == 0 {
		return clamp01(raw)
	}
	raw = clamp01(raw)
	if raw <= c.points[0].Raw {
		return clamp01(c.points[0].Calibrated)
	}
	last := c.points[len(c.points)-1]
	if raw >= last.Raw {
		return clamp01(last.Calibrated)
	}
	for i := 1; i < len(c.points); i++ {
		left := c.points[i-1]
		right := c.points[i]
		if raw > right.Raw {
			continue
		}
		if right.Raw <= left.Raw {
			return clamp01(right.Calibrated)
		}
		t := (raw - left.Raw) / (right.Raw - left.Raw)
		return clamp01(left.Calibrated + t*(right.Calibrated-left.Calibrated))
	}
	return clamp01(raw)
}

func (c *Calibrator) Points() []Point {
	if c == nil || len(c.points) == 0 {
		return nil
	}
	out := make([]Point, len(c.points))
	copy(out, c.points)
	return out
}

func defaultCalibrationPoints() []Point {
	return []Point{
		{Raw: 0.00, Calibrated: 0.01},
		{Raw: 0.10, Calibrated: 0.04},
		{Raw: 0.20, Calibrated: 0.10},
		{Raw: 0.30, Calibrated: 0.20},
		{Raw: 0.45, Calibrated: 0.38},
		{Raw: 0.60, Calibrated: 0.58},
		{Raw: 0.75, Calibrated: 0.74},
		{Raw: 0.90, Calibrated: 0.89},
		{Raw: 1.00, Calibrated: 0.97},
	}
}

func fitIsotonic(points []Point) []Point {
	filtered := make([]Point, 0, len(points))
	for _, p := range points {
		if p.Weight <= 0 {
			p.Weight = 1
		}
		filtered = append(filtered, Point{
			Raw:        clamp01(p.Raw),
			Calibrated: clamp01(p.Calibrated),
			Weight:     p.Weight,
		})
	}
	if len(filtered) == 0 {
		return nil
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Raw != filtered[j].Raw {
			return filtered[i].Raw < filtered[j].Raw
		}
		return filtered[i].Calibrated < filtered[j].Calibrated
	})

	type block struct {
		rawSum   float64
		valueSum float64
		weight   float64
	}

	blocks := make([]block, 0, len(filtered))
	for _, p := range filtered {
		blocks = append(blocks, block{
			rawSum:   p.Raw * p.Weight,
			valueSum: p.Calibrated * p.Weight,
			weight:   p.Weight,
		})
		for len(blocks) >= 2 {
			n := len(blocks)
			prev := blocks[n-2]
			cur := blocks[n-1]
			prevAvg := prev.valueSum / prev.weight
			curAvg := cur.valueSum / cur.weight
			if prevAvg <= curAvg {
				break
			}
			merged := block{
				rawSum:   prev.rawSum + cur.rawSum,
				valueSum: prev.valueSum + cur.valueSum,
				weight:   prev.weight + cur.weight,
			}
			blocks = append(blocks[:n-2], merged)
		}
	}

	out := make([]Point, 0, len(blocks))
	if len(blocks) == 0 {
		return defaultCalibrationPoints()
	}
	for _, b := range blocks {
		out = append(out, Point{
			Raw:        clamp01(b.rawSum / b.weight),
			Calibrated: clamp01(b.valueSum / b.weight),
			Weight:     b.weight,
		})
	}
	for i := 1; i < len(out); i++ {
		if out[i].Calibrated < out[i-1].Calibrated {
			out[i].Calibrated = out[i-1].Calibrated
		}
	}
	return out
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func NormalizeLabel(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "wireless printer", "ipp":
		return "printer"
	case "television", "smart tv":
		return "tv"
	case "speaker", "smart speaker":
		return "iot"
	case "phone", "mobile", "smartphone":
		return "phone"
	default:
		return v
	}
}
