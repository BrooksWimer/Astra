package classify

import "testing"

func TestClassifyPrinter(t *testing.T) {
	r := Classify("HP", "hp-printer", []string{"_ipp._tcp"}, nil, nil, []int{631}, "", "", "", "", "", "", false)
	if r.DeviceType != "printer" {
		t.Errorf("DeviceType = %q, want printer", r.DeviceType)
	}
	if r.Confidence < 0.5 {
		t.Errorf("Confidence = %f, want >= 0.5", r.Confidence)
	}
	if len(r.Reasons) == 0 {
		t.Error("Reasons should not be empty")
	}
}

func TestClassifyChromecast(t *testing.T) {
	r := Classify("Google", "", []string{"_googlecast._tcp"}, nil, nil, nil, "", "", "", "", "", "", false)
	if r.DeviceType != "tv" {
		t.Errorf("DeviceType = %q, want tv", r.DeviceType)
	}
}

func TestClassifyUnknown(t *testing.T) {
	r := Classify("Unknown", "", nil, nil, nil, nil, "", "", "", "", "", "", false)
	if r.DeviceType != "unknown" {
		t.Errorf("DeviceType = %q, want unknown", r.DeviceType)
	}
	if len(r.Reasons) == 0 {
		t.Error("Reasons should explain unknown")
	}
}

func TestClassifyRouterVendor(t *testing.T) {
	r := Classify("Ubiquiti", "ubnt-gateway", nil, nil, nil, nil, "", "", "", "", "", "", false)
	if r.DeviceType != "router" {
		t.Errorf("DeviceType = %q, want router", r.DeviceType)
	}
}

func TestClassifyNetBios(t *testing.T) {
	r := Classify("Unknown", "", nil, nil, []string{"HP-LJ-Desk", "office-printer"}, []int{}, "", "", "", "", "", "", false)
	if r.DeviceType != "printer" {
		t.Errorf("DeviceType = %q, want printer", r.DeviceType)
	}
}

func TestClassifyUsesHTTPServerHint(t *testing.T) {
	r := Classify("Unknown", "office", nil, nil, nil, []int{}, "CUPS/2.4 IPP Printer", "", "", "", "", "", false)
	if r.DeviceType != "printer" {
		t.Errorf("DeviceType = %q, want printer", r.DeviceType)
	}
}

func TestClassifyUsesTLSServerHints(t *testing.T) {
	r := Classify("Unknown", "cam-17", nil, nil, nil, []int{}, "", "CN=IP Camera Unit", "axis.com", "axis.local", "", "", false)
	if r.DeviceType != "camera" {
		t.Errorf("DeviceType = %q, want camera", r.DeviceType)
	}
}

func TestClassifyUsesSSDPServerHint(t *testing.T) {
	r := Classify("Unknown", "", nil, nil, nil, []int{}, "", "", "", "", "", "MediaRenderer/1.0", false)
	if r.DeviceType != "tv" {
		t.Errorf("DeviceType = %q, want tv", r.DeviceType)
	}
}

func TestClassifySuppressesLocallyAdministeredVendor(t *testing.T) {
	r := Classify("Apple", "office-dev", nil, nil, nil, []int{}, "", "", "", "", "", "", true)
	if r.DeviceType != "unknown" {
		t.Errorf("DeviceType = %q, want unknown when MAC is locally administered and no other signals", r.DeviceType)
	}
}
