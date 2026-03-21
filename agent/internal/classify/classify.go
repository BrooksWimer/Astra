package classify

import "strings"

// Result is the output of rule-based device classification.
type Result struct {
	DeviceType string   // router, laptop, phone, printer, tv, speaker, camera, iot, unknown
	Confidence float64  // 0..1
	Reasons    []string // facts that led to the classification
}

// Classify returns device_type, confidence, and reasons from combined identity signals.
func Classify(
	vendor,
	hostname string,
	mdnsServices,
	ssdpServices,
	netbiosServices []string,
	portsOpen []int,
	httpServer,
	tlsSubject,
	tlsIssuer,
	tlsSAN,
	sshBanner,
	ssdpServer string,
	macIsLocal bool,
) Result {
	var reasons []string
	score := 0.0
	deviceType := "unknown"
	effectiveVendor := vendor
	if macIsLocal {
		effectiveVendor = "Unknown"
	}

	v := effectiveVendor + " " + hostname

	// Helper to add reason and boost score
	add := func(r string, s float64, dt string) {
		reasons = append(reasons, r)
		score += s
		if deviceType == "unknown" || s > 0.3 {
			deviceType = dt
		}
	}

	// mDNS service type rules (high signal)
	for _, s := range mdnsServices {
		switch {
		case contains(s, "googlecast", "chromecast"):
			add("mDNS: "+s+" (Chromecast/cast device)", 0.9, "tv")
		case contains(s, "airplay", "raop"):
			add("mDNS: "+s+" (AirPlay)", 0.85, "tv")
		case contains(s, "ipp.", "printer", "pdl-datastream"):
			add("mDNS: "+s+" (printer)", 0.9, "printer")
		case contains(s, "hap."):
			add("mDNS: "+s+" (HomeKit)", 0.8, "iot")
		case contains(s, "spotify-connect", "sonos"):
			add("mDNS: "+s+" (speaker)", 0.85, "speaker")
		case contains(s, "roku"):
			add("mDNS: "+s+" (Roku)", 0.9, "tv")
		}
	}

	// SSDP service type rules
	for _, s := range ssdpServices {
		if contains(s, "BasicDevice", "router", "WANDevice") {
			add("SSDP: "+s, 0.7, "router")
		}
		if contains(s, "Printer", "Print", "ipp") {
			add("SSDP: "+s, 0.85, "printer")
		}
		if contains(s, "MediaRenderer", "RenderingControl") {
			add("SSDP: "+s, 0.7, "tv")
		}
	}

	if ssdpServer != "" {
		add("SSDP server header: "+ssdpServer, 0.25, classifyFromString(ssdpServer))
	}

	// NetBIOS names can expose role hints
	for _, s := range netbiosServices {
		switch {
		case contains(s, "printer", "scan"):
			add("NetBIOS: "+s+" (printer)", 0.5, "printer")
		case contains(s, "media", "sonos", "apple-tv", "roku", "chromecast"):
			add("NetBIOS: "+s+" (media)", 0.4, "tv")
		case contains(s, "camera", "nvr", "ipcam"):
			add("NetBIOS: "+s+" (camera)", 0.5, "camera")
		case contains(s, "laptop", "pc", "desktop", "workstation"):
			add("NetBIOS: "+s+" (laptop/workstation)", 0.45, "laptop")
		}
	}

	// Protocol header hints (supports protocol-specific confidence)
	if contains(httpServer, "printer", "ipp", "cups", "laser", "canon", "hp", "epson", "brother") {
		add("HTTP server: "+httpServer, 0.35, "printer")
	}
	if contains(httpServer, "airplay", "chromecast", "plex", "sonos") {
		add("HTTP server: "+httpServer, 0.35, "tv")
	}
	if contains(sshBanner, "OpenSSH") {
		add("SSH banner: "+sshBanner, 0.25, "laptop")
	}
	if contains(tlsIssuer, "Apple", "Roku", "Sonos") {
		add("TLS issuer: "+tlsIssuer, 0.35, "tv")
	}
	if contains(tlsSubject, "camera", "IP Camera", "CCTV", "NVR", "hikvision", "axis") {
		add("TLS subject: "+tlsSubject, 0.45, "camera")
	}
	if contains(tlsSAN, "printer", "ipps") {
		add("TLS SAN: "+tlsSAN, 0.35, "printer")
	}

	// Port-based hints
	for _, p := range portsOpen {
		if p == 631 {
			add("port 631 (IPP) open", 0.8, "printer")
		}
		if p == 554 {
			add("port 554 (RTSP) open", 0.6, "camera")
		}
		if p == 7000 {
			add("port 7000 (AirPlay-style media receiver) open", 0.55, "tv")
		}
		if p == 8008 || p == 8009 {
			add("port 8009 (cast receiver) open", 0.7, "tv")
		}
		if p == 80 {
			add("port 80 (HTTP) open", 0.15, "unknown")
		}
		if p == 443 {
			add("port 443 (HTTPS) open", 0.15, "unknown")
		}
		if p == 3389 {
			add("port 3389 (RDP) open", 0.5, "laptop")
		}
	}

	// Vendor/hostname fallbacks (lower weight)
	if contains(v, "Apple", "iPhone", "iPad") {
		add("vendor/hostname: Apple device", 0.5, "phone")
	}
	if contains(v, "Raspberry", "VMware", "VirtualBox", "QEMU") {
		add("vendor/hostname: "+vendor, 0.6, "iot")
	}
	if contains(v, "router", "gateway", "ubnt", "netgear", "tp-link", "UniFi") {
		add("vendor/hostname: router-like", 0.6, "router")
	}
	if contains(v, "eero", "orbi", "deco", "amplifi", "nest-wifi", "google wifi", "mesh") {
		add("vendor/hostname: mesh-router-like", 0.7, "router")
	}
	if contains(v, "printer", "hp-", "epson", "canon", "Brother") {
		add("vendor/hostname: printer-like", 0.6, "printer")
	}
	if contains(v, "swann", "hikvision", "reolink", "arlo", "wyze", "amcrest", "axis", "ring", "nest cam") {
		add("vendor/hostname: camera-like", 0.7, "camera")
	}
	if contains(v, "tv", "roku", "chromecast", "apple-tv", "Sonos") {
		add("vendor/hostname: media device", 0.5, "tv")
	}
	if contains(v, "ps5", "playstation", "xbox", "nintendo switch", "steam deck", "steamdeck") {
		add("vendor/hostname: console-like device", 0.6, "iot")
	}
	if contains(v, "laptop", "thinkpad", "dell", "lenovo", "macbook") {
		add("vendor/hostname: laptop-like", 0.5, "laptop")
	}
	if contains(v, "t14", "elitebook", "latitude", "xps", "surface", "macbook-pro", "macbook air", "macbook-pro-") {
		add("vendor/hostname: workstation-like", 0.6, "laptop")
	}

	// Normalize confidence to 0..1
	confidence := score
	if confidence > 1 {
		confidence = 1
	}
	if score >= 0.8 {
		confidence = 1
	}
	if confidence < 0.2 && deviceType == "unknown" {
		confidence = 0.2
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no identifying services or vendor")
	}

	return Result{
		DeviceType: deviceType,
		Confidence: confidence,
		Reasons:    reasons,
	}
}

func classifyFromString(s string) string {
	switch {
	case contains(s, "router", "gateway", "wan", "bridge", "gateway"):
		return "router"
	case contains(s, "camera", "nvr", "ipcam", "hikvision", "axis"):
		return "camera"
	case contains(s, "printer", "ipp", "pdl", "jetdirect"):
		return "printer"
	case contains(s, "airplay", "chromecast", "roku", "plex", "sonos", "dlna", "mediarenderer", "renderingcontrol"):
		return "tv"
	default:
		return "unknown"
	}
}

func contains(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(lower, strings.ToLower(x)) {
			return true
		}
	}
	return false
}
