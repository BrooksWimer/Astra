package strategy

type UpnpServiceControl struct{}

func (s *UpnpServiceControl) Name() string {
	return "upnp_service_control"
}

func (s *UpnpServiceControl) Collect(targets []Target, emit ObservationSink) {
	entries := ssdpEntries()
	for _, t := range targets {
		found := false
		for _, e := range entries {
			if e.IP != t.IP || e.Location == "" {
				continue
			}
			desc := fetchUPnPDescription(e.Location)
			if desc == nil {
				continue
			}
			if desc.Manufacturer != "" {
				emitObservation(emit, s.Name(), t, "upnp_manufacturer", desc.Manufacturer, nil)
				found = true
			}
			if desc.ModelName != "" {
				emitObservation(emit, s.Name(), t, "upnp_model", desc.ModelName, nil)
				found = true
			}
			if desc.FriendlyName != "" {
				emitObservation(emit, s.Name(), t, "upnp_friendly", desc.FriendlyName, nil)
				found = true
			}
		}
		if !found {
			emitObservation(emit, s.Name(), t, "upnp", "none", nil)
		}
	}
}
