package strategy

type HttpHeaderProbe struct{}

func (s *HttpHeaderProbe) Name() string {
	return "http_header_probe"
}

func (s *HttpHeaderProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		seen := false
		for _, scheme := range []string{"http", "https"} {
			meta := probeHTTPMetadata(t.IP, scheme, "/", nil)
			if meta.Status == 0 && meta.Server == "" && meta.ContentType == "" && meta.TitleSHA1 == "" && meta.BodySHA1 == "" {
				continue
			}
			seen = true
			emitHTTPMetadataObservations(emit, s.Name(), t, "http", meta)
		}
		if !seen {
			emitObservation(emit, s.Name(), t, "http", "no_response", map[string]string{"reason": "no_http_headers"})
		}
	}
}
