package strategy

import (
	"encoding/base64"
	"os"
	"strings"
)

type CredentialedAPI struct{}

func (s *CredentialedAPI) Name() string {
	return "credentialed_api"
}

func (s *CredentialedAPI) Collect(targets []Target, emit ObservationSink) {
	authHeaders, authMode := credentialHeadersFromEnv()
	paths := []string{"/", "/api", "/api/status", "/api/v1", "/api/info", "/api/system", "/status", "/health"}
	for _, t := range targets {
		if len(authHeaders) == 0 {
			emitObservation(emit, s.Name(), t, "credentialed_api", "unavailable", map[string]string{"reason": "no_credentials_configured"})
			continue
		}
		seen := false
		for _, scheme := range []string{"http", "https"} {
			for _, p := range paths {
				meta := probeHTTPMetadata(t.IP, scheme, p, authHeaders)
				if meta.Status == 0 && meta.Server == "" && meta.ContentType == "" && meta.TitleSHA1 == "" && meta.BodySHA1 == "" {
					continue
				}
				seen = true
				emitHTTPMetadataObservations(emit, s.Name(), t, "credentialed_api", meta)
				emitObservation(emit, s.Name(), t, "credentialed_api_auth_mode", authMode, map[string]string{
					"scheme": scheme,
					"path":   p,
				})
			}
		}
		if !seen {
			emitObservation(emit, s.Name(), t, "credentialed_api", "no_response", map[string]string{"auth_mode": authMode})
		}
	}
}

func credentialHeadersFromEnv() (map[string]string, string) {
	token := strings.TrimSpace(os.Getenv("NETWISE_HTTP_BEARER_TOKEN"))
	if token != "" {
		return map[string]string{"Authorization": "Bearer " + token}, "bearer"
	}
	user := strings.TrimSpace(os.Getenv("NETWISE_HTTP_BASIC_USER"))
	pass := os.Getenv("NETWISE_HTTP_BASIC_PASS")
	if user != "" || pass != "" {
		raw := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		return map[string]string{"Authorization": "Basic " + raw}, "basic"
	}
	return nil, ""
}
