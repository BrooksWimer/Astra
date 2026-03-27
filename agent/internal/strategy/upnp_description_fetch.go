package strategy

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type UpnpDescriptionFetch struct{}

func (s *UpnpDescriptionFetch) Name() string {
	return "upnp_description_fetch"
}

func (s *UpnpDescriptionFetch) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		upnpDescriptionFetchCollectTarget(t, emit)
	}
}

type upnpRoot struct {
	Device upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType      string        `xml:"deviceType"`
	FriendlyName    string        `xml:"friendlyName"`
	Manufacturer    string        `xml:"manufacturer"`
	ModelName       string        `xml:"modelName"`
	ModelNumber     string        `xml:"modelNumber"`
	SerialNumber    string        `xml:"serialNumber"`
	UDN             string        `xml:"UDN"`
	PresentationURL string        `xml:"presentationURL"`
	ServiceList     []upnpService `xml:"serviceList>service"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ServiceID   string `xml:"serviceId"`
	ControlURL  string `xml:"controlURL"`
	EventSubURL string `xml:"eventSubURL"`
	SCPDURL     string `xml:"SCPDURL"`
}

func upnpDescriptionFetchCollectTarget(target Target, emit ObservationSink) {
	entries := ssdpEntries()
	if len(entries) == 0 {
		emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "not_seen", map[string]string{
			"target_ip":       target.IP,
			"target_hostname": target.Hostname,
		})
		return
	}
	// Local-device fetches should bypass host proxy settings; otherwise LAN
	// UPnP description requests can be misrouted through unrelated HTTP proxy
	// env vars and fail even when the device is reachable.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
	}
	matchedAny := false
	seenLocations := map[string]struct{}{}
	for _, entry := range entries {
		matched, matchReason, locationHost := ssdpEntryMatchesTarget(entry, target)
		if !matched {
			continue
		}
		matchedAny = true
		if entry.Location == "" {
			emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "no_location", map[string]string{
				"st":           entry.ST,
				"usn":          entry.USN,
				"server":       entry.Server,
				"match_reason": matchReason,
			})
			continue
		}
		if _, seen := seenLocations[entry.Location]; seen {
			continue
		}
		seenLocations[entry.Location] = struct{}{}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, entry.Location, nil)
		if err != nil {
			emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "request_error", map[string]string{
				"location":     entry.Location,
				"error":        err.Error(),
				"match_reason": matchReason,
			})
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "fetch_failed", map[string]string{
				"location":     entry.Location,
				"error":        err.Error(),
				"match_reason": matchReason,
			})
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "read_failed", map[string]string{
				"location":     entry.Location,
				"error":        readErr.Error(),
				"match_reason": matchReason,
			})
			continue
		}
		root := upnpRoot{}
		if err := xml.Unmarshal(bytes.TrimSpace(body), &root); err != nil {
			emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "parse_failed", map[string]string{
				"location":      entry.Location,
				"error":         err.Error(),
				"http_status":   resp.Status,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
			continue
		}
		base, _ := url.Parse(entry.Location)
		device := root.Device
		emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "observed", map[string]string{
			"location":      entry.Location,
			"http_status":   resp.Status,
			"st":            entry.ST,
			"usn":           entry.USN,
			"match_reason":  matchReason,
			"location_host": locationHost,
		})
		emitObservation(emit, "upnp_description_fetch", target, "upnp_location", entry.Location, map[string]string{
			"st":            entry.ST,
			"usn":           entry.USN,
			"server":        entry.Server,
			"match_reason":  matchReason,
			"location_host": locationHost,
		})
		deviceDetails := map[string]string{
			"location":      entry.Location,
			"match_reason":  matchReason,
			"location_host": locationHost,
		}
		emitObservation(emit, "upnp_description_fetch", target, "upnp_device_type", strings.TrimSpace(device.DeviceType), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_friendly_name", strings.TrimSpace(device.FriendlyName), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_manufacturer", strings.TrimSpace(device.Manufacturer), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_model_name", strings.TrimSpace(device.ModelName), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_model_number", strings.TrimSpace(device.ModelNumber), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_serial_number", strings.TrimSpace(device.SerialNumber), deviceDetails)
		emitObservation(emit, "upnp_description_fetch", target, "upnp_udn", strings.TrimSpace(device.UDN), deviceDetails)
		if strings.TrimSpace(device.PresentationURL) != "" {
			presentation := device.PresentationURL
			if base != nil {
				if resolved, err := base.Parse(device.PresentationURL); err == nil {
					presentation = resolved.String()
				}
			}
			emitObservation(emit, "upnp_description_fetch", target, "upnp_presentation_url", presentation, deviceDetails)
		}
		for _, service := range device.ServiceList {
			serviceControl := resolveUPnPRelative(base, service.ControlURL)
			serviceEvent := resolveUPnPRelative(base, service.EventSubURL)
			serviceSCPD := resolveUPnPRelative(base, service.SCPDURL)
			emitObservation(emit, "upnp_description_fetch", target, "upnp_service_type", strings.TrimSpace(service.ServiceType), map[string]string{
				"location":      entry.Location,
				"service_id":    service.ServiceID,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
			emitObservation(emit, "upnp_description_fetch", target, "upnp_service_id", strings.TrimSpace(service.ServiceID), map[string]string{
				"location":      entry.Location,
				"service_type":  service.ServiceType,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
			emitObservation(emit, "upnp_description_fetch", target, "upnp_service_control_url", serviceControl, map[string]string{
				"location":      entry.Location,
				"service_id":    service.ServiceID,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
			emitObservation(emit, "upnp_description_fetch", target, "upnp_service_event_url", serviceEvent, map[string]string{
				"location":      entry.Location,
				"service_id":    service.ServiceID,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
			emitObservation(emit, "upnp_description_fetch", target, "upnp_service_scpd_url", serviceSCPD, map[string]string{
				"location":      entry.Location,
				"service_id":    service.ServiceID,
				"match_reason":  matchReason,
				"location_host": locationHost,
			})
		}
	}
	if !matchedAny {
		emitObservation(emit, "upnp_description_fetch", target, "upnp_status", "not_seen", map[string]string{
			"target_ip":       target.IP,
			"target_hostname": target.Hostname,
		})
	}
}

func resolveUPnPRelative(base *url.URL, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if base == nil {
		return value
	}
	resolved, err := base.Parse(value)
	if err != nil {
		return value
	}
	return resolved.String()
}
