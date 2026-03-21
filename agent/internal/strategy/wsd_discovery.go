package strategy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
	"time"
)

type WsdDiscovery struct{}

func (s *WsdDiscovery) Name() string { return "wsd_discovery" }

func (s *WsdDiscovery) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		wsdDiscoveryCollectTarget(t, emit)
	}
}

type wsdDiscoveryMatch struct {
	Address         string `xml:"EndpointReference>Address"`
	Types           string `xml:"Types"`
	Scopes          string `xml:"Scopes"`
	XAddrs          string `xml:"XAddrs"`
	MetadataVersion string `xml:"MetadataVersion"`
}

type wsdDiscoveryEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ProbeMatches struct {
			Matches []wsdDiscoveryMatch `xml:"ProbeMatch"`
		} `xml:"ProbeMatches"`
	} `xml:"Body"`
}

func wsdDiscoveryCollectTarget(t Target, emit ObservationSink) {
	resp, err := wsdDiscoveryProbe(t.IP)
	if err != nil {
		emitObservation(emit, "wsd_discovery", t, "wsd_status", "no_response", map[string]string{"error": err.Error()})
		return
	}

	matches, err := wsdDiscoveryParse(resp)
	if err != nil {
		emitObservation(emit, "wsd_discovery", t, "wsd_status", "unparsed", map[string]string{"error": err.Error()})
		return
	}
	if len(matches) == 0 {
		emitObservation(emit, "wsd_discovery", t, "wsd_status", "empty", nil)
		return
	}

	for _, match := range matches {
		details := map[string]string{}
		if match.Address != "" {
			details["endpoint_reference"] = match.Address
			emitObservation(emit, "wsd_discovery", t, "wsd_uuid", wsdDiscoveryNormalizeUUID(match.Address), details)
		}
		if match.Types != "" {
			emitObservation(emit, "wsd_discovery", t, "wsd_type", strings.TrimSpace(match.Types), details)
		}
		if match.Scopes != "" {
			emitObservation(emit, "wsd_discovery", t, "wsd_scope", strings.TrimSpace(match.Scopes), details)
		}
		if match.XAddrs != "" {
			emitObservation(emit, "wsd_discovery", t, "wsd_xaddr", strings.TrimSpace(match.XAddrs), details)
		}
		if match.MetadataVersion != "" {
			emitObservation(emit, "wsd_discovery", t, "wsd_metadata_version", strings.TrimSpace(match.MetadataVersion), details)
		}
		emitObservation(emit, "wsd_discovery", t, "wsd_status", "real_data", details)
	}
}

func wsdDiscoveryProbe(host string) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "3702"), strategyProbeTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(strategyProbeTimeout)); err != nil {
		return nil, err
	}

	msgID := wsdDiscoveryMessageID()
	req := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <e:Header>
    <w:MessageID>%s</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04/discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe/>
  </e:Body>
</e:Envelope>`, msgID)

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func wsdDiscoveryParse(resp []byte) ([]wsdDiscoveryMatch, error) {
	trimmed := bytes.TrimSpace(resp)
	var env wsdDiscoveryEnvelope
	if err := xml.Unmarshal(trimmed, &env); err == nil {
		if len(env.Body.ProbeMatches.Matches) > 0 {
			return env.Body.ProbeMatches.Matches, nil
		}
	}

	body := string(trimmed)
	if !strings.Contains(body, "ProbeMatch") {
		return nil, nil
	}

	matches := []wsdDiscoveryMatch{}
	for _, block := range strings.Split(body, "<d:ProbeMatch>") {
		if !strings.Contains(block, "</d:ProbeMatch>") {
			continue
		}
		m := wsdDiscoveryMatch{
			Address:         wsdDiscoveryTagValue(block, "Address"),
			Types:           wsdDiscoveryTagValue(block, "Types"),
			Scopes:          wsdDiscoveryTagValue(block, "Scopes"),
			XAddrs:          wsdDiscoveryTagValue(block, "XAddrs"),
			MetadataVersion: wsdDiscoveryTagValue(block, "MetadataVersion"),
		}
		matches = append(matches, m)
	}
	return matches, nil
}

func wsdDiscoveryTagValue(block, tag string) string {
	startTags := []string{"<" + tag + ">", "<d:" + tag + ">", "<a:" + tag + ">"}
	endTags := []string{"</" + tag + ">", "</d:" + tag + ">", "</a:" + tag + ">"}
	for i := range startTags {
		start := strings.Index(block, startTags[i])
		if start < 0 {
			continue
		}
		start += len(startTags[i])
		end := strings.Index(block[start:], endTags[i])
		if end < 0 {
			continue
		}
		return strings.TrimSpace(block[start : start+end])
	}
	return ""
}

func wsdDiscoveryMessageID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("uuid:%d", time.Now().UnixNano())
	}
	return "uuid:" + hex.EncodeToString(raw[:])
}

func wsdDiscoveryNormalizeUUID(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "urn:uuid:")
	v = strings.TrimPrefix(v, "uuid:")
	return strings.ToLower(v)
}
