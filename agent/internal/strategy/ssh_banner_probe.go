package strategy

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
)

type SshBannerProbe struct{}

var sshBannerRegex = regexp.MustCompile(`^SSH-([0-9.]+)-([^\s]+)(?:\s+(.*))?$`)

func (s *SshBannerProbe) Name() string {
	return "ssh_banner_probe"
}

func (s *SshBannerProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		banner := fetchSSHBanner(t.IP)
		if banner == "" {
			emitObservation(emit, s.Name(), t, "ssh", "no_data", map[string]string{"port": "22"})
			continue
		}
		meta := parseSSHBannerMetadata(banner)
		details := map[string]string{
			"banner_sha1": meta.BannerSHA1,
			"protocol":    meta.Protocol,
			"software":    meta.Software,
			"comment":     meta.Comment,
			"family":      meta.Family,
			"port":        "22",
		}
		emitObservation(emit, s.Name(), t, "ssh_banner", banner, details)
		emitObservation(emit, s.Name(), t, "ssh_protocol", meta.Protocol, details)
		emitObservation(emit, s.Name(), t, "ssh_software", meta.Software, details)
		if meta.Comment != "" {
			emitObservation(emit, s.Name(), t, "ssh_comment", meta.Comment, details)
		}
		emitObservation(emit, s.Name(), t, "ssh_family", meta.Family, details)
		emitObservation(emit, s.Name(), t, "ssh_banner_sha1", meta.BannerSHA1, details)
	}
}

type sshBannerMetadata struct {
	Protocol   string
	Software   string
	Comment    string
	Family     string
	BannerSHA1 string
}

func parseSSHBannerMetadata(banner string) sshBannerMetadata {
	meta := sshBannerMetadata{BannerSHA1: bannerSHA1(banner)}
	matches := sshBannerRegex.FindStringSubmatch(strings.TrimSpace(banner))
	if len(matches) == 0 {
		meta.Family = sshSoftwareFamily(banner)
		return meta
	}
	meta.Protocol = matches[1]
	meta.Software = matches[2]
	if len(matches) > 3 {
		meta.Comment = strings.TrimSpace(matches[3])
	}
	meta.Family = sshSoftwareFamily(meta.Software)
	return meta
}

func sshSoftwareFamily(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "openssh"):
		return "openssh"
	case strings.Contains(lower, "dropbear"):
		return "dropbear"
	case strings.Contains(lower, "libssh"):
		return "libssh"
	case strings.Contains(lower, "putty"):
		return "putty"
	default:
		return "unknown"
	}
}

func bannerSHA1(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}
