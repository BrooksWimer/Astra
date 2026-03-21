package strategy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type TlsCertProbe struct{}

type tlsFingerprintResult struct {
	Port              int
	Status            string
	Subject           string
	Issuer            string
	SANs              string
	Serial            string
	FingerprintSHA1   string
	FingerprintSHA256 string
	NotBefore         string
	NotAfter          string
	Version           string
	CipherSuite       string
	ALPN              string
	PublicKeyType     string
	PublicKeyBits     string
}

func (s *TlsCertProbe) Name() string {
	return "tls_cert_probe"
}

func (s *TlsCertProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		results := []tlsFingerprintResult{
			probeTLSFingerprint(t.IP, 443),
			probeTLSFingerprint(t.IP, 8443),
			probeTLSFingerprint(t.IP, 9443),
		}
		seen := false
		for _, r := range results {
			if r.Status == "" && r.Subject == "" && r.Issuer == "" && r.SANs == "" {
				continue
			}
			seen = true
			details := map[string]string{
				"port":       strconv.Itoa(r.Port),
				"status":     r.Status,
				"version":    r.Version,
				"cipher":     r.CipherSuite,
				"alpn":       r.ALPN,
				"key_type":   r.PublicKeyType,
				"key_bits":   r.PublicKeyBits,
				"not_before": r.NotBefore,
				"not_after":  r.NotAfter,
			}
			emitObservation(emit, s.Name(), t, "tls_port", strconv.Itoa(r.Port), details)
			emitObservation(emit, s.Name(), t, "tls_subject", r.Subject, details)
			emitObservation(emit, s.Name(), t, "tls_issuer", r.Issuer, details)
			emitObservation(emit, s.Name(), t, "tls_sans", r.SANs, details)
			emitObservation(emit, s.Name(), t, "tls_serial", r.Serial, details)
			emitObservation(emit, s.Name(), t, "tls_fingerprint_sha1", r.FingerprintSHA1, details)
			emitObservation(emit, s.Name(), t, "tls_fingerprint_sha256", r.FingerprintSHA256, details)
			emitObservation(emit, s.Name(), t, "tls_version", r.Version, details)
			emitObservation(emit, s.Name(), t, "tls_cipher", r.CipherSuite, details)
			emitObservation(emit, s.Name(), t, "tls_alpn", r.ALPN, details)
			emitObservation(emit, s.Name(), t, "tls_key_type", r.PublicKeyType, details)
			emitObservation(emit, s.Name(), t, "tls_key_bits", r.PublicKeyBits, details)
		}
		if !seen {
			emitObservation(emit, s.Name(), t, "tls", "no_data", map[string]string{"reason": "no_tls_certificate"})
		}
	}
}

func probeTLSFingerprint(ip string, port int) tlsFingerprintResult {
	if ip == "" || port <= 0 {
		return tlsFingerprintResult{}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: strategyProbeTimeout}, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return tlsFingerprintResult{Port: port, Status: "no_response"}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	out := tlsFingerprintResult{
		Port:        port,
		Status:      "connected",
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) == 0 {
		return out
	}
	cert := state.PeerCertificates[0]
	out.Subject = strings.TrimSpace(cert.Subject.String())
	out.Issuer = strings.TrimSpace(cert.Issuer.String())
	out.Serial = strings.ToUpper(cert.SerialNumber.Text(16))
	out.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	out.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	out.SANs = strings.Join(collectCertificateSANs(cert), ",")
	out.FingerprintSHA1 = sha1HexTLS(cert.Raw)
	out.FingerprintSHA256 = sha256Hex(cert.Raw)
	out.PublicKeyType, out.PublicKeyBits = describePublicKey(cert.PublicKey)
	return out
}

func sha1HexTLS(raw []byte) string {
	sum := sha1.Sum(raw)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func describePublicKey(key any) (string, string) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return "rsa", strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ecdsa", strconv.Itoa(k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "ed25519", strconv.Itoa(len(k) * 8)
	default:
		return fmt.Sprintf("%T", key), ""
	}
}

func collectCertificateSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	out := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return uniqueSortedStrings(out)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return strconv.Itoa(int(version))
	}
}
