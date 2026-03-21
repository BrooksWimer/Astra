package strategy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type dhcpLeaseFamily int

const (
	dhcpLeaseFamilyV4 dhcpLeaseFamily = iota
	dhcpLeaseFamilyV6
	dhcpLeaseFamilyStatic
)

type dhcpv4OptionsStrategy struct{}

func NewDHCPV4Options() Strategy { return dhcpv4OptionsStrategy{} }

func (s dhcpv4OptionsStrategy) Name() string { return "dhcpv4_options" }

func (s dhcpv4OptionsStrategy) Collect(targets []Target, emit ObservationSink) {
	collectDHCPLeaseFamily(s.Name(), targets, emit, dhcpLeaseFamilyV4)
}

type dhcpLeaseRecord struct {
	File   string
	Header string
	Kind   string
	Raw    string
}

var (
	dhcpWordToken = regexp.MustCompile(`[A-Za-z0-9_.:-]+`)

	reDHCPv4LeaseHeader   = regexp.MustCompile(`(?im)^\s*lease\s+([^\s{;]+)\s*\{`)
	reDHCPv6IAAddr        = regexp.MustCompile(`(?im)^\s*iaaddr\s+([^\s{;]+)\s*\{`)
	reDHCPv6IAHeader      = regexp.MustCompile(`(?im)^\s*ia-(?:na|pd)\s+([^\s{;]+)\s*\{`)
	reBindingState        = regexp.MustCompile(`(?im)^\s*binding state\s+([a-z0-9_-]+);`)
	reEnds                = regexp.MustCompile(`(?im)^\s*ends\s+([^;]+);`)
	reRenew               = regexp.MustCompile(`(?im)^\s*renew\s+([^;]+);`)
	reRebind              = regexp.MustCompile(`(?im)^\s*rebind\s+([^;]+);`)
	rePreferredLife       = regexp.MustCompile(`(?im)^\s*preferred-life\s+([^;]+);`)
	reValidLife           = regexp.MustCompile(`(?im)^\s*(?:valid-life|max-life)\s+([^;]+);`)
	reHardwareEthernet    = regexp.MustCompile(`(?im)^\s*hardware ethernet\s+([^;]+);`)
	reClientIdentifier    = regexp.MustCompile(`(?im)^\s*(?:client identifier|client-identifier|uid)\s+([^;]+);`)
	reHostName            = regexp.MustCompile(`(?im)^\s*(?:option\s+host-name|host-name|client-hostname)\s+"?([^";]+)"?;`)
	reVendorClass         = regexp.MustCompile(`(?im)^\s*option\s+vendor-class-identifier\s+"?([^";]+)"?;`)
	reServerID            = regexp.MustCompile(`(?im)^\s*(?:option\s+dhcp-server-identifier|server identifier|server-id)\s+([^;]+);`)
	reFixedAddress        = regexp.MustCompile(`(?im)^\s*fixed-address(?:6)?\s+([^;]+);`)
	reRouter              = regexp.MustCompile(`(?im)^\s*option\s+routers\s+([^;]+);`)
	reSubnetMask          = regexp.MustCompile(`(?im)^\s*option\s+subnet-mask\s+([^;]+);`)
	reRequestedAddress    = regexp.MustCompile(`(?im)^\s*option\s+requested-address\s+([^;]+);`)
	reLeaseTime           = regexp.MustCompile(`(?im)^\s*option\s+dhcp-lease-time\s+([^;]+);`)
	reParamRequestList    = regexp.MustCompile(`(?im)^\s*option\s+dhcp-parameter-request-list\s+([^;]+);`)
	reMessageType         = regexp.MustCompile(`(?im)^\s*(?:option\s+)?(?:dhcp-)?message-type\s+([^;]+);`)
	reFQDN                = regexp.MustCompile(`(?im)^\s*option\s+fqdn\s+([^;]+);`)
	reDomainName          = regexp.MustCompile(`(?im)^\s*option\s+domain-name\s+"?([^";]+)"?;`)
	reDNS                 = regexp.MustCompile(`(?im)^\s*option\s+domain-name-servers\s+([^;]+);`)
	reNTP                 = regexp.MustCompile(`(?im)^\s*option\s+ntp-servers\s+([^;]+);`)
	reInterfaceMTU        = regexp.MustCompile(`(?im)^\s*option\s+interface-mtu\s+([^;]+);`)
	reBootfile            = regexp.MustCompile(`(?im)^\s*filename\s+"?([^";]+)"?;`)
	reServerName          = regexp.MustCompile(`(?im)^\s*server-name\s+"?([^";]+)"?;`)
	reDDNS                = regexp.MustCompile(`(?im)^\s*ddns-hostname\s+"?([^";]+)"?;`)
	reCircuitID           = regexp.MustCompile(`(?im)^\s*option\s+circuit-id\s+"?([^";]+)"?;`)
	reRemoteID            = regexp.MustCompile(`(?im)^\s*option\s+remote-id\s+"?([^";]+)"?;`)
	reClasslessRoute      = regexp.MustCompile(`(?im)^\s*option\s+classless-static-routes\s+([^;]+);`)
	reBootpVendorClass    = regexp.MustCompile(`(?im)^\s*vendor-class-identifier\s+"?([^";]+)"?;`)
	reRawOptionCode       = regexp.MustCompile(`(?im)^\s*option\s+([0-9]{1,3})\s+([^;]+);`)
	reLeaseIdentifier     = regexp.MustCompile(`(?im)^\s*lease\s+([^\s{;]+)\s*\{`)
	reStaticHostHeader    = regexp.MustCompile(`(?im)^\s*host\s+([A-Za-z0-9_.:-]+)\s*\{`)
	reConfigReservation   = regexp.MustCompile(`(?im)^\s*host\s+([A-Za-z0-9_.:-]+)\s*\{`)
	reConfigFixedAddress   = regexp.MustCompile(`(?im)^\s*fixed-address(?:6)?\s+([^;]+);`)
	reConfigHwEthernet    = regexp.MustCompile(`(?im)^\s*hardware ethernet\s+([^;]+);`)
	reConfigClientID      = regexp.MustCompile(`(?im)^\s*client-identifier\s+([^;]+);`)
	reConfigHostName      = regexp.MustCompile(`(?im)^\s*option\s+host-name\s+"?([^";]+)"?;`)
)

func collectDHCPLeaseFamily(strategyName string, targets []Target, emit ObservationSink, family dhcpLeaseFamily) {
	paths := dhcpLeasePaths()
	if len(paths) == 0 {
		emit(Observation{Strategy: strategyName, Key: "lease_match", Value: "no_lease_paths"})
		return
	}

	tokens := targetTokens(targets)

	seen := map[string]struct{}{}
	for _, path := range uniqueStrings(paths) {
		content, err := os.ReadFile(path)
		if err != nil {
			emit(Observation{Strategy: strategyName, Key: "lease_match", Value: "read_error:" + filepath.Base(path)})
			continue
		}
		for _, record := range parseDHCPLeaseRecords(path, string(content), family) {
			if !recordMatchesTokens(record, tokens) {
				continue
			}
			emitDHCPLeaseRecord(strategyName, family, record, emit, seen)
		}
	}
}

func emitDHCPLeaseRecord(strategyName string, family dhcpLeaseFamily, record dhcpLeaseRecord, emit ObservationSink, seen map[string]struct{}) {
	prefix := dhcpFamilyPrefix(family)
	recordKey := record.File + "|" + record.Header + "|" + record.Raw
	if _, ok := seen[recordKey]; ok {
		return
	}
	seen[recordKey] = struct{}{}

	emit(Observation{Strategy: strategyName, Key: "lease_match", Value: summarizeLeaseMatch(record)})
	emit(Observation{Strategy: strategyName, Key: prefix + "_lease_file", Value: record.File})
	emit(Observation{Strategy: strategyName, Key: prefix + "_lease_header", Value: record.Header})

	for _, value := range uniqueStrings(append(allMatches(record.Raw, reLeaseIdentifier), allMatches(record.Raw, reLeaseIdentifier)...)) {
		if value != "" {
			emit(Observation{Strategy: strategyName, Key: prefix + "_lease_id", Value: value})
		}
	}

	switch family {
	case dhcpLeaseFamilyV4:
		emitLeaseFields(strategyName, prefix, record.Raw, emit, []fieldRule{
			{"dhcpv4_lease_state", reBindingState},
			{"dhcpv4_lease_ends", reEnds},
			{"dhcpv4_lease_renew", reRenew},
			{"dhcpv4_lease_rebind", reRebind},
			{"dhcpv4_mac", reHardwareEthernet},
			{"dhcpv4_client_id", reClientIdentifier},
			{"dhcpv4_hostname", reHostName},
			{"dhcpv4_vendor_class", reVendorClass},
			{"dhcpv4_server_id", reServerID},
			{"dhcpv4_fixed_address", reFixedAddress},
			{"dhcpv4_router", reRouter},
			{"dhcpv4_subnet_mask", reSubnetMask},
			{"dhcpv4_requested_address", reRequestedAddress},
			{"dhcpv4_lease_time", reLeaseTime},
			{"dhcpv4_parameter_request_list", reParamRequestList},
			{"dhcpv4_message_type", reMessageType},
			{"dhcpv4_fqdn", reFQDN},
			{"dhcpv4_domain_name", reDomainName},
			{"dhcpv4_dns_servers", reDNS},
			{"dhcpv4_ntp_servers", reNTP},
			{"dhcpv4_interface_mtu", reInterfaceMTU},
			{"dhcpv4_bootfile", reBootfile},
			{"dhcpv4_server_name", reServerName},
			{"dhcpv4_ddns_hostname", reDDNS},
			{"dhcpv4_circuit_id", reCircuitID},
			{"dhcpv4_remote_id", reRemoteID},
			{"dhcpv4_classless_routes", reClasslessRoute},
		})
		emitOptionCodes(strategyName, record.Raw, emit)
	case dhcpLeaseFamilyV6:
		emitLeaseFields(strategyName, prefix, record.Raw, emit, []fieldRule{
			{"dhcpv6_address", reDHCPv6IAAddr},
			{"dhcpv6_iaid", reDHCPv6IAHeader},
			{"dhcpv6_duid", reClientIdentifier},
			{"dhcpv6_state", reBindingState},
			{"dhcpv6_preferred_life", rePreferredLife},
			{"dhcpv6_valid_life", reValidLife},
			{"dhcpv6_lease_ends", reEnds},
			{"dhcpv6_lease_renew", reRenew},
			{"dhcpv6_lease_rebind", reRebind},
			{"dhcpv6_server_id", reServerID},
			{"dhcpv6_hostname", reHostName},
		})
		emit(Observation{Strategy: strategyName, Key: "dhcpv6_lease_file", Value: record.File})
	case dhcpLeaseFamilyStatic:
		emitLeaseFields(strategyName, prefix, record.Raw, emit, []fieldRule{
			{"reservation_state", reBindingState},
			{"reservation_binding", reStaticHostHeader},
			{"reservation_ip", reConfigFixedAddress},
			{"reservation_mac", reConfigHwEthernet},
			{"reservation_client_identifier", reConfigClientID},
			{"reservation_hostname", reConfigHostName},
			{"reservation_fixed_address", reConfigFixedAddress},
			{"reservation_vendor_class", reVendorClass},
			{"reservation_expiry", reEnds},
		})
		emit(Observation{Strategy: strategyName, Key: "reservation_source", Value: "static_config"})
		emit(Observation{Strategy: strategyName, Key: "reservation_file", Value: record.File})
	}
}

type fieldRule struct {
	key string
	re  *regexp.Regexp
}

func emitLeaseFields(strategyName, prefix, raw string, emit ObservationSink, rules []fieldRule) {
	for _, rule := range rules {
		for _, value := range uniqueStrings(allMatches(raw, rule.re)) {
			if value == "" {
				continue
			}
			if strings.HasPrefix(rule.key, prefix) || strings.HasPrefix(rule.key, "reservation_") {
				emit(Observation{Strategy: strategyName, Key: rule.key, Value: value})
				continue
			}
			emit(Observation{Strategy: strategyName, Key: rule.key, Value: value})
		}
	}
}

func emitOptionCodes(strategyName, raw string, emit ObservationSink) {
	// Numeric options are emitted in addition to their semantic aliases where possible.
	codes := map[string]*regexp.Regexp{
		"dhcpv4_option_12": reHostName,
		"dhcpv4_option_50": reRequestedAddress,
		"dhcpv4_option_53": reMessageType,
		"dhcpv4_option_54": reServerID,
		"dhcpv4_option_55": reParamRequestList,
		"dhcpv4_option_60": reVendorClass,
		"dhcpv4_option_61": reClientIdentifier,
		"dhcpv4_option_81": reFQDN,
	}
	for key, re := range codes {
		for _, value := range uniqueStrings(allMatches(raw, re)) {
			if value != "" {
				emit(Observation{Strategy: strategyName, Key: key, Value: value})
			}
		}
	}
	emitRawOptionPairs(strategyName, raw, emit)
}

func emitRawOptionPairs(strategyName, raw string, emit ObservationSink) {
	matches := reRawOptionCode.FindAllStringSubmatch(raw, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		code := strings.TrimSpace(match[1])
		value := strings.TrimSpace(match[2])
		if code == "" || value == "" {
			continue
		}
		emit(Observation{Strategy: strategyName, Key: "dhcpv4_option_raw", Value: code + ":" + value})
	}
}

func parseDHCPLeaseRecords(path, content string, family dhcpLeaseFamily) []dhcpLeaseRecord {
	blocks := scanBraceBlocks(content)
	records := make([]dhcpLeaseRecord, 0, len(blocks))
	for _, block := range blocks {
		header := strings.TrimSpace(block.header)
		raw := strings.TrimSpace(block.raw)
		if raw == "" {
			continue
		}

		switch family {
		case dhcpLeaseFamilyV4:
			if !strings.HasPrefix(strings.ToLower(header), "lease ") && !strings.HasPrefix(strings.ToLower(header), "host ") {
				continue
			}
			records = append(records, dhcpLeaseRecord{File: path, Header: header, Kind: "v4", Raw: raw})
		case dhcpLeaseFamilyV6:
			lower := strings.ToLower(header)
			if !strings.HasPrefix(lower, "iaaddr ") && !strings.HasPrefix(lower, "ia-na ") && !strings.HasPrefix(lower, "ia-pd ") && !strings.HasPrefix(lower, "host ") {
				continue
			}
			records = append(records, dhcpLeaseRecord{File: path, Header: header, Kind: "v6", Raw: raw})
		case dhcpLeaseFamilyStatic:
			lower := strings.ToLower(header)
			if !strings.HasPrefix(lower, "host ") && !strings.Contains(raw, "fixed-address") && !strings.Contains(raw, "hardware ethernet") {
				continue
			}
			records = append(records, dhcpLeaseRecord{File: path, Header: header, Kind: "static", Raw: raw})
		}
	}

	if len(records) == 0 && family == dhcpLeaseFamilyStatic {
		lower := strings.ToLower(content)
		if strings.Contains(lower, "fixed-address") || strings.Contains(lower, "host-name") {
			records = append(records, dhcpLeaseRecord{File: path, Header: "static-file", Kind: "static", Raw: content})
		}
	}
	return records
}

func scanBraceBlocks(content string) []dhcpLeaseBlock {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var blocks []dhcpLeaseBlock
	var current []string
	var header string
	depth := 0
	inBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !inBlock {
			if !strings.Contains(line, "{") {
				continue
			}
			inBlock = true
			header = line
			current = []string{line}
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				blocks = append(blocks, dhcpLeaseBlock{header: header, raw: strings.Join(current, "\n")})
				inBlock = false
				current = nil
				depth = 0
			}
			continue
		}
		current = append(current, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			blocks = append(blocks, dhcpLeaseBlock{header: header, raw: strings.Join(current, "\n")})
			inBlock = false
			current = nil
			depth = 0
		}
	}
	return blocks
}

type dhcpLeaseBlock struct {
	header string
	raw    string
}

func recordMatchesTokens(record dhcpLeaseRecord, tokens []string) bool {
	if len(tokens) == 0 {
		return true
	}
	haystack := normalizeLeaseText(record.File + " " + record.Header + " " + record.Raw)
	for _, token := range tokens {
		if token == "" || token == "unknown" {
			continue
		}
		if strings.Contains(haystack, normalizeLeaseText(token)) {
			return true
		}
	}
	return false
}

func summarizeLeaseMatch(record dhcpLeaseRecord) string {
	matches := []string{}
	if match := firstMatch(record.Raw, reLeaseIdentifier); match != "" {
		matches = append(matches, "id:"+match)
	}
	if match := firstMatch(record.Raw, reHostName); match != "" {
		matches = append(matches, "host:"+match)
	}
	if match := firstMatch(record.Raw, reHardwareEthernet); match != "" {
		matches = append(matches, "mac:"+match)
	}
	if match := firstMatch(record.Raw, reFixedAddress); match != "" {
		matches = append(matches, "ip:"+match)
	}
	if len(matches) == 0 {
		return "file:" + filepath.Base(record.File)
	}
	return strings.Join(matches, "|")
}

func allMatches(raw string, re *regexp.Regexp) []string {
	if re == nil {
		return nil
	}
	matches := re.FindAllStringSubmatch(raw, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		value = strings.Trim(value, `"'`)
		value = strings.TrimSuffix(value, ";")
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func firstMatch(raw string, re *regexp.Regexp) string {
	matches := allMatches(raw, re)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func targetTokens(targets []Target) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(targets)*4)
	for _, target := range targets {
		raw := strings.ToLower(fmt.Sprint(target))
		for _, token := range dhcpWordToken.FindAllString(raw, -1) {
			if !interestingDHCPToken(token) {
				continue
			}
			for _, candidate := range []string{token, normalizeLeaseText(token)} {
				if candidate == "" || candidate == "unknown" {
					continue
				}
				if _, ok := seen[candidate]; ok {
					continue
				}
				seen[candidate] = struct{}{}
				out = append(out, candidate)
			}
		}
	}
	return out
}

func interestingDHCPToken(token string) bool {
	if len(token) < 2 {
		return false
	}
	switch token {
	case "target", "device", "devices", "unknown", "none", "true", "false", "host", "hostname", "address", "ip", "mac", "vendor":
		return false
	}
	return true
}

func normalizeLeaseText(in string) string {
	in = strings.ToLower(in)
	replacer := strings.NewReplacer("-", "", "_", "", ".", "", ":", "", " ", "", "\t", "", "\n", "")
	return replacer.Replace(in)
}

func dhcpFamilyPrefix(family dhcpLeaseFamily) string {
	switch family {
	case dhcpLeaseFamilyV4:
		return "dhcpv4"
	case dhcpLeaseFamilyV6:
		return "dhcpv6"
	default:
		return "reservation"
	}
}
