package oui

import (
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"strings"
	"sync"
)
 
// IsLocallyAdministeredMAC reports whether a MAC uses the U/L bit.
func IsLocallyAdministeredMAC(mac string) bool {
	norm := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""), ".", ""))
	if len(norm) < 2 {
		return false
	}
	prefix := norm[:2]
	b, err := hex.DecodeString(prefix)
	if err != nil || len(b) == 0 {
		return false
	}
	return b[0]&0x02 != 0
}

func normalizePrefix(mac string) string {
	return strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
}

//go:embed oui.csv
var ouiCSV []byte

var (
	once sync.Once
	m    map[string]string
)

func Lookup(mac string) string {
	once.Do(loadOUI)
	norm := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(norm) >= 6 {
		prefix := norm[:6]
		if v, ok := m[prefix]; ok {
			return v
		}
	}
	return "Unknown"
}

func loadOUI() {
	m = make(map[string]string)
	r := csv.NewReader(strings.NewReader(string(ouiCSV)))
	records, err := r.ReadAll()
	if err != nil {
		return
	}
	for i, row := range records {
		if i == 0 && len(row) > 0 && row[0] == "mac_prefix" {
			continue
		}
		if len(row) >= 2 {
			prefix := strings.ToUpper(strings.ReplaceAll(row[0], ":", ""))
			if len(prefix) >= 6 {
				m[prefix[:6]] = strings.TrimSpace(row[1])
			}
		}
	}
}
