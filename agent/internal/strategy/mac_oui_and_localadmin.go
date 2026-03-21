package strategy

import (
	"strconv"

	"github.com/netwise/agent/internal/oui"
)

type MacOuiAndLocalAdmin struct{}

func (s *MacOuiAndLocalAdmin) Name() string {
	return "mac_oui_and_localadmin"
}

func (s *MacOuiAndLocalAdmin) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		emitObservation(emit, s.Name(), t, "vendor", oui.Lookup(t.MAC), map[string]string{
			"locally_admin": strconv.FormatBool(oui.IsLocallyAdministeredMAC(t.MAC)),
		})
	}
}
