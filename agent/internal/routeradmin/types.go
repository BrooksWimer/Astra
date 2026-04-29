package routeradmin

import "time"

const (
	ProviderAuto    = "auto"
	ProviderXfinity = "xfinity"
)

const (
	StatusUnavailable  = "unavailable"
	StatusPageFetched  = "page_fetched"
	StatusAuthRejected = "auth_rejected"
)

type Config struct {
	Provider  string
	BaseURL   string
	Username  string
	Password  string
	Timeout   time.Duration
	UserAgent string
}

type DeviceSummary struct {
	Name       string
	DetailHint string
}

type Inventory struct {
	Provider             string
	BaseURL              string
	Status               string
	StatusReason         string
	ConnectedDevicesPath string
	ListPageTitle        string
	ListPageSHA1         string
	ListPageBytes        int
	Devices              []DeviceSummary
	DetailPath           string
	DetailPathResolved   bool
	DetailCandidates     []string
}
