package passive

import (
	"sync"
	"time"
)

type RuntimeConfig struct {
	Enabled           bool
	Window            time.Duration
	Interface         string
	Promiscuous       bool
	Snaplen           int
	BufferPackets     int
	LocalIP           string
	InfraEnabled      bool
	SyslogListenAddr  string
	ResolverLogPath   string
	DHCPLogPath       string
	SessionSource     string
	SessionCommand    string
}

type Corpus struct {
	CapturePoint         string
	Interface            string
	Window               time.Duration
	StartedAt            time.Time
	FinishedAt           time.Time
	HostCaptureEnabled   bool
	HostCaptureAvailable bool
	HostCaptureReason    string
	InfraEnabled         bool
	Flows                []FlowEvent
	TLSServers           []TLSServerEvent
	TLSClients           []TLSClientEvent
	HTTP                 []HTTPEvent
	SSH                  []SSHEvent
	DHCP                 []DHCPEvent
	DNS                  []DNSEvent
	QUIC                 []QUICEvent
	IPv6                 []IPv6Event
	MDNS                 []MDNSEvent
	SSDP                 []SSDPEVent
	Netflow              []NetflowEvent
	WiFi                 []WiFiEvent
	Resolver             []ResolverEvent
	Sessions             []SessionProfileEvent
	Radius               []RadiusEvent
}

type FlowEvent struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcMAC    string
	DstMAC    string
	Transport string
	SrcPort   int
	DstPort   int
	Protocol  string
}

type TLSServerEvent struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	Version     string
	ALPN        string
	SNI         string
	Cipher      string
	CertSubject string
	CertIssuer  string
}

type TLSClientEvent struct {
	Timestamp          time.Time
	SrcIP              string
	DstIP              string
	SrcMAC             string
	DstMAC             string
	JA3                string
	Version            string
	ALPN               string
	SNI                string
	SNICategory        string
	CipherOrderHash    string
	ExtensionOrderHash string
}

type HTTPEvent struct {
	Timestamp  time.Time
	SrcIP      string
	DstIP      string
	SrcMAC     string
	DstMAC     string
	Role       string
	Host       string
	UserAgent  string
	Server     string
	PathHint   string
	StatusCode int
}

type SSHEvent struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcMAC    string
	DstMAC    string
	Banner    string
	Software  string
	Proto     string
}

type DHCPEvent struct {
	Timestamp        time.Time
	ClientIP         string
	RequestedIP      string
	ClientMAC        string
	ServerIP         string
	Hostname         string
	VendorClass      string
	ClientIdentifier string
	MessageType      string
	PRL              []string
	OptionOrder      []string
}

type DNSEvent struct {
	Timestamp  time.Time
	ClientIP   string
	ClientMAC  string
	ResolverIP string
	Query      string
	QueryType  string
	Transport  string
	Category   string
	IsReverse  bool
	IsLocal    bool
}

type QUICEvent struct {
	Timestamp       time.Time
	SrcIP           string
	DstIP           string
	SrcMAC          string
	DstMAC          string
	Version         string
	SNICategory     string
	ALPN            string
	FingerprintHash string
}

type IPv6Event struct {
	Timestamp      time.Time
	SrcIP          string
	DstIP          string
	SrcMAC         string
	DstMAC         string
	Role           string
	PrivacyAddress bool
	SLAACBehavior  string
}

type MDNSEvent struct {
	Timestamp     time.Time
	SrcIP         string
	SrcMAC        string
	MessageType   string
	Name          string
	QueryType     string
	ServiceFamily string
	TTL           uint32
	Instance      string
	Hostname      string
}

type SSDPEVent struct {
	Timestamp    time.Time
	SrcIP        string
	SrcMAC       string
	MessageType  string
	ST           string
	NT           string
	NTS          string
	USN          string
	Server       string
	Location     string
	CacheControl string
}

type NetflowEvent struct {
	Timestamp         time.Time
	ExporterIP        string
	Version           int
	ObservationDomain string
	TemplateID        string
	PEN               string
	SrcIP             string
	DstIP             string
	SrcPort           int
	DstPort           int
	Protocol          string
}

type WiFiEvent struct {
	Timestamp       time.Time
	ClientIP        string
	ClientMAC       string
	Hostname        string
	State           string
	RSSI            string
	Band            string
	Channel         string
	SessionDuration string
	RoamCount       string
}

type ResolverEvent struct {
	Timestamp   time.Time
	ClientIP    string
	ClientMAC   string
	Query       string
	Category    string
	LocalLookup bool
	SRVLookup   bool
}

type SessionProfileEvent struct {
	Timestamp      time.Time
	ClientIP       string
	ClientMAC      string
	SessionCount   int
	ProtocolMix    string
	LongLivedCount int
	RemoteCategory string
	Burstiness     string
}

type RadiusEvent struct {
	Timestamp  time.Time
	ClientIP   string
	ClientMAC  string
	Identity   string
	Realm      string
	EAPType    string
	VLAN       string
	Role       string
	AuthResult string
}

type Session struct {
	done   chan struct{}
	mu     sync.RWMutex
	corpus Corpus
}
