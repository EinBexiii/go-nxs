package nxs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	discoveryPath = "/.well-known/nethernet-external-signaling"

	extensionConnectivity = "dev.opencollab.nxs.connectivity"
	extensionWebSocket    = "dev.opencollab.nxs.websocket"

	assistedCapability = "nethernet.websocket-assisted.v1"

	schemeAnonymous = "anonymous-proof-of-work"
	schemeBearer    = "bearer-token"

	// ModeAutomatic lets the provider choose between creating a service and attaching an instance.
	ModeAutomatic = "automatic"
	// ModeNewService creates a new service with this instance.
	ModeNewService = "new-service"
	// ModeAttachInstance attaches this instance to an existing service. It requires a token and Placement.
	ModeAttachInstance = "attach-instance"

	modeRecover = "recover"
)

var operations = []string{"register", "complete", "heartbeat", "outcomes", "rotate", "retire", "deregister"}

// extension is an optional protocol extension.
type extension struct {
	Version  int             `json:"version"`
	Critical bool            `json:"critical"`
	Data     json.RawMessage `json:"data"`
}

type discovery struct {
	Provider      string            `json:"provider"`
	ControlOrigin string            `json:"controlOrigin"`
	Protocols     []string          `json:"protocols"`
	Signatures    []string          `json:"signatures"`
	Profiles      []string          `json:"profiles"`
	Modes         []string          `json:"modes"`
	Operations    map[string]string `json:"operations"`
	Authorization struct {
		Header  string `json:"header"`
		Schemes []struct {
			Scheme string   `json:"scheme"`
			Modes  []string `json:"modes"`
		} `json:"schemes"`
	} `json:"authorization"`
	Limits struct {
		MaxBodyBytes        int64 `json:"maxBodyBytes"`
		ClockSkewMs         int64 `json:"clockSkewMs"`
		HeartbeatIntervalMs int64 `json:"heartbeatIntervalMs"`
		LeaseMs             int64 `json:"leaseMs"`
	} `json:"limits"`
	Extensions map[string]extension `json:"extensions"`
}

// validate checks that discovery is usable for the origin, registration scheme and mode.
func (d *discovery) validate(origin, scheme, mode string) error {
	if d.Provider != origin || d.ControlOrigin != origin {
		return errors.New("provider origin mismatch")
	}
	for _, c := range []struct {
		name   string
		values []string
		want   string
	}{{"protocol", d.Protocols, Protocol}, {"signature", d.Signatures, SignatureVersion}, {"profile", d.Profiles, Profile}, {"mode", d.Modes, mode}} {
		if !slices.Contains(c.values, c.want) {
			return fmt.Errorf("unsupported %s %q", c.name, c.want)
		}
	}
	if d.Authorization.Header != "Authorization" {
		return errors.New("unsupported authorization header")
	}
	supported := false
	for _, s := range d.Authorization.Schemes {
		supported = supported || (s.Scheme == scheme && slices.Contains(s.Modes, mode))
	}
	if !supported {
		return fmt.Errorf("provider does not accept %s registration with mode %s", scheme, mode)
	}
	for _, op := range operations {
		u, ok := d.Operations[op]
		if !ok {
			return fmt.Errorf("missing operation %s", op)
		}
		if _, err := operationURL(origin, u); err != nil {
			return fmt.Errorf("operation %s: %w", op, err)
		}
	}
	if l := d.Limits; l.HeartbeatIntervalMs < 1000 || l.HeartbeatIntervalMs > 30000 || l.MaxBodyBytes < 1 ||
		l.MaxBodyBytes > 65536 || l.ClockSkewMs < 0 || l.ClockSkewMs > 60000 {
		return errors.New("unsupported provider limits")
	}
	for name, ext := range d.Extensions {
		if ext.Critical && name != extensionConnectivity {
			return fmt.Errorf("unsupported critical extension %s", name)
		}
	}
	return nil
}

// stunServers returns the STUN servers advertised by the connectivity extension.
func (d *discovery) stunServers() []string {
	ext, ok := d.Extensions[extensionConnectivity]
	if !ok || ext.Version != 1 {
		return nil
	}
	var data struct {
		StunServers []struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"stunServers"`
	}
	if json.Unmarshal(ext.Data, &data) != nil {
		return nil
	}
	var servers []string
	for _, s := range data.StunServers[:min(len(data.StunServers), 2)] {
		if s.Host != "" && s.Port > 0 && s.Port < 65536 {
			servers = append(servers, joinHostPort(s.Host, s.Port))
		}
	}
	return servers
}

func (d *discovery) connectivity() bool {
	ext, ok := d.Extensions[extensionConnectivity]
	return ok && ext.Version == 1
}

type authorization struct {
	Scheme    string `json:"scheme"`
	Reference string `json:"reference,omitempty"`
}

// Placement selects the region and pool of an instance.
type Placement struct {
	Region string            `json:"region"`
	Pool   string            `json:"pool"`
	Tags   map[string]string `json:"tags,omitempty"`
}

var (
	regionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	poolPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
)

func (p *Placement) validate() error {
	if !regionPattern.MatchString(p.Region) || !poolPattern.MatchString(p.Pool) || len(p.Tags) > 16 {
		return errors.New("nxs: invalid placement")
	}
	for k, v := range p.Tags {
		if !tagPattern.MatchString(k) || strings.TrimSpace(v) != v || len(v) < 1 || len(v) > 64 || strings.ContainsFunc(v, isControl) {
			return fmt.Errorf("nxs: invalid placement tag %q", k)
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }

type registerRequest struct {
	Protocol       string         `json:"protocol"`
	Mode           string         `json:"mode,omitempty"`
	Profile        string         `json:"profile"`
	PublicKeyJWK   *jwk           `json:"publicKeyJwk,omitempty"`
	Label          string         `json:"label,omitempty"`
	Authorization  *authorization `json:"authorization,omitempty"`
	Placement      *Placement     `json:"placement,omitempty"`
	RegistrationID string         `json:"registrationId,omitempty"`
}

type challenge struct {
	Protocol      string           `json:"protocol"`
	Signature     string           `json:"signature"`
	ChallengeID   string           `json:"challengeId"`
	Nonce         string           `json:"nonce"`
	Audience      string           `json:"audience"`
	Thumbprint    string           `json:"thumbprint"`
	Context       challengeContext `json:"context"`
	ContextDigest string           `json:"contextDigest"`
	ExpiresAt     int64            `json:"expiresAt"`
	ServerTime    int64            `json:"serverTime"`
	Pow           struct {
		Algorithm  string `json:"algorithm"`
		Difficulty int    `json:"difficulty"`
	} `json:"pow"`
	Authorization *authorization `json:"authorization,omitempty"`
}

// validate checks that the challenge is bound to the origin and key.
func (c *challenge) validate(origin, thumbprint string) error {
	d, err := c.Context.digest()
	if err != nil {
		return err
	}
	if c.Protocol != Protocol || c.Signature != SignatureVersion || c.Audience != origin || c.Thumbprint != thumbprint ||
		c.ContextDigest != d || c.Context.Profile != Profile || c.Pow.Algorithm != powAlgorithm || c.Pow.Difficulty < 0 || c.Pow.Difficulty > 24 {
		return errors.New("nxs: unbound registration challenge")
	}
	return nil
}

type completeRequest struct {
	Protocol       string `json:"protocol"`
	ChallengeID    string `json:"challengeId"`
	ProofNonce     string `json:"proofNonce"`
	IdempotencyKey string `json:"idempotencyKey"`
	Signature      string `json:"signature"`
}

// Readiness is the provider's latest observation of whether players can be routed to the host.
type Readiness struct {
	Routable bool     `json:"routable"`
	Reasons  []string `json:"reasons"`
}

type ticketKey struct {
	KeyID       string `json:"keyId"`
	Secret      string `json:"secret"`
	NotBefore   int64  `json:"notBefore,omitempty"`
	RetireAfter int64  `json:"retireAfter,omitempty"`
}

type registration struct {
	Protocol            string     `json:"protocol"`
	Provider            string     `json:"provider"`
	RegistrationID      string     `json:"registrationId"`
	InstanceID          string     `json:"instanceId"`
	KeyID               string     `json:"keyId"`
	Profile             string     `json:"profile"`
	Placement           Placement  `json:"placement"`
	HeartbeatIntervalMs int64      `json:"heartbeatIntervalMs"`
	LeaseGeneration     int64      `json:"leaseGeneration"`
	LeaseDeadline       int64      `json:"leaseDeadline"`
	Readiness           Readiness  `json:"readiness"`
	ServiceID           string     `json:"serviceId,omitempty"`
	PublicAddress       string     `json:"publicAddress,omitempty"`
	TicketKey           *ticketKey `json:"ticketKey,omitempty"`
	// Extensions are optional provider metadata, such as a link to claim the service.
	Extensions map[string]extension `json:"extensions,omitempty"`
}

func (r *registration) validate(origin string) error {
	if r.Protocol != Protocol || r.Provider != origin || r.Profile != Profile || r.RegistrationID == "" ||
		r.InstanceID == "" || r.KeyID == "" || r.LeaseGeneration < 1 || (r.ServiceID == "") != (r.PublicAddress == "") {
		return errors.New("nxs: invalid registration")
	}
	return nil
}

type candidate struct {
	Foundation string `json:"foundation"`
	Component  int    `json:"component"`
	Protocol   string `json:"protocol"`
	Priority   uint32 `json:"priority"`
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	Type       string `json:"type"`
	ExpiresAt  int64  `json:"expiresAt,omitempty"`
}

type hostProfile struct {
	Candidates         []candidate `json:"candidates"`
	DTLSFingerprint    string      `json:"dtlsFingerprint"`
	CredentialKeyID    string      `json:"credentialKeyId"`
	SCTPPort           int         `json:"sctpPort"`
	MaxMessageSize     int         `json:"maxMessageSize"`
	StatelessAdmission struct {
		Capability  string `json:"capability"`
		Assisted    string `json:"assisted,omitempty"`
		Incarnation string `json:"incarnation"`
	} `json:"statelessAdmission"`
}

type playerCount struct {
	ConnectedPlayers int   `json:"connectedPlayers"`
	SampledAt        int64 `json:"sampledAt"`
}

// serverStatus is the public listing metadata of the host.
type serverStatus struct {
	Name       string `json:"name"`
	Level      string `json:"level"`
	Players    *int   `json:"players,omitempty"`
	MaxPlayers int    `json:"maxPlayers"`
	GameType   int    `json:"gameType"`
}

type heartbeatRequest struct {
	AcceptingPlayers    bool                 `json:"acceptingPlayers"`
	Capacity            int                  `json:"capacity"`
	ClockUnixMillis     int64                `json:"clockUnixMillis"`
	PlayerCount         *playerCount         `json:"playerCount,omitempty"`
	Build               string               `json:"build,omitempty"`
	ServerStatus        *serverStatus        `json:"serverStatus,omitempty"`
	GameOutcomes        string               `json:"gameOutcomes,omitempty"`
	HostProfile         *hostProfile         `json:"hostProfile,omitempty"`
	HostProfileRevision string               `json:"hostProfileRevision,omitempty"`
	InstalledKeyIDs     []string             `json:"installedKeyIds,omitempty"`
	KeyRequestID        string               `json:"keyRequestId,omitempty"`
	Extensions          map[string]extension `json:"extensions,omitempty"`
	// AppliedStateRevision acknowledges the historic desired state of the provider.
	AppliedStateRevision int64 `json:"appliedStateRevision"`
}

type checkIn struct {
	Version                 int   `json:"version"`
	AfterMillis             int64 `json:"afterMillis"`
	NextCheckInAt           int64 `json:"nextCheckInAt"`
	LeaseExpiresAt          int64 `json:"leaseExpiresAt"`
	MinUpdateIntervalMillis int64 `json:"minUpdateIntervalMillis"`
}

type heartbeatResponse struct {
	Accepted            bool      `json:"accepted"`
	ReceivedAt          string    `json:"receivedAt"`
	StaleAfter          string    `json:"staleAfter"`
	HostProfileRevision *string   `json:"hostProfileRevision"`
	ActiveKeyID         string    `json:"activeKeyId"`
	LeaseGeneration     int64     `json:"leaseGeneration"`
	Readiness           Readiness `json:"readiness"`
	Retirements         []struct {
		KeyID       string `json:"keyId"`
		RetireAfter int64  `json:"retireAfter"`
	} `json:"retirements"`
	CheckIn    *checkIn `json:"checkIn"`
	KeyRequest *struct {
		ID    string `json:"id"`
		KeyID string `json:"keyId"`
	} `json:"keyRequest"`
	TicketKey    *ticketKey           `json:"ticketKey"`
	Extensions   map[string]extension `json:"extensions"`
	DesiredState *struct {
		Revision int64  `json:"revision"`
		State    string `json:"state"`
	} `json:"desiredState"`
}

// event is an outcome observation of an admission attempt.
type event struct {
	TicketID      string `json:"ticketId"`
	Stage         string `json:"stage"`
	OccurredAt    string `json:"occurredAt"`
	Reason        string `json:"reason,omitempty"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	RemotePort    int    `json:"remotePort,omitempty"`
}

// normalizeOrigin returns the canonical form of a provider origin.
func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("nxs: parse origin: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.Hostname() == "" {
		return "", fmt.Errorf("nxs: invalid origin %q", raw)
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("nxs: origin %q must use HTTPS", raw)
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", fmt.Errorf("nxs: origin %q must use HTTPS", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return "", fmt.Errorf("nxs: invalid origin port %q", port)
		}
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// operationURL checks that an operation URL is on the origin.
func operationURL(origin, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("URL must not contain userinfo or fragment")
	}
	o, err := normalizeOrigin(u.Scheme + "://" + u.Host)
	if err != nil || o != origin {
		return nil, errors.New("URL is not on the provider origin")
	}
	return u, nil
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// marshal encodes v as JSON without HTML escaping.
func marshal(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
