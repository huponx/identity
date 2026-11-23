package appconfig

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/huponx/gocommon/config"
)

// MFA modes of IDENTITY_MFA_MODE.
const (
	MFAOff      = "off"      // nobody is asked, MFA screens are hidden
	MFAOptional = "optional" // each user turns MFA on or off
	MFARequired = "required" // every user must use MFA
)

type Identity struct {
	config.Log
	config.Postgres
	config.Redis

	Host            string        `env:"HOST" envDefault:"0.0.0.0"`
	GRPCPort        int           `env:"PORT" envDefault:"9090"`
	HTTPPort        int           `env:"HTTP_PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	// Issuer is the public URL browsers use to reach identity (https://auth.example.com). It is
	// the iss of every token and the base of the endpoints in the discovery document.
	Issuer string `env:"IDENTITY_ISSUER,required"`
	// SigningKeyFile is the PEM private key (RSA 2048+ or ECDSA P-256) that signs tokens.
	SigningKeyFile string `env:"IDENTITY_SIGNING_KEY_FILE,required"`
	// SigningKeyID is the kid of that key.
	SigningKeyID string `env:"IDENTITY_SIGNING_KEY_ID,required"`
	// PreviousKeysDir holds the PEM files of retired keys (file name without extension is the
	// kid). They stay in the JWKS so tokens signed before a rotation keep verifying.
	PreviousKeysDir string `env:"IDENTITY_PREVIOUS_KEYS_DIR"`

	AccessTokenTTL   time.Duration `env:"IDENTITY_ACCESS_TOKEN_TTL" envDefault:"10m"`
	IDTokenTTL       time.Duration `env:"IDENTITY_ID_TOKEN_TTL" envDefault:"10m"`
	RefreshTokenTTL  time.Duration `env:"IDENTITY_REFRESH_TOKEN_TTL" envDefault:"720h"`
	ExchangeTokenTTL time.Duration `env:"IDENTITY_EXCHANGE_TOKEN_TTL" envDefault:"2m"`

	// SessionIdleTTL and SessionAbsoluteTTL bound the SSO session cookie.
	SessionIdleTTL     time.Duration `env:"IDENTITY_SESSION_IDLE_TTL" envDefault:"8h"`
	SessionAbsoluteTTL time.Duration `env:"IDENTITY_SESSION_ABSOLUTE_TTL" envDefault:"168h"`

	MFAMode string `env:"IDENTITY_MFA_MODE" envDefault:"optional"`
	// MFAKeys seal the TOTP secrets: "id:base64key" (32 bytes), comma separated, the first one
	// seals new secrets, the others only open old ones (key rotation).
	MFAKeys []string `env:"IDENTITY_MFA_KEY" envSeparator:","`
	// MFAIssuerName is the label shown in authenticator apps.
	MFAIssuerName string `env:"IDENTITY_MFA_ISSUER_NAME" envDefault:"Example"`

	// AuthAudience is the aud of the tokens allowed to call the gRPC API.
	AuthAudience string `env:"IDENTITY_AUTH_AUDIENCE" envDefault:"identity"`
	// S2SToken is an optional static Bearer token for the gRPC API, read only when ENV=local.
	S2SToken string `env:"IDENTITY_S2S_TOKEN"`

	// CourierTarget is the courier gRPC address; empty disables e-mails (the links are logged
	// when ENV=local). CourierTokenFile is the projected ServiceAccount token (audience
	// courier); CourierToken is a static token for local runs.
	CourierTarget    string `env:"COURIER_TARGET"`
	CourierTokenFile string `env:"COURIER_TOKEN_FILE"`
	CourierToken     string `env:"COURIER_S2S_TOKEN"`

	// TrustedProxies are the CIDRs of the proxies whose forwarded client address is believed
	// (the ingress controller). Empty: the connection address is used, which is safe but makes the
	// per-IP rate limits count the ingress as one client.
	TrustedProxies []string `env:"IDENTITY_TRUSTED_PROXIES" envSeparator:","`

	// UIDir holds the built sign in app (index.html and assets/); the image has it in /ui. Outside ENV=local
	// the service does not start without it; locally the page paths answer 503 and a warning is logged.
	UIDir string `env:"IDENTITY_UI_DIR" envDefault:"/ui"`

	// Apps are the applications listed on /apps, the page a user lands on after signing in at identity itself
	// (no application sent them): "Name=https://url" entries, comma separated, each with an optional icon
	// "Name=https://url|https://icon.example/logo.svg".
	Apps []string `env:"IDENTITY_APPS" envSeparator:","`
}

// AppLink is an application of the /apps page.
type AppLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon,omitempty"`
}

// IconOrigins are the origins the sign in pages may load the icons from (the img-src of the CSP).
func IconOrigins(apps []AppLink) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range apps {
		if a.Icon == "" {
			continue
		}
		u, err := url.Parse(a.Icon)
		if err != nil {
			continue
		}
		if o := u.Scheme + "://" + u.Host; !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

func (c Identity) okURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return false
	}
	return p.Scheme == "https" || (c.IsLocal() && p.Scheme == "http")
}

// AppLinks parses IDENTITY_APPS.
func (c Identity) AppLinks() ([]AppLink, error) {
	var out []AppLink
	for _, e := range c.Apps {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		name, u, ok := strings.Cut(e, "=")
		u, icon, _ := strings.Cut(u, "|")
		name, u, icon = strings.TrimSpace(name), strings.TrimSpace(u), strings.TrimSpace(icon)
		if !ok || name == "" || !c.okURL(u) || (icon != "" && !c.okURL(icon)) {
			return nil, fmt.Errorf("IDENTITY_APPS entries are Name=https://url or Name=https://url|https://icon (http only with ENV=local), got %q", e)
		}
		out = append(out, AppLink{Name: name, URL: u, Icon: icon})
	}
	return out, nil
}

// Setup is the configuration of identity-setup (the initial setup Job): only the database.
type Setup struct {
	config.Postgres
}

func (c Identity) GRPCAddr() string { return fmt.Sprintf("%s:%d", c.Host, c.GRPCPort) }
func (c Identity) HTTPAddr() string { return fmt.Sprintf("%s:%d", c.Host, c.HTTPPort) }

// IsLocal reports a local development run (cookies without Secure over http, static token, logs links).
func (c Identity) IsLocal() bool { return strings.EqualFold(c.Env, "local") }

// Validate rejects settings that would start the service unsafely.
func (c Identity) Validate() error {
	if err := config.ValidatePort(c.GRPCPort); err != nil {
		return err
	}
	if err := config.ValidatePort(c.HTTPPort); err != nil {
		return err
	}
	switch c.MFAMode {
	case MFAOff, MFAOptional, MFARequired:
	default:
		return fmt.Errorf("IDENTITY_MFA_MODE must be off, optional or required, got %q", c.MFAMode)
	}
	if c.MFAMode != MFAOff && len(c.MFAKeys) == 0 {
		return fmt.Errorf("IDENTITY_MFA_KEY is required unless IDENTITY_MFA_MODE=off")
	}
	if !c.IsLocal() && !strings.HasPrefix(c.Issuer, "https://") {
		return fmt.Errorf("IDENTITY_ISSUER must be https outside ENV=local")
	}
	if _, err := c.AppLinks(); err != nil {
		return err
	}
	if c.SessionAbsoluteTTL < c.SessionIdleTTL {
		return fmt.Errorf("IDENTITY_SESSION_ABSOLUTE_TTL must not be shorter than IDENTITY_SESSION_IDLE_TTL")
	}
	return nil
}
