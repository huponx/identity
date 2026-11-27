package appconfig

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/huponx/gocommon/config"
)

// roleName is the shape of a role name (the CHECK of identity_roles).
var roleName = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)

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
	// MFAIssuerName is the label shown in authenticator apps; it is also the name at the top of every e-mail.
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

	// RegistrationEnabled opens POST /auth-api/register: anybody may create an account (the welcome mail with the
	// link to set the password proves the address). Off by default, then the endpoint answers 404. There is no
	// CAPTCHA, only the rate limit per client IP and per e-mail.
	RegistrationEnabled bool `env:"IDENTITY_REGISTRATION_ENABLED" envDefault:"false"`
	// RegistrationRole is the role a self-registered account gets; it must exist (migration V36 creates "member").
	RegistrationRole string `env:"IDENTITY_REGISTRATION_ROLE" envDefault:"member"`

	// UIDir holds the built sign in app (index.html and assets/); the image has it in /ui. Outside ENV=local
	// the service does not start without it; locally the page paths answer 503 and a warning is logged.
	UIDir string `env:"IDENTITY_UI_DIR" envDefault:"/ui"`

	// PortalURL is where a user lands after signing in at identity itself (no application sent them).
	PortalURL string `env:"IDENTITY_PORTAL_URL,required"`

	// RateLimitFactor multiplies the maximum of every rate limit (login, registration, password reset, MFA), for tests that
	// repeat an action many times. Only with ENV=local: anywhere else a value above 1 stops the service from starting.
	RateLimitFactor int64 `env:"IDENTITY_RATE_LIMIT_FACTOR" envDefault:"1"`

	// AdminURL is the admin app, the mail to the users who approve registrations links to {AdminURL}/users/{id} of the applicant; empty omits the link.
	AdminURL string `env:"IDENTITY_ADMIN_URL"`

	// WebAuthnEnabled turns passkeys on; off, their endpoints answer 404 and the sign in pages hide them.
	WebAuthnEnabled bool `env:"IDENTITY_WEBAUTHN_ENABLED" envDefault:"true"`
	// WebAuthnRPID is the relying party id, a registrable suffix of every origin that runs a passkey ceremony
	// (empty: the host of the issuer). It is bound into every passkey: changing it later makes all of them unusable.
	WebAuthnRPID string `env:"IDENTITY_WEBAUTHN_RP_ID"`
	// WebAuthnRPName is the name the authenticator shows (empty: IDENTITY_MFA_ISSUER_NAME).
	WebAuthnRPName string `env:"IDENTITY_WEBAUTHN_RP_NAME"`
	// WebAuthnOrigins are the origins allowed to run a ceremony (empty: the issuer, the portal and the admin app).
	WebAuthnOrigins []string `env:"IDENTITY_WEBAUTHN_ORIGINS" envSeparator:","`
}

// origin is scheme://host of a URL, "" when it is not one.
func origin(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return ""
	}
	return p.Scheme + "://" + p.Host
}

// WebAuthnRP returns the relying party id, with its default.
func (c Identity) WebAuthnRP() string {
	if c.WebAuthnRPID != "" {
		return strings.ToLower(c.WebAuthnRPID)
	}
	if p, err := url.Parse(c.Issuer); err == nil {
		return strings.ToLower(p.Hostname())
	}
	return ""
}

// WebAuthnName returns the relying party name, with its default.
func (c Identity) WebAuthnName() string {
	if c.WebAuthnRPName != "" {
		return c.WebAuthnRPName
	}
	return c.MFAIssuerName
}

// WebAuthnOriginList returns the allowed origins, with the default (issuer, portal, admin).
func (c Identity) WebAuthnOriginList() []string {
	if len(c.WebAuthnOrigins) > 0 {
		out := make([]string, 0, len(c.WebAuthnOrigins))
		for _, o := range c.WebAuthnOrigins {
			if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
				out = append(out, o)
			}
		}
		return out
	}
	// the defaults are the origins the relying party id covers: with the default id (the issuer host) the portal
	// and the admin app, on other hosts, cannot run a ceremony, which needs IDENTITY_WEBAUTHN_RP_ID of a parent domain
	rp := c.WebAuthnRP()
	var out []string
	for _, u := range []string{c.Issuer, c.PortalURL, c.AdminURL} {
		o := origin(u)
		if o == "" {
			continue
		}
		if p, err := url.Parse(o); err == nil {
			if h := strings.ToLower(p.Hostname()); h == rp || strings.HasSuffix(h, "."+rp) {
				out = append(out, o)
			}
		}
	}
	return out
}

func (c Identity) validateWebAuthn() error {
	rp := c.WebAuthnRP()
	if rp == "" || strings.ContainsAny(rp, "/:") {
		return fmt.Errorf("IDENTITY_WEBAUTHN_RP_ID must be a domain name, got %q", rp)
	}
	origins := c.WebAuthnOriginList()
	if len(origins) == 0 {
		return fmt.Errorf("IDENTITY_WEBAUTHN_ORIGINS is empty")
	}
	for _, o := range origins {
		p, err := url.Parse(o)
		if err != nil || origin(o) != o || !c.okURL(o) {
			return fmt.Errorf("IDENTITY_WEBAUTHN_ORIGINS entries must be https origins like https://auth.example.com (http only with ENV=local), got %q", o)
		}
		if h := strings.ToLower(p.Hostname()); h != rp && !strings.HasSuffix(h, "."+rp) {
			return fmt.Errorf("IDENTITY_WEBAUTHN_RP_ID %q must be the host or a parent domain of every origin, %q is not", rp, o)
		}
	}
	return nil
}

func (c Identity) okURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return false
	}
	return p.Scheme == "https" || (c.IsLocal() && p.Scheme == "http")
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
	if c.RegistrationEnabled && !roleName.MatchString(c.RegistrationRole) {
		return fmt.Errorf("IDENTITY_REGISTRATION_ROLE must be a role name (lowercase letters, digits, _ . -), got %q", c.RegistrationRole)
	}
	if !c.okURL(c.PortalURL) {
		return fmt.Errorf("IDENTITY_PORTAL_URL must be an https URL (http only with ENV=local), got %q", c.PortalURL)
	}
	if c.RateLimitFactor < 0 || (c.RateLimitFactor > 1 && !c.IsLocal()) {
		return fmt.Errorf("IDENTITY_RATE_LIMIT_FACTOR must not be negative, and above 1 only with ENV=local, got %d", c.RateLimitFactor)
	}
	if c.AdminURL != "" && !c.okURL(c.AdminURL) {
		return fmt.Errorf("IDENTITY_ADMIN_URL must be an https URL (http only with ENV=local), got %q", c.AdminURL)
	}
	if c.SessionAbsoluteTTL < c.SessionIdleTTL {
		return fmt.Errorf("IDENTITY_SESSION_ABSOLUTE_TTL must not be shorter than IDENTITY_SESSION_IDLE_TTL")
	}
	if c.WebAuthnEnabled {
		if err := c.validateWebAuthn(); err != nil {
			return err
		}
	}
	return nil
}
