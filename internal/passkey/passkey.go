// Package passkey is the WebAuthn side of identity: the options of a ceremony and the check of what the
// authenticator answered, on top of github.com/go-webauthn/webauthn. It knows nothing about sessions or
// the database: the account package stores the ceremony state and the credentials.
//
// Every ceremony asks for user verification and a discoverable (resident) credential, and takes no
// attestation, so a passkey login is a multi-factor login (something held, plus the biometric or PIN).
package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/huponx/identity/internal/store"
)

// Errors: the callers map them to a code; the cause of a refusal is logged, never shown.
var (
	// ErrInvalid is any credential that does not verify: wrong origin or RP ID, wrong challenge, no user
	// verification, a bad signature, unknown credential, a user handle that is not the credential's owner.
	ErrInvalid = errors.New("passkey: the credential is not valid")
	// ErrCloned is a sign count that did not move forward.
	ErrCloned = errors.New("passkey: the sign count went backwards")
)

// Config is the relying party.
type Config struct {
	RPID    string
	RPName  string
	Origins []string
}

// Service runs the ceremonies.
type Service struct {
	wa *webauthn.WebAuthn
}

// New validates the relying party.
func New(cfg Config) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{RPID: cfg.RPID, RPDisplayName: cfg.RPName, RPOrigins: cfg.Origins})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Service{wa: wa}, nil
}

// User adapts a user and their passkeys to webauthn.User. The user handle is the UUID bytes of the user id:
// opaque, and no e-mail address is stored in the authenticator's record beyond the account name it shows.
type User struct {
	U        *store.User
	Passkeys []store.Passkey
}

// Handle is the WebAuthn user handle of a user id.
func Handle(userID string) ([]byte, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, err
	}
	return id[:], nil
}

// UserID is the user id a handle stands for.
func UserID(handle []byte) (string, bool) {
	id, err := uuid.FromBytes(handle)
	if err != nil {
		return "", false
	}
	return id.String(), true
}

func (u User) WebAuthnID() []byte {
	h, _ := Handle(u.U.ID)
	return h
}
func (u User) WebAuthnName() string { return u.U.Email }
func (u User) WebAuthnDisplayName() string {
	if u.U.Name != "" {
		return u.U.Name
	}
	return u.U.Email
}
func (u User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Passkeys))
	for i, p := range u.Passkeys {
		out[i] = credential(p)
	}
	return out
}

func credential(p store.Passkey) webauthn.Credential {
	tr := make([]protocol.AuthenticatorTransport, len(p.Transports))
	for i, t := range p.Transports {
		tr[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID: p.CredentialID, PublicKey: p.PublicKey, AttestationType: p.AttestationType, Transport: tr,
		// the passkeys of this service were all registered with user verification
		Flags:         webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: p.BackupEligible, BackupState: p.BackupState},
		Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
	}
}

func descriptors(passkeys []store.Passkey) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, len(passkeys))
	for i, p := range passkeys {
		c := credential(p)
		out[i] = c.Descriptor()
	}
	return out
}

// Session is the state of a ceremony between its two steps (webauthn.SessionData as JSON).
type Session = webauthn.SessionData

// BeginRegistration returns the creation options (JSON for navigator.credentials.create) of a new passkey.
// The passkeys the user has are excluded, so one authenticator is not registered twice.
func (s *Service) BeginRegistration(u User) (options []byte, sd *Session, err error) {
	rk := true
	creation, sd, err := s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &rk, ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(descriptors(u.Passkeys)),
	)
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(creation)
	return options, sd, err
}

// Registered is a verified new credential.
type Registered struct {
	CredentialID, PublicKey, AAGUID []byte
	SignCount                       uint32
	Transports                      []string
	BackupEligible, BackupState     bool
	AttestationType                 string
}

// FinishRegistration verifies the answer of navigator.credentials.create (the JSON of the credential).
func (s *Service) FinishRegistration(u User, sd Session, credentialJSON []byte) (*Registered, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	c, err := s.wa.CreateCredential(u, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// the library checks UV when the session asks for it; this is the same check on the answer itself
	if !parsed.Response.AttestationObject.AuthData.Flags.HasUserVerified() {
		return nil, fmt.Errorf("%w: user verification is missing", ErrInvalid)
	}
	r := &Registered{
		CredentialID: c.ID, PublicKey: c.PublicKey, AAGUID: c.Authenticator.AAGUID, SignCount: c.Authenticator.SignCount,
		BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState, AttestationType: c.AttestationType,
	}
	for _, t := range c.Transport {
		r.Transports = append(r.Transports, string(t))
	}
	if r.AttestationType == "" {
		r.AttestationType = "none"
	}
	return r, nil
}

// BeginLogin returns the request options of a usernameless sign in: no list of credentials, the
// authenticator offers the passkeys it has for this relying party.
func (s *Service) BeginLogin() (options []byte, sd *Session, err error) {
	assertion, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(assertion)
	return options, sd, err
}

// BeginUserLogin returns the request options for a known user (the second factor after the password),
// limited to their passkeys.
func (s *Service) BeginUserLogin(u User) (options []byte, sd *Session, err error) {
	if len(u.Passkeys) == 0 {
		return nil, nil, errors.New("passkey: the user has no passkey")
	}
	assertion, sd, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(assertion)
	return options, sd, err
}

// Assertion is a verified sign in.
type Assertion struct {
	CredentialID   []byte
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
}

// Lookup finds the user and the passkeys for a credential id and user handle (the discoverable sign in).
type Lookup func(credentialID, userHandle []byte) (User, error)

// FinishLogin verifies the answer of a usernameless sign in.
func (s *Service) FinishLogin(lookup Lookup, sd Session, credentialJSON []byte) (*User, *Assertion, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var found User
	u, c, err := s.wa.ValidatePasskeyLogin(func(rawID, handle []byte) (webauthn.User, error) {
		var err error
		found, err = lookup(rawID, handle)
		return found, err
	}, sd, parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	_ = u
	a, err := assertion(parsed, c)
	return &found, a, err
}

// FinishUserLogin verifies the answer for a known user.
func (s *Service) FinishUserLogin(u User, sd Session, credentialJSON []byte) (*Assertion, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	c, err := s.wa.ValidateLogin(u, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return assertion(parsed, c)
}

func assertion(parsed *protocol.ParsedCredentialAssertionData, c *webauthn.Credential) (*Assertion, error) {
	// user verification is required by the options; check the answer itself too
	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return nil, fmt.Errorf("%w: user verification is missing", ErrInvalid)
	}
	if c.Authenticator.CloneWarning {
		return nil, ErrCloned
	}
	return &Assertion{CredentialID: c.ID, SignCount: c.Authenticator.SignCount, BackupEligible: c.Flags.BackupEligible, BackupState: c.Flags.BackupState}, nil
}

// AMR is the amr of a session started by a passkey: a synced (backup eligible) key is a software key,
// a device bound one a hardware key (RFC 8176); "mfa" says it counted as multiple factors.
func (a Assertion) AMR() []string {
	if a.BackupEligible {
		return []string{"swk", "mfa"}
	}
	return []string{"hwk", "mfa"}
}

// SessionJSON and ParseSession move the ceremony state through Redis.
func SessionJSON(sd *Session) ([]byte, error) { return json.Marshal(sd) }

// ParseSession is the reverse of SessionJSON.
func ParseSession(b []byte) (Session, error) {
	var sd Session
	err := json.Unmarshal(bytes.TrimSpace(b), &sd)
	return sd, err
}

// ValidName trims a passkey name and checks its length (1-60 characters).
func ValidName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	n := len([]rune(name))
	return name, n >= 1 && n <= 60
}
