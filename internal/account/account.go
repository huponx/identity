// Package account holds the account operations shared by the HTTP pages and the gRPC API:
// password login, password reset, MFA, and the revocation of sessions and tokens.
package account

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/huponx/identity/internal/appconfig"
	"github.com/huponx/identity/internal/mfa"
	"github.com/huponx/identity/internal/notify"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	"github.com/skip2/go-qrcode"
	"go.uber.org/zap"
)

// Errors the callers map to a page or a status. They never say which part of a credential was wrong.
var (
	ErrInvalidCredentials = errors.New("account: invalid credentials")
	ErrRateLimited        = errors.New("account: too many attempts")
	ErrInvalidCode        = errors.New("account: invalid code")
	ErrInvalidResetToken  = errors.New("account: invalid or expired reset token")
	ErrMFAOff             = errors.New("account: mfa is turned off on this server")
	ErrMFAEnabled         = errors.New("account: mfa is already enabled")
	ErrMFANotEnrolled     = errors.New("account: the user has not enrolled a second factor")
	ErrMFAForced          = errors.New("account: mfa is required for this user")
)

// Config is the part of the settings used here.
type Config struct {
	Issuer        string
	MFAMode       string
	MFAIssuerName string
	ResetTTL      time.Duration // default 30 minutes
	WelcomeTTL    time.Duration // validity of the set-password link of a new user, default 7 days
	// RevokeTTL is how long the per-user token cutoff is kept: longer than any access token.
	RevokeTTL time.Duration
}

// Service is the account logic.
type Service struct {
	Cfg    Config
	Store  *store.Store
	State  *state.State
	Tokens *token.Service
	Sealer *mfa.Sealer // nil when MFA is off
	Notify notify.Notifier
	Log    *zap.Logger
	HTTP   *http.Client

	wg  sync.WaitGroup
	now func() time.Time
}

// New fills the defaults.
func New(cfg Config, st *store.Store, sta *state.State, tk *token.Service, sealer *mfa.Sealer, n notify.Notifier, log *zap.Logger) *Service {
	if cfg.ResetTTL <= 0 {
		cfg.ResetTTL = 30 * time.Minute
	}
	if cfg.WelcomeTTL <= 0 {
		cfg.WelcomeTTL = 7 * 24 * time.Hour
	}
	if cfg.RevokeTTL <= 0 {
		cfg.RevokeTTL = time.Hour
	}
	if cfg.MFAMode == "" {
		cfg.MFAMode = appconfig.MFAOptional
	}
	return &Service{Cfg: cfg, Store: st, State: sta, Tokens: tk, Sealer: sealer, Notify: n, Log: log,
		HTTP: &http.Client{Timeout: 5 * time.Second}, now: time.Now}
}

// Drain waits for the background work (mails, back-channel logout) to finish (shutdown, tests).
func (s *Service) Drain() { s.wg.Wait() }

func (s *Service) background(name string, fn func(ctx context.Context) error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := fn(ctx); err != nil {
			s.Log.Warn("background task failed", zap.String("task", name), zap.Error(err))
		}
	}()
}

func mailUser(u *store.User) notify.User {
	return notify.User{ID: u.ID, Email: u.Email, Name: u.Name, Locale: u.Locale}
}

// ---- password login ----

// PasswordLogin checks the credentials. Failures are limited per client IP and per e-mail, and
// an unknown user costs as much time as a wrong password.
func (s *Service) PasswordLogin(ctx context.Context, email, pw, ip string) (*store.User, error) {
	email = store.NormalizeEmail(email)
	for _, l := range []struct {
		key string
		max int64
		win time.Duration
	}{
		{"login:ip:" + ip, 20, 5 * time.Minute},
		{"login:email:" + email, 5, 15 * time.Minute},
	} {
		ok, err := s.State.Allow(ctx, l.key, l.max, l.win)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrRateLimited
		}
	}
	u, err := s.Store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (u.PasswordHash == "" || u.Disabled)) {
		password.DummyVerify(pw)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !password.Verify(pw, u.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	_ = s.State.Reset(ctx, "login:email:"+email)
	return u, nil
}

// ---- MFA ----

// Requirement is what a login needs after the password.
type Requirement int

// Requirements.
const (
	NoMFA  Requirement = iota
	Verify             // ask for a code
	Enroll             // the user must set up a second factor first
)

// MFARequirement applies the server mode and the flags of the user.
func (s *Service) MFARequirement(u *store.User) Requirement {
	if s.Cfg.MFAMode == appconfig.MFAOff {
		return NoMFA
	}
	if u.MFAEnabled {
		return Verify
	}
	if s.Cfg.MFAMode == appconfig.MFARequired || u.MFAEnforced {
		return Enroll
	}
	return NoMFA
}

// MFAForced reports that the user cannot turn MFA off.
func (s *Service) MFAForced(u *store.User) bool {
	return s.Cfg.MFAMode == appconfig.MFARequired || u.MFAEnforced
}

// Enrollment is what the user needs to add the factor to an authenticator app.
type Enrollment struct {
	Secret string // base32
	URI    string // otpauth://
	QRData string // data:image/png;base64,...
}

// BeginEnrollment returns the pending enrollment of the user, creating it when there is none.
func (s *Service) BeginEnrollment(ctx context.Context, u *store.User) (*Enrollment, error) {
	if s.Cfg.MFAMode == appconfig.MFAOff || s.Sealer == nil {
		return nil, ErrMFAOff
	}
	if u.MFAEnabled {
		return nil, ErrMFAEnabled
	}
	// A pending enrollment is reused, so reloading the page keeps the same QR code.
	var secret []byte
	if f, sec, err := s.openFactor(ctx, u.ID); err == nil && !f.Confirmed {
		secret = sec
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if secret == nil {
		secret = mfa.NewSecret()
		sealed, err := s.Sealer.Seal(secret, u.ID)
		if err != nil {
			return nil, err
		}
		if err := s.Store.ReplaceMFAFactor(ctx, u.ID, sealed); err != nil {
			return nil, err
		}
	}
	uri := mfa.URI(s.Cfg.MFAIssuerName, u.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 224)
	if err != nil {
		return nil, err
	}
	return &Enrollment{Secret: mfa.EncodeSecret(secret), URI: uri, QRData: "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, nil
}

func (s *Service) openFactor(ctx context.Context, userID string) (*store.MFAFactor, []byte, error) {
	f, err := s.Store.MFAFactorOf(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.Sealer.Open(f.Sealed, userID)
	if err != nil {
		return nil, nil, err
	}
	if s.Sealer.NeedsReseal(f.Sealed) {
		if sealed, err := s.Sealer.Seal(secret, userID); err == nil {
			_ = s.Store.UpdateMFASealed(ctx, userID, sealed)
		}
	}
	return f, secret, nil
}

// ConfirmEnrollment checks the first code and turns MFA on. It returns the recovery codes,
// shown once.
func (s *Service) ConfirmEnrollment(ctx context.Context, u *store.User, code string) ([]string, error) {
	ok, err := s.State.Allow(ctx, "mfa:confirm:"+u.ID, 10, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRateLimited
	}
	f, secret, err := s.openFactor(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	if f.Confirmed {
		return nil, ErrMFAEnabled
	}
	step, matched := mfa.Match(secret, code, s.now())
	if !matched {
		return nil, ErrInvalidCode
	}
	codes := mfa.RecoveryCodes(10)
	hashes := make([][]byte, len(codes))
	for i, c := range codes {
		hashes[i] = password.Digest(c)
	}
	if err := s.Store.ConfirmMFAFactor(ctx, u.ID, step, hashes); err != nil {
		return nil, err
	}
	s.mailMFA(u, "enabled")
	return codes, nil
}

// VerifySecondFactor accepts a TOTP code or a recovery code. A TOTP step is accepted once.
// It reports whether a recovery code was used.
func (s *Service) VerifySecondFactor(ctx context.Context, u *store.User, code string) (recovery bool, err error) {
	if rc := mfa.NormalizeRecoveryCode(code); rc != "" { // 12 characters: never a TOTP code
		ok, err := s.Store.UseRecoveryCode(ctx, u.ID, password.Digest(rc))
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		return false, ErrInvalidCode
	}
	_, secret, err := s.openFactor(ctx, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return false, ErrInvalidCode
	}
	if err != nil {
		return false, err
	}
	step, matched := mfa.Match(secret, code, s.now())
	if !matched {
		return false, ErrInvalidCode
	}
	fresh, err := s.Store.AdvanceMFAStep(ctx, u.ID, step)
	if err != nil {
		return false, err
	}
	if !fresh {
		return false, ErrInvalidCode // the code was already used
	}
	return false, nil
}

// DisableMFA turns MFA off for the user after checking the password and a second factor.
func (s *Service) DisableMFA(ctx context.Context, u *store.User, pw, code string) error {
	if s.MFAForced(u) {
		return ErrMFAForced
	}
	if ok, err := s.State.Allow(ctx, "mfa:disable:"+u.ID, 10, 10*time.Minute); err != nil {
		return err
	} else if !ok {
		return ErrRateLimited
	}
	if !password.Verify(pw, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	if _, err := s.VerifySecondFactor(ctx, u, code); err != nil {
		return err
	}
	return s.AdminDisableMFA(ctx, u)
}

// AdminDisableMFA turns MFA off without asking the user (admin API), unless it is required.
func (s *Service) AdminDisableMFA(ctx context.Context, u *store.User) error {
	if s.MFAForced(u) {
		return ErrMFAForced
	}
	if err := s.Store.ResetMFA(ctx, u.ID); err != nil {
		return err
	}
	s.mailMFA(u, "disabled")
	return nil
}

// AdminResetMFA deletes the factor of a user who lost the device, and ends their sessions.
func (s *Service) AdminResetMFA(ctx context.Context, u *store.User) error {
	if err := s.Store.ResetMFA(ctx, u.ID); err != nil {
		return err
	}
	s.mailMFA(u, "reset")
	return s.RevokeUserAccess(ctx, u.ID)
}

// AdminEnforceMFA sets or clears the enforcement flag.
func (s *Service) AdminEnforceMFA(ctx context.Context, u *store.User, enforced bool) error {
	if err := s.Store.SetUserMFAFlags(ctx, u.ID, nil, &enforced); err != nil {
		return err
	}
	if enforced {
		s.mailMFA(u, "enforced")
	}
	return nil
}

func (s *Service) mailMFA(u *store.User, change string) {
	id := uuid.NewString()
	user := mailUser(u)
	s.background("mfa mail", func(ctx context.Context) error { return s.Notify.MFAChanged(ctx, user, change, id) })
}

// ---- password reset ----

// RequestReset starts a password reset. It never says whether the e-mail exists: the caller
// shows the same answer in every case. The mail is sent in the background so the time does
// not depend on the outcome.
func (s *Service) RequestReset(ctx context.Context, email, ip string) error {
	email = store.NormalizeEmail(email)
	for _, l := range []struct {
		key string
		max int64
	}{{"reset:ip:" + ip, 10}, {"reset:email:" + email, 3}} {
		ok, err := s.State.Allow(ctx, l.key, l.max, time.Hour)
		if err != nil {
			return err
		}
		if !ok {
			s.Log.Warn("password reset rate limited", zap.String("key", l.key))
			return nil
		}
	}
	u, err := s.Store.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Disabled) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.sendReset(ctx, u, ip)
}

// SendReset sends a reset mail to a known user (admin API).
func (s *Service) SendReset(ctx context.Context, u *store.User) error { return s.sendReset(ctx, u, "") }

// ErrNotPending is returned by SendWelcome for a user who already has a password.
var ErrNotPending = errors.New("account: the user already has a password")

// SendWelcome sends the welcome mail with a link to set the first password (admin API). It is
// for a user who has no password yet; the link lives Cfg.WelcomeTTL and replaces older links.
func (s *Service) SendWelcome(ctx context.Context, u *store.User) error {
	if u.PasswordHash != "" {
		return ErrNotPending
	}
	link, id, err := s.issueLink(ctx, u, "", s.Cfg.WelcomeTTL)
	if err != nil {
		return err
	}
	user := mailUser(u)
	ttl := s.Cfg.WelcomeTTL
	s.background("welcome mail", func(ctx context.Context) error { return s.Notify.Welcome(ctx, user, link, ttl, id) })
	return nil
}

// issueLink creates a single-use reset token valid for ttl and returns the link to the reset page.
func (s *Service) issueLink(ctx context.Context, u *store.User, ip string, ttl time.Duration) (link, id string, err error) {
	tok := password.Random(32)
	id, err = s.Store.CreatePasswordReset(ctx, u.ID, password.Digest(tok), ip, s.now().Add(ttl))
	if err != nil {
		return "", "", err
	}
	return strings.TrimRight(s.Cfg.Issuer, "/") + "/password/reset?token=" + url.QueryEscape(tok), id, nil
}

func (s *Service) sendReset(ctx context.Context, u *store.User, ip string) error {
	link, id, err := s.issueLink(ctx, u, ip, s.Cfg.ResetTTL)
	if err != nil {
		return err
	}
	user := mailUser(u)
	ttl := s.Cfg.ResetTTL
	s.background("reset mail", func(ctx context.Context) error { return s.Notify.PasswordReset(ctx, user, link, ttl, id) })
	return nil
}

// ResetTokenUser checks a reset token without consuming it (to show the form).
func (s *Service) ResetTokenUser(ctx context.Context, tok string) (*store.User, error) {
	uid, err := s.Store.PeekPasswordReset(ctx, password.Digest(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidResetToken
	}
	if err != nil {
		return nil, err
	}
	return s.Store.UserByID(ctx, uid)
}

// CompleteReset sets the new password. The token is consumed only after the policy accepted
// the password, and consuming is atomic, so two requests with one token cannot both win.
func (s *Service) CompleteReset(ctx context.Context, tok, newPassword string) error {
	u, err := s.ResetTokenUser(ctx, tok)
	if err != nil {
		return err
	}
	if err := password.Check(newPassword, u.Email, u.PasswordHash); err != nil {
		return err
	}
	if _, err := s.Store.ConsumePasswordReset(ctx, password.Digest(tok)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidResetToken
		}
		return err
	}
	return s.SetPassword(ctx, u, newPassword, false)
}

// SetPassword stores a new password and ends every session and token of the user. With
// check, the policy is applied first (admin API); the reset flow already did.
func (s *Service) SetPassword(ctx context.Context, u *store.User, newPassword string, check bool) error {
	if check {
		if err := password.Check(newPassword, u.Email, u.PasswordHash); err != nil {
			return err
		}
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.Store.SetUserPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.RevokeUserAccess(ctx, u.ID); err != nil {
		return err
	}
	user := mailUser(u)
	id := uuid.NewString()
	s.background("password changed mail", func(ctx context.Context) error { return s.Notify.PasswordChanged(ctx, user, id) })
	return nil
}

// ---- revocation ----

// EndSession ends one SSO session: deletes it, revokes its refresh tokens and sends the
// back-channel logout to the clients that used it. It returns the clients.
func (s *Service) EndSession(ctx context.Context, publicID string) (*state.Session, error) {
	sess, err := s.State.DeleteSession(ctx, publicID)
	if err != nil {
		return nil, err
	}
	if err := s.Store.RevokeRefreshBySession(ctx, publicID); err != nil {
		return nil, err
	}
	if sess != nil {
		s.backchannel(*sess)
	}
	return sess, nil
}

// RevokeUserAccess ends every session and refresh token of a user and makes the access tokens
// issued so far unusable for introspection and token exchange (services that verify locally
// stop accepting them within the access token lifetime).
func (s *Service) RevokeUserAccess(ctx context.Context, userID string) error {
	sessions, err := s.State.DeleteUserSessions(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.Store.RevokeRefreshByUser(ctx, userID); err != nil {
		return err
	}
	if err := s.State.SetCutoff(ctx, userID, s.now(), s.Cfg.RevokeTTL); err != nil {
		return err
	}
	for _, sess := range sessions {
		s.backchannel(sess)
	}
	return nil
}

// backchannel sends OpenID Connect Back-Channel Logout to every client of the session. It runs
// in the background with a few retries; a failure is logged, never fatal.
func (s *Service) backchannel(sess state.Session) {
	for _, clientID := range sess.Clients {
		clientID := clientID
		s.background("backchannel logout "+clientID, func(ctx context.Context) error {
			c, err := s.Store.ClientByID(ctx, clientID)
			if err != nil || c.BackchannelLogoutURI == "" {
				return nil
			}
			lt, err := s.Tokens.Logout(clientID, sess.UserID, sess.PublicID)
			if err != nil {
				return err
			}
			var last error
			for attempt := 0; attempt < 3; attempt++ {
				if attempt > 0 {
					select {
					case <-time.After(time.Duration(attempt) * time.Second):
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if last = s.postLogout(ctx, c.BackchannelLogoutURI, lt); last == nil {
					return nil
				}
			}
			return last
		})
	}
}

func (s *Service) postLogout(ctx context.Context, endpoint, logoutToken string) error {
	form := url.Values{"logout_token": {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
