package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
)

// The passkey (WebAuthn) endpoints of the sign in app. The options and the credential travel as the JSON
// the browser API uses (navigator.credentials.create and get); the ceremony state stays in Redis, under the
// id `c` the app sends back, and works once.

// passkeyAvailable answers 404 when passkeys are turned off.
func (s *Server) passkeyAvailable(c *gin.Context) bool {
	if !s.acct.PasskeysEnabled() {
		s.apiError(c, http.StatusNotFound, "not_found")
		return false
	}
	return true
}

// passkeyErr maps the errors of the account methods; it returns false when err is nil.
func (s *Server) passkeyErr(c *gin.Context, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, account.ErrPasskeyOff):
		s.apiError(c, http.StatusNotFound, "not_found")
	case errors.Is(err, account.ErrRateLimited):
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, account.ErrPasskeyInvalid):
		s.apiError(c, http.StatusUnauthorized, "invalid_passkey")
	case errors.Is(err, account.ErrInvalidCredentials):
		s.apiError(c, http.StatusUnauthorized, "invalid_password")
	case errors.Is(err, account.ErrPasskeyLimit):
		s.apiError(c, http.StatusConflict, "passkey_limit")
	case errors.Is(err, account.ErrPasskeyName):
		s.apiError(c, http.StatusBadRequest, "invalid_passkey_name")
	case errors.Is(err, account.ErrPasskeyNotFound):
		s.apiError(c, http.StatusNotFound, "passkey_not_found")
	default:
		s.apiFail(c, err)
	}
	return true
}

// ---- sign in with a passkey (no e-mail, no password, no second step) ----

func (s *Server) apiPasskeyLoginBegin(c *gin.Context) {
	if !s.passkeyAvailable(c) {
		return
	}
	var req csrfBody
	if !s.readJSON(c, &req) {
		return
	}
	id, options, err := s.acct.PasskeyLoginBegin(c.Request.Context(), c.ClientIP())
	if s.passkeyErr(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"c": id, "options": json.RawMessage(options)})
}

func (s *Server) apiPasskeyLoginFinish(c *gin.Context) {
	if !s.passkeyAvailable(c) {
		return
	}
	var req struct {
		csrfBody
		C          string          `json:"c"`
		Credential json.RawMessage `json:"credential"`
		ReturnTo   string          `json:"return_to"`
		Theme      string          `json:"theme"`
		Locale     string          `json:"locale"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	user, a, err := s.acct.PasskeyLoginFinish(c.Request.Context(), req.C, req.Credential, c.ClientIP())
	if s.passkeyErr(c, err) {
		return
	}
	if user.MustChangePassword { // somebody else set the password: it is changed first, at the password sign in
		s.apiError(c, http.StatusUnauthorized, "invalid_passkey")
		return
	}
	s.keepPreferences(c, user, req.Theme, req.Locale)
	s.endOldSession(c)
	// the passkey with user verification counts as the second factor: amr carries "mfa", so acr=mfa
	if err := s.startSession(c, user.ID, a.AMR()); err != nil {
		s.apiFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"redirect": s.safeReturn(req.ReturnTo), "theme": user.Theme, "locale": user.Locale})
}

// ---- passkey as the second factor after the password ----

func (s *Server) apiMFAPasskeyBegin(c *gin.Context) {
	if !s.passkeyAvailable(c) {
		return
	}
	ctx := c.Request.Context()
	var req struct {
		csrfBody
		C string `json:"c"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	ch, err := s.state.PeekChallenge(ctx, req.C)
	if err != nil || ch.Purpose != "" {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	options, err := s.acct.PasskeyMFABegin(ctx, user, req.C)
	if errors.Is(err, account.ErrPasskeyNotFound) { // the user has no passkey: nothing to ask for
		s.apiError(c, http.StatusUnauthorized, "invalid_passkey")
		return
	}
	if s.passkeyErr(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"options": json.RawMessage(options)})
}

func (s *Server) apiMFAPasskeyFinish(c *gin.Context) {
	if !s.passkeyAvailable(c) {
		return
	}
	ctx := c.Request.Context()
	var req struct {
		csrfBody
		C          string          `json:"c"`
		Credential json.RawMessage `json:"credential"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	// the same counter of tries as the code: 5 per challenge
	ch, err := s.state.Attempt(ctx, req.C, 5)
	if err == nil && ch.Purpose != "" {
		err = state.ErrNotFound
	}
	if errors.Is(err, state.ErrNotFound) {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if err != nil {
		s.apiFail(c, err)
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled {
		s.apiError(c, http.StatusUnauthorized, "challenge_expired")
		return
	}
	if ok, err := s.state.Allow(ctx, "mfa:user:"+user.ID, 15, 10*time.Minute); err != nil {
		s.apiFail(c, err)
		return
	} else if !ok {
		s.apiError(c, http.StatusTooManyRequests, "rate_limited")
		return
	}
	a, err := s.acct.PasskeyMFAFinish(ctx, user, req.C, req.Credential, c.ClientIP())
	if s.passkeyErr(c, err) {
		return
	}
	_ = s.state.DeleteChallenge(ctx, req.C)
	s.finishMFA(c, user, ch, a.AMR())
}

// ---- the passkeys of the signed in user ----

// passkeySession returns the signed in user, or answers 404 (passkeys off) or 401 (no session).
func (s *Server) passkeySession(c *gin.Context) (*store.User, bool) {
	if !s.passkeyAvailable(c) {
		return nil, false
	}
	_, user, _ := s.sessionFrom(c)
	if user == nil {
		s.apiError(c, http.StatusUnauthorized, "unauthenticated")
		return nil, false
	}
	return user, true
}

func passkeyJSON(p store.Passkey) gin.H {
	h := gin.H{"id": p.ID, "name": p.Name, "createdAt": p.CreatedAt.UTC().Format(time.RFC3339), "synced": p.BackupEligible}
	if p.LastUsedAt != nil {
		h["lastUsedAt"] = p.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return h
}

func (s *Server) apiPasskeyList(c *gin.Context) {
	user, ok := s.passkeySession(c)
	if !ok {
		return
	}
	list, err := s.acct.ListPasskeys(c.Request.Context(), user)
	if s.passkeyErr(c, err) {
		return
	}
	out := make([]gin.H, len(list))
	for i, p := range list {
		out[i] = passkeyJSON(p)
	}
	c.JSON(http.StatusOK, gin.H{"passkeys": out, "max": account.MaxPasskeys})
}

func (s *Server) apiPasskeyAddBegin(c *gin.Context) {
	user, ok := s.passkeySession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		Password string `json:"password"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	id, options, err := s.acct.PasskeyRegisterBegin(c.Request.Context(), user, req.Password)
	if s.passkeyErr(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"c": id, "options": json.RawMessage(options)})
}

func (s *Server) apiPasskeyAddFinish(c *gin.Context) {
	user, ok := s.passkeySession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		C          string          `json:"c"`
		Credential json.RawMessage `json:"credential"`
		Name       string          `json:"name"`
		ReturnTo   string          `json:"return_to"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	p, err := s.acct.PasskeyRegisterFinish(c.Request.Context(), user, req.C, req.Credential, req.Name)
	if s.passkeyErr(c, err) {
		return
	}
	// The first second factor of a user is an enrollment: they just proved the password and, with the user verification
	// of the registration, the key, like a confirmed TOTP device, and that makes this session multi-factor (else a user
	// who had to enroll would be asked for the key they just made). Another passkey of a user who has a factor already
	// proves nothing new: a password session that adds its own key must not become multi-factor.
	if n, err := s.store.CountPasskeys(c.Request.Context(), user.ID); err != nil {
		s.apiFail(c, err)
		return
	} else if n == 1 && !user.MFAEnabled {
		methods := []string{"hwk", "mfa"}
		if p.BackupEligible {
			methods = []string{"swk", "mfa"}
		}
		if err := s.upgradeSession(c, methods...); err != nil {
			s.apiFail(c, err)
			return
		}
	}
	out := passkeyJSON(*p)
	out["redirect"] = s.safeReturn(req.ReturnTo)
	c.JSON(http.StatusOK, out)
}

func (s *Server) apiPasskeyRename(c *gin.Context) {
	user, ok := s.passkeySession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		Name string `json:"name"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	if s.passkeyErr(c, s.acct.RenamePasskey(c.Request.Context(), user, c.Param("id"), req.Name)) {
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) apiPasskeyDelete(c *gin.Context) {
	user, ok := s.passkeySession(c)
	if !ok {
		return
	}
	var req struct {
		csrfBody
		Password string `json:"password"`
	}
	if !s.readJSON(c, &req) {
		return
	}
	if s.passkeyErr(c, s.acct.DeletePasskey(c.Request.Context(), user, c.Param("id"), req.Password)) {
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
