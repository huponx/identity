package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/account"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"go.uber.org/zap"
)

const tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"

func (s *Server) discovery(c *gin.Context) {
	iss := s.cfg.Issuer
	doc := gin.H{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/authorize",
		"token_endpoint":                        iss + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"revocation_endpoint":                   iss + "/oauth2/revoke",
		"introspection_endpoint":                iss + "/oauth2/introspect",
		"end_session_endpoint":                  iss + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", tokenExchangeGrant},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{s.keys.Signer.Alg()},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "jti", "auth_time", "nonce", "at_hash", "sid", "amr", "acr", "name", "email"},
		"prompt_values_supported":               []string{"none", "login"},
		"acr_values_supported":                  []string{"mfa"},
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,
	}
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, doc)
}

func (s *Server) jwks(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300")
	c.Data(http.StatusOK, "application/json", s.keys.JWKS)
}

// sessionFrom returns the SSO session and its user, or nil when there is none (or the user is
// gone or disabled, in which case the session is ended).
func (s *Server) sessionFrom(c *gin.Context) (*state.Session, *store.User, string) {
	cookie := s.cookie(c, "sid")
	if cookie == "" {
		return nil, nil, ""
	}
	ctx := c.Request.Context()
	sess, err := s.state.GetSession(ctx, cookie, s.cfg.SessionIdle, s.cfg.SessionAbsolute)
	if err != nil {
		return nil, nil, cookie
	}
	u, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil || u.Disabled {
		_, _ = s.acct.EndSession(ctx, sess.PublicID)
		return nil, nil, cookie
	}
	return sess, u, cookie
}

func hasAMR(amr []string, m string) bool {
	for _, v := range amr {
		if v == m {
			return true
		}
	}
	return false
}

// redirectErr sends an authorization error back to the client (only after redirect_uri was
// validated against the client).
func redirectErr(c *gin.Context, redirectURI, state, code, desc, iss string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", iss)
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) authorize(c *gin.Context) {
	ctx := c.Request.Context()
	q := c.Request.URL.Query()

	// 1. client and redirect_uri: until both are trusted nothing is redirected
	client, err := s.store.ClientByID(ctx, q.Get("client_id"))
	if err != nil || client.Disabled {
		s.errorPage(c, http.StatusBadRequest, "Unknown application.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !contains(client.RedirectURIs, redirectURI) {
		s.errorPage(c, http.StatusBadRequest, "The redirect address is not registered for this application.")
		return
	}
	stateParam := q.Get("state")
	iss := s.cfg.Issuer
	fail := func(code, desc string) { redirectErr(c, redirectURI, stateParam, code, desc, iss) }

	// 2. request parameters
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only the code flow is supported")
		return
	}
	if !contains(client.AllowedGrants, "authorization_code") {
		fail("unauthorized_client", "the application may not use the code flow")
		return
	}
	if stateParam == "" {
		fail("invalid_request", "state is required")
		return
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || len(challenge) < 43 || len(challenge) > 128 {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	scope := strings.Fields(q.Get("scope"))
	if len(scope) == 0 {
		scope = []string{"openid"}
	}
	for _, sc := range scope {
		if !contains(client.AllowedScopes, sc) {
			fail("invalid_scope", "scope "+sc+" is not allowed for this application")
			return
		}
	}
	prompt := q.Get("prompt")
	if prompt != "" && prompt != "none" && prompt != "login" {
		fail("invalid_request", "unsupported prompt")
		return
	}
	var maxAge time.Duration
	if v := q.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			fail("invalid_request", "max_age must be a number of seconds")
			return
		}
		maxAge = time.Duration(n) * time.Second
	}
	wantMFA := contains(strings.Fields(q.Get("acr_values")), "mfa")
	if wantMFA && s.cfg.MFAMode == "off" {
		fail("unmet_authentication_requirements", "multi-factor authentication is not available")
		return
	}

	// 3. who is signing in
	sess, user, _ := s.sessionFrom(c)
	needLogin := sess == nil || (user != nil && user.MustChangePassword) || prompt == "login" || (maxAge > 0 && s.now().Sub(sess.AuthTime) > maxAge)
	if needLogin {
		if prompt == "none" {
			fail("login_required", "")
			return
		}
		// prompt=login must not loop: after the login the request continues without it
		back := cloneQuery(q)
		back.Del("prompt")
		c.Redirect(http.StatusFound, "/login?return_to="+url.QueryEscape("/oauth2/authorize?"+back.Encode()))
		return
	}

	// 4. second factor
	req := s.acct.MFARequirement(user)
	needOTP := (req != account.NoMFA || wantMFA) && !hasAMR(sess.AMR, "otp")
	if needOTP {
		if prompt == "none" {
			fail("interaction_required", "")
			return
		}
		ret := "/oauth2/authorize?" + q.Encode()
		if user.MFAEnabled {
			id := password.Random(24)
			if err := s.state.SaveChallenge(ctx, id, state.Challenge{UserID: user.ID, ReturnTo: ret, SessionID: sess.PublicID, AMR: sess.AMR}); err != nil {
				s.fail(c, err)
				return
			}
			c.Redirect(http.StatusFound, "/login/mfa?c="+url.QueryEscape(id))
			return
		}
		c.Redirect(http.StatusFound, "/account/mfa?return_to="+url.QueryEscape(ret))
		return
	}

	// 5. issue the code
	code := password.Random(32)
	acr := ""
	if hasAMR(sess.AMR, "otp") {
		acr = "mfa"
	}
	if err := s.state.SaveCode(ctx, code, state.AuthCode{
		ClientID: client.ClientID, RedirectURI: redirectURI, UserID: user.ID, Scope: strings.Join(scope, " "),
		Nonce: q.Get("nonce"), CodeChallenge: challenge, AuthTime: sess.AuthTime, AMR: sess.AMR, ACR: acr, SessionID: sess.PublicID,
	}); err != nil {
		s.fail(c, err)
		return
	}
	u, _ := url.Parse(redirectURI)
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", stateParam)
	rq.Set("iss", iss)
	u.RawQuery = rq.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func cloneQuery(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func (s *Server) fail(c *gin.Context, err error) {
	logging.FromCtx(c.Request.Context()).Error("request failed", zap.Error(err))
	s.errorPage(c, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

// ---- login ----

func (s *Server) loginForm(c *gin.Context) {
	s.render(c, http.StatusOK, "login", page{Title: "Sign in", CSRF: s.csrfToken(c), ReturnTo: safeReturn(c.Query("return_to")), Fields: map[string]string{}})
}

func (s *Server) loginSubmit(c *gin.Context) {
	ctx := c.Request.Context()
	ret := safeReturn(c.PostForm("return_to"))
	form := func(status int, msg string, email string) {
		s.render(c, status, "login", page{Title: "Sign in", Message: msg, CSRF: s.csrfToken(c), ReturnTo: ret, Fields: map[string]string{"email": email}})
	}
	if !s.csrfOK(c) {
		form(http.StatusForbidden, "The form expired. Please try again.", "")
		return
	}
	email := c.PostForm("email")
	user, err := s.acct.PasswordLogin(ctx, email, c.PostForm("password"), c.ClientIP())
	switch {
	case errors.Is(err, account.ErrRateLimited):
		form(http.StatusTooManyRequests, "Too many attempts. Please wait a few minutes.", email)
		return
	case errors.Is(err, account.ErrInvalidCredentials):
		form(http.StatusUnauthorized, "Wrong e-mail or password.", email)
		return
	case err != nil:
		s.fail(c, err)
		return
	}

	// a login always starts a new session (no session fixation)
	if _, _, old := s.sessionFrom(c); old != "" {
		if sess, err := s.state.GetSession(ctx, old, s.cfg.SessionIdle, s.cfg.SessionAbsolute); err == nil {
			_, _ = s.acct.EndSession(ctx, sess.PublicID)
		}
	}

	if user.MustChangePassword {
		// the password was set by somebody else: no session until the user chose their own
		id := password.Random(24)
		if err := s.state.SaveChallenge(ctx, id, state.Challenge{UserID: user.ID, ReturnTo: ret, Purpose: state.PurposePassword}); err != nil {
			s.fail(c, err)
			return
		}
		c.Redirect(http.StatusSeeOther, "/login/password?c="+url.QueryEscape(id))
		return
	}
	s.continueLogin(c, user, ret)
}

// continueLogin runs the steps after the password: the second factor, then the session.
func (s *Server) continueLogin(c *gin.Context, user *store.User, ret string) {
	ctx := c.Request.Context()
	switch s.acct.MFARequirement(user) {
	case account.Verify:
		id := password.Random(24)
		if err := s.state.SaveChallenge(ctx, id, state.Challenge{UserID: user.ID, ReturnTo: ret, AMR: []string{"pwd"}}); err != nil {
			s.fail(c, err)
			return
		}
		c.Redirect(http.StatusSeeOther, "/login/mfa?c="+url.QueryEscape(id))
	case account.Enroll:
		if err := s.startSession(c, user.ID, []string{"pwd"}); err != nil {
			s.fail(c, err)
			return
		}
		c.Redirect(http.StatusSeeOther, "/account/mfa?return_to="+url.QueryEscape(ret))
	default:
		if err := s.startSession(c, user.ID, []string{"pwd"}); err != nil {
			s.fail(c, err)
			return
		}
		c.Redirect(http.StatusSeeOther, ret)
	}
}

// startSession creates an SSO session and sets its cookie.
func (s *Server) startSession(c *gin.Context, userID string, amr []string) error {
	cookie := password.Random(32)
	err := s.state.CreateSession(c.Request.Context(), state.Session{UserID: userID, AuthTime: s.now(), AMR: amr},
		cookie, password.Random(18), s.cfg.SessionIdle, s.cfg.SessionAbsolute)
	if err != nil {
		return err
	}
	s.setCookie(c, "sid", cookie, int(s.cfg.SessionAbsolute.Seconds()))
	return nil
}

// ---- second factor at login ----

func (s *Server) mfaForm(c *gin.Context) {
	id := c.Query("c")
	if ch, err := s.state.PeekChallenge(c.Request.Context(), id); err != nil || ch.Purpose != "" {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	s.render(c, http.StatusOK, "mfa", page{Title: "Verification", CSRF: s.csrfToken(c), Fields: map[string]string{"c": id}})
}

func (s *Server) mfaSubmit(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.PostForm("c")
	again := func(status int, msg string) {
		s.render(c, status, "mfa", page{Title: "Verification", Message: msg, CSRF: s.csrfToken(c), Fields: map[string]string{"c": id}})
	}
	if !s.csrfOK(c) {
		again(http.StatusForbidden, "The form expired. Please try again.")
		return
	}
	ch, err := s.state.Attempt(ctx, id, 5)
	if err == nil && ch.Purpose != "" { // a password change challenge is not a second factor
		err = state.ErrNotFound
	}
	if errors.Is(err, state.ErrNotFound) {
		s.render(c, http.StatusUnauthorized, "login", page{Title: "Sign in", Message: "Too many wrong codes or the request expired. Please sign in again.",
			CSRF: s.csrfToken(c), ReturnTo: "/account/mfa", Fields: map[string]string{}})
		return
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	user, err := s.store.UserByID(ctx, ch.UserID)
	if err != nil || user.Disabled {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	if ok, err := s.state.Allow(ctx, "mfa:user:"+user.ID, 15, 10*time.Minute); err != nil {
		s.fail(c, err)
		return
	} else if !ok {
		again(http.StatusTooManyRequests, "Too many attempts. Please wait a few minutes.")
		return
	}
	if _, err := s.acct.VerifySecondFactor(ctx, user, c.PostForm("code")); err != nil {
		if errors.Is(err, account.ErrInvalidCode) {
			again(http.StatusUnauthorized, "Wrong code.")
			return
		}
		s.fail(c, err)
		return
	}
	_ = s.state.DeleteChallenge(ctx, id)

	if ch.SessionID == "" { // login: the session is created now, after both factors
		if err := s.startSession(c, user.ID, []string{"pwd", "otp"}); err != nil {
			s.fail(c, err)
			return
		}
		c.Redirect(http.StatusSeeOther, safeReturn(ch.ReturnTo))
		return
	}
	// step-up of the current session
	if err := s.upgradeSession(c); err != nil {
		s.fail(c, err)
		return
	}
	c.Redirect(http.StatusSeeOther, safeReturn(ch.ReturnTo))
}

// upgradeSession adds the otp method to the current session.
func (s *Server) upgradeSession(c *gin.Context) error {
	cookie := s.cookie(c, "sid")
	sess, err := s.state.GetSession(c.Request.Context(), cookie, s.cfg.SessionIdle, s.cfg.SessionAbsolute)
	if err != nil {
		return err
	}
	if !hasAMR(sess.AMR, "otp") {
		sess.AMR = append(sess.AMR, "otp")
	}
	return s.state.UpdateSession(c.Request.Context(), cookie, *sess)
}
