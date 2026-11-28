package oauth

import (
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

// mfaDone reports that the session passed a second factor: a TOTP or recovery code ("otp") or a passkey with user
// verification ("mfa", next to "swk" or "hwk"). acr=mfa is derived from it.
func mfaDone(amr []string) bool { return hasAMR(amr, "otp") || hasAMR(amr, "mfa") }

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
		s.errorPage(c, "unknown_client")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !contains(client.RedirectURIs, redirectURI) {
		s.errorPage(c, "bad_redirect")
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
	req, err := s.acct.MFARequirement(ctx, user)
	if err != nil {
		s.fail(c, err)
		return
	}
	needOTP := (req != account.NoMFA || wantMFA) && !mfaDone(sess.AMR)
	if needOTP {
		if prompt == "none" {
			fail("interaction_required", "")
			return
		}
		ret := "/oauth2/authorize?" + q.Encode()
		// a user with a second factor (a TOTP device or a passkey) is asked for it; one without is sent to enroll
		totp, passkeys, err := s.acct.MFAMethods(ctx, user)
		if err != nil {
			s.fail(c, err)
			return
		}
		if req == account.Verify || totp || passkeys {
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
	if mfaDone(sess.AMR) {
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
	s.errorPage(c, "internal")
}

// continueLogin runs the steps after the password: the second factor, then the session. It returns the
// address the browser goes to next.
func (s *Server) continueLogin(c *gin.Context, user *store.User, ret string) (string, error) {
	ctx := c.Request.Context()
	req, err := s.acct.MFARequirement(ctx, user)
	if err != nil {
		return "", err
	}
	switch req {
	case account.Verify:
		id := password.Random(24)
		if err := s.state.SaveChallenge(ctx, id, state.Challenge{UserID: user.ID, ReturnTo: ret, AMR: []string{"pwd"}}); err != nil {
			return "", err
		}
		return "/login/mfa?c=" + url.QueryEscape(id), nil
	case account.Enroll:
		if err := s.startSession(c, user.ID, []string{"pwd"}); err != nil {
			return "", err
		}
		return "/account/mfa?return_to=" + url.QueryEscape(ret), nil
	default:
		if err := s.startSession(c, user.ID, []string{"pwd"}); err != nil {
			return "", err
		}
		return ret, nil
	}
}

// startSession creates an SSO session and sets its cookie.
func (s *Server) startSession(c *gin.Context, userID string, amr []string) error {
	cookie := password.Random(32)
	ua := c.GetHeader("User-Agent")
	if len(ua) > state.MaxUserAgent {
		ua = strings.ToValidUTF8(ua[:state.MaxUserAgent], "")
	}
	err := s.state.CreateSession(c.Request.Context(),
		state.Session{UserID: userID, AuthTime: s.now(), AMR: amr, IP: c.ClientIP(), UserAgent: ua, LastSeen: s.now()},
		cookie, password.Random(18), s.cfg.SessionIdle, s.cfg.SessionAbsolute)
	if err != nil {
		return err
	}
	s.setCookie(c, "sid", cookie, int(s.cfg.SessionAbsolute.Seconds()))
	// every completed sign in passes here (password, password + second factor, enrollment); a failure
	// to record it must not stop the sign in
	if err := s.store.TouchLogin(c.Request.Context(), userID); err != nil {
		s.log.Warn("could not record the sign in", zap.String("user_id", userID), zap.Error(err))
	}
	return nil
}

// upgradeSession adds the methods of a second factor to the current session ("otp"; "swk" or "hwk" and "mfa" for a passkey).
func (s *Server) upgradeSession(c *gin.Context, methods ...string) error {
	cookie := s.cookie(c, "sid")
	sess, err := s.state.GetSession(c.Request.Context(), cookie, s.cfg.SessionIdle, s.cfg.SessionAbsolute)
	if err != nil {
		return err
	}
	for _, m := range methods {
		if !hasAMR(sess.AMR, m) {
			sess.AMR = append(sess.AMR, m)
		}
	}
	return s.state.UpdateSession(c.Request.Context(), cookie, *sess)
}
