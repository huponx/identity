package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/identity/internal/password"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/store"
	"github.com/huponx/identity/internal/token"
	"go.uber.org/zap"
)

// HashSecret is the form in which client secrets are stored (they are random 256 bit values,
// so a fast hash is enough and keeps the token endpoint cheap).
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func tokenFail(c *gin.Context, e *token.Error) {
	if e.Status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", `Basic realm="identity"`)
	}
	c.JSON(e.Status, gin.H{"error": e.Code, "error_description": e.Desc})
}

func asTokenErr(err error) *token.Error {
	var te *token.Error
	if errors.As(err, &te) {
		return te
	}
	return nil
}

// authenticateClient reads client_secret_basic or client_secret_post, or the client_id of a
// public client. The secret comparison is constant time.
func (s *Server) authenticateClient(c *gin.Context) (*store.Client, *token.Error) {
	id, secret, basic := c.Request.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return nil, &token.Error{Code: "invalid_client", Desc: "malformed client credentials", Status: http.StatusUnauthorized}
		}
	} else {
		id, secret = c.PostForm("client_id"), c.PostForm("client_secret")
	}
	bad := &token.Error{Code: "invalid_client", Desc: "client authentication failed", Status: http.StatusUnauthorized}
	if id == "" {
		return nil, bad
	}
	cl, err := s.store.ClientByID(c.Request.Context(), id)
	if err != nil || cl.Disabled {
		_ = subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(HashSecret("x"))) // same work as a real check
		return nil, bad
	}
	if cl.Type == "public" {
		if secret != "" {
			return nil, bad
		}
		return cl, nil
	}
	if subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(cl.SecretHash)) != 1 {
		return nil, bad
	}
	return cl, nil
}

func (s *Server) tokenEndpoint(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	cl, terr := s.authenticateClient(c)
	if terr != nil {
		tokenFail(c, terr)
		return
	}
	grant := c.PostForm("grant_type")
	if !contains(cl.AllowedGrants, grant) {
		tokenFail(c, &token.Error{Code: "unauthorized_client", Desc: "the client may not use this grant", Status: http.StatusBadRequest})
		return
	}
	var resp gin.H
	var err error
	switch grant {
	case "authorization_code":
		resp, err = s.grantCode(c, cl)
	case "refresh_token":
		resp, err = s.grantRefresh(c, cl)
	case "client_credentials":
		resp, err = s.grantClientCredentials(c, cl)
	case tokenExchangeGrant:
		resp, err = s.grantExchange(c, cl)
	default:
		err = &token.Error{Code: "unsupported_grant_type", Desc: "unsupported grant_type", Status: http.StatusBadRequest}
	}
	if err != nil {
		if te := asTokenErr(err); te != nil {
			tokenFail(c, te)
			return
		}
		logging.FromCtx(c.Request.Context()).Error("token endpoint", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func terr(code, desc string) *token.Error {
	return &token.Error{Code: code, Desc: desc, Status: http.StatusBadRequest}
}

func (s *Server) accessTTL(cl *store.Client) time.Duration {
	if cl.AccessTokenTTL > 0 {
		return cl.AccessTokenTTL
	}
	return s.cfg.AccessTokenDefault
}

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// userTokens issues the access token (audience: the resource of the client), the ID token when
// openid was asked, and a refresh token when offline_access was asked and is allowed.
func (s *Server) userTokens(c *gin.Context, cl *store.Client, u *store.User, scope string, authTime time.Time,
	amr []string, acr, sid, nonce, familyID string, withID bool) (gin.H, error) {
	ctx := c.Request.Context()
	perms, err := s.store.UserPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	roles, err := s.store.UserRoles(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	scopes := strings.Fields(scope)
	access, claims, err := s.tokens.Access(token.AccessParams{
		Subject: u.ID, ClientID: cl.ClientID, Audience: cl.Resource, Scope: scope, Roles: roles, Perms: perms,
		AMR: amr, ACR: acr, SessionID: sid, AuthTime: authTime, TTL: s.accessTTL(cl),
	})
	if err != nil {
		return nil, err
	}
	resp := gin.H{
		"access_token": access, "token_type": "Bearer", "scope": scope,
		"expires_in": int(time.Until(claims.ExpiresAt.Time).Seconds()),
	}
	if withID && contains(scopes, "openid") {
		p := token.IDParams{Subject: u.ID, ClientID: cl.ClientID, Nonce: nonce, AccessToken: access, AMR: amr, ACR: acr, SessionID: sid, AuthTime: authTime}
		if contains(scopes, "profile") {
			p.Name = u.Name
		}
		if contains(scopes, "email") {
			p.Email = u.Email
		}
		if resp["id_token"], err = s.tokens.ID(p); err != nil {
			return nil, err
		}
	}
	if contains(scopes, "offline_access") && contains(cl.AllowedGrants, "refresh_token") {
		rt := password.Random(48)
		err := s.store.InsertRefreshToken(ctx, password.Digest(rt), store.RefreshToken{
			FamilyID: familyID, UserID: u.ID, ClientID: cl.ClientID, SessionID: sid, Scope: scope,
			AuthTime: authTime, AMR: amr, ExpiresAt: s.now().Add(s.cfg.RefreshTokenTTL),
		})
		if err != nil {
			return nil, err
		}
		resp["refresh_token"] = rt
	}
	return resp, nil
}

func (s *Server) grantCode(c *gin.Context, cl *store.Client) (gin.H, error) {
	ctx := c.Request.Context()
	ac, err := s.state.TakeCode(ctx, c.PostForm("code"))
	if errors.Is(err, state.ErrNotFound) {
		return nil, terr("invalid_grant", "the code is invalid, expired or already used")
	}
	if err != nil {
		return nil, err
	}
	if ac.ClientID != cl.ClientID || ac.RedirectURI != c.PostForm("redirect_uri") || !pkceOK(c.PostForm("code_verifier"), ac.CodeChallenge) {
		return nil, terr("invalid_grant", "the code does not match this request")
	}
	u, err := s.store.UserByID(ctx, ac.UserID)
	if err != nil || u.Disabled {
		return nil, terr("invalid_grant", "the user is not active")
	}
	resp, err := s.userTokens(c, cl, u, ac.Scope, ac.AuthTime, ac.AMR, ac.ACR, ac.SessionID, ac.Nonce, "", true)
	if err != nil {
		return nil, err
	}
	if ac.SessionID != "" {
		if err := s.state.AddSessionClient(ctx, ac.SessionID, cl.ClientID); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (s *Server) grantRefresh(c *gin.Context, cl *store.Client) (gin.H, error) {
	ctx := c.Request.Context()
	rt, err := s.store.ConsumeRefreshToken(ctx, password.Digest(c.PostForm("refresh_token")), cl.ClientID)
	switch {
	case errors.Is(err, store.ErrRefreshReused):
		logging.FromCtx(ctx).Warn("refresh token reuse: family revoked", zap.String("client_id", cl.ClientID))
		return nil, terr("invalid_grant", "the refresh token is invalid")
	case errors.Is(err, store.ErrRefreshInvalid):
		return nil, terr("invalid_grant", "the refresh token is invalid")
	case err != nil:
		return nil, err
	}
	u, err := s.store.UserByID(ctx, rt.UserID)
	if err != nil || u.Disabled {
		return nil, terr("invalid_grant", "the user is not active")
	}
	scope := rt.Scope
	if req := c.PostForm("scope"); req != "" { // may only narrow
		var kept []string
		for _, sc := range strings.Fields(req) {
			if !contains(strings.Fields(rt.Scope), sc) {
				return nil, terr("invalid_scope", "scope "+sc+" was not granted")
			}
			kept = append(kept, sc)
		}
		scope = strings.Join(kept, " ")
	}
	acr := ""
	if hasAMR(rt.AMR, "otp") {
		acr = "mfa"
	}
	// the new refresh token stays in the family (only when offline_access is still in the scope)
	return s.userTokens(c, cl, u, scope, rt.AuthTime, rt.AMR, acr, rt.SessionID, "", rt.FamilyID, true)
}

func (s *Server) grantClientCredentials(c *gin.Context, cl *store.Client) (gin.H, error) {
	ctx := c.Request.Context()
	if cl.Type != "confidential" {
		return nil, terr("unauthorized_client", "only confidential clients use client_credentials")
	}
	audience := c.PostForm("audience")
	if audience == "" {
		return nil, terr("invalid_request", "audience is required")
	}
	pol, err := s.store.ExchangePolicyFor(ctx, cl.ClientID, audience)
	if errors.Is(err, store.ErrNotFound) {
		return nil, terr("access_denied", "this client may not request tokens for this audience")
	}
	if err != nil {
		return nil, err
	}
	scope := token.NarrowScope(c.PostForm("scope"), strings.Join(cl.AllowedScopes, " "), pol.MaxScope)
	perms, err := s.store.ClientPermissions(ctx, cl.ClientID)
	if err != nil {
		return nil, err
	}
	access, claims, err := s.tokens.Access(token.AccessParams{
		Subject: cl.ClientID, ClientID: cl.ClientID, Audience: audience, Scope: scope,
		Roles: cl.Roles, Perms: token.FilterPerms(perms, audience), TTL: s.accessTTL(cl),
	})
	if err != nil {
		return nil, err
	}
	logging.FromCtx(ctx).Info("client credentials token", zap.String("client_id", cl.ClientID), zap.String("audience", audience), zap.String("jti", claims.ID))
	return gin.H{"access_token": access, "token_type": "Bearer", "scope": scope, "expires_in": int(time.Until(claims.ExpiresAt.Time).Seconds())}, nil
}

func (s *Server) grantExchange(c *gin.Context, cl *store.Client) (gin.H, error) {
	ctx := c.Request.Context()
	if cl.Type != "confidential" {
		return nil, terr("unauthorized_client", "only confidential clients exchange tokens")
	}
	res, err := s.tokens.Exchange(ctx, token.ExchangeRequest{
		Client: cl, SubjectToken: c.PostForm("subject_token"), SubjectTokenType: c.PostForm("subject_token_type"),
		RequestedType: c.PostForm("requested_token_type"), Audience: c.PostFormArray("audience"), Scope: c.PostForm("scope"),
	})
	if err != nil {
		if te := asTokenErr(err); te != nil {
			logging.FromCtx(ctx).Info("token exchange refused", zap.String("client_id", cl.ClientID), zap.String("reason", te.Code))
		}
		return nil, err
	}
	logging.FromCtx(ctx).Info("token exchange", zap.String("sub", res.Claims.Subject), zap.String("act", cl.ClientID),
		zap.String("audience", res.Claims.Audience[0]), zap.String("scope", res.Scope),
		zap.String("subject_jti", res.SubjectJTI), zap.String("jti", res.Claims.ID))
	return gin.H{
		"access_token": res.AccessToken, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type": "Bearer", "expires_in": int(res.TTL.Seconds()), "scope": res.Scope,
	}, nil
}

// ---- revoke, introspect, userinfo ----

// revoke implements RFC 7009. It answers 200 whatever the token was, so it is no oracle.
func (s *Server) revoke(c *gin.Context) {
	ctx := c.Request.Context()
	cl, terr := s.authenticateClient(c)
	if terr != nil {
		tokenFail(c, terr)
		return
	}
	raw := c.PostForm("token")
	if raw != "" {
		if strings.Count(raw, ".") == 2 { // a JWT: deny its jti until it expires
			if claims, err := s.tokens.VerifyAny(ctx, raw); err == nil && (claims.ClientID == cl.ClientID || claims.AZP == cl.ClientID) {
				_ = s.state.Deny(ctx, claims.ID, time.Until(claims.ExpiresAt.Time))
			}
		} else {
			if err := s.store.RevokeRefreshByHash(ctx, password.Digest(raw), cl.ClientID); err != nil {
				logging.FromCtx(ctx).Error("revoke refresh token", zap.Error(err))
			}
		}
	}
	c.Status(http.StatusOK)
}

// introspect implements RFC 7662 for access tokens. Only confidential clients may ask.
func (s *Server) introspect(c *gin.Context) {
	ctx := c.Request.Context()
	cl, terr := s.authenticateClient(c)
	if terr != nil {
		tokenFail(c, terr)
		return
	}
	if cl.Type != "confidential" {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	inactive := gin.H{"active": false}
	claims, err := s.tokens.VerifyAny(ctx, c.PostForm("token"))
	if err != nil || claims.Type != "access" {
		c.JSON(http.StatusOK, inactive)
		return
	}
	live, err := s.tokens.IsLive(ctx, claims)
	if err != nil {
		logging.FromCtx(ctx).Error("introspect", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if !live {
		c.JSON(http.StatusOK, inactive)
		return
	}
	out := gin.H{
		"active": true, "sub": claims.Subject, "client_id": claims.ClientID, "scope": claims.Scope, "aud": claims.Audience,
		"jti": claims.ID, "exp": claims.ExpiresAt.Unix(), "iat": claims.IssuedAt.Unix(), "iss": claims.Issuer, "token_type": "Bearer",
	}
	if claims.Act != nil {
		var chain []string
		for a := claims.Act; a != nil; a = a.Act {
			chain = append(chain, a.Subject)
		}
		out["act"] = chain
	}
	c.JSON(http.StatusOK, out)
}

// userinfo returns the claims of the user of a bearer access token that carries the openid scope.
func (s *Server) userinfo(c *gin.Context) {
	ctx := c.Request.Context()
	h := c.GetHeader("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		c.Header("WWW-Authenticate", "Bearer")
		c.Status(http.StatusUnauthorized)
		return
	}
	claims, err := s.tokens.VerifyAny(ctx, strings.TrimSpace(h[7:]))
	if err == nil && claims.Type == "access" {
		if live, lerr := s.tokens.IsLive(ctx, claims); lerr != nil || !live {
			err = errors.New("not live")
		}
	}
	if err != nil || claims.Type != "access" || !claims.HasScope("openid") || claims.Subject == claims.ClientID {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return
	}
	u, err := s.store.UserByID(ctx, claims.Subject)
	if err != nil || u.Disabled {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return
	}
	out := gin.H{"sub": u.ID}
	if claims.HasScope("profile") {
		out["name"] = u.Name
		out["locale"] = u.Locale
	}
	if claims.HasScope("email") {
		out["email"] = u.Email
	}
	c.JSON(http.StatusOK, out)
}
