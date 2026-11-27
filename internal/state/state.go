// Package state is the short lived data of identity in Redis: SSO sessions, authorization
// codes, MFA challenges, the token denylist, per-user token cutoffs and rate limit counters.
//
// Secrets (cookie values, codes) are never stored, only their SHA-256.
package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned for a missing, expired or already used item.
var ErrNotFound = errors.New("state: not found")

// State wraps the Redis client.
type State struct {
	rdb *redis.Client
	now func() time.Time
	// LimitFactor multiplies the maximum of every rate limit (Allow); 0 or 1 leaves them as they are. Local tests only.
	LimitFactor int64
}

// New builds a State from a redis:// URL and pings.
func New(ctx context.Context, url string) (*State, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: %w", err)
	}
	return &State{rdb: rdb, now: time.Now}, nil
}

// NewWithClient wraps an existing client (tests).
func NewWithClient(rdb *redis.Client, now func() time.Time) *State {
	if now == nil {
		now = time.Now
	}
	return &State{rdb: rdb, now: now}
}

// Ping is the readiness check.
func (s *State) Ping(ctx context.Context) error { return s.rdb.Ping(ctx).Err() }

// Close releases the client.
func (s *State) Close() error { return s.rdb.Close() }

func hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// ---- SSO sessions ----

// Session is an SSO session. The cookie value is the secret; PublicID is the "sid" of the
// tokens and the back-channel logout tokens.
type Session struct {
	PublicID  string    `json:"pid"`
	UserID    string    `json:"uid"`
	AuthTime  time.Time `json:"auth_time"`
	AMR       []string  `json:"amr"`
	CreatedAt time.Time `json:"created"`
	// Clients are the OAuth clients that received tokens through this session (for logout).
	Clients []string `json:"clients,omitempty"`
	// IP and UserAgent of the request that signed in (UserAgent cut to MaxUserAgent); LastSeen is the last read of
	// the session, written at most once per LastSeenEvery. Sessions from before they existed have none of them.
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"ua,omitempty"`
	LastSeen  time.Time `json:"seen,omitzero"`
}

// MaxUserAgent is the longest User-Agent kept.
const MaxUserAgent = 512

// LastSeenEvery is how often the last activity of a session is written.
const LastSeenEvery = time.Minute

func sessKey(cookie string) string { return "identity:sess:" + hash(cookie) }
func sidxKey(pid string) string    { return "identity:sidx:" + pid }
func usessKey(uid string) string   { return "identity:usess:" + uid }

// CreateSession stores a session and returns the cookie value. The session lives idle, and at
// most absolute from its creation.
func (s *State) CreateSession(ctx context.Context, sess Session, cookie, publicID string, idle, absolute time.Duration) error {
	sess.PublicID = publicID
	sess.CreatedAt = s.now()
	raw, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, sessKey(cookie), raw, idle)
	pipe.Set(ctx, sidxKey(publicID), hash(cookie), absolute)
	pipe.SAdd(ctx, usessKey(sess.UserID), publicID)
	pipe.Expire(ctx, usessKey(sess.UserID), absolute)
	_, err = pipe.Exec(ctx)
	return err
}

// GetSession returns the session for a cookie and slides the idle expiry. A session older
// than absolute is deleted and reported missing.
func (s *State) GetSession(ctx context.Context, cookie string, idle, absolute time.Duration) (*Session, error) {
	raw, err := s.rdb.Get(ctx, sessKey(cookie)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, err
	}
	left := absolute - s.now().Sub(sess.CreatedAt)
	if left <= 0 {
		_, _ = s.DeleteSession(ctx, sess.PublicID)
		return nil, ErrNotFound
	}
	ttl := idle
	if left < ttl {
		ttl = left
	}
	if now := s.now(); now.Sub(sess.LastSeen) >= LastSeenEvery {
		sess.LastSeen = now
		if raw, err := json.Marshal(sess); err == nil { // best effort: a missed write only makes "last active" older
			_ = s.rdb.SetArgs(ctx, sessKey(cookie), raw, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
		}
	}
	if err := s.rdb.Expire(ctx, sessKey(cookie), ttl).Err(); err != nil {
		return nil, err
	}
	return &sess, nil
}

// UpdateSession rewrites a session (amr upgrade after step-up), keeping its expiry.
func (s *State) UpdateSession(ctx context.Context, cookie string, sess Session) error {
	raw, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.rdb.SetArgs(ctx, sessKey(cookie), raw, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
}

// AddSessionClient records that a client received tokens through the session.
func (s *State) AddSessionClient(ctx context.Context, publicID, clientID string) error {
	cookieHash, err := s.rdb.Get(ctx, sidxKey(publicID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}
	key := "identity:sess:" + cookieHash
	raw, err := s.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return err
	}
	for _, c := range sess.Clients {
		if c == clientID {
			return nil
		}
	}
	sess.Clients = append(sess.Clients, clientID)
	raw, err = json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.rdb.SetArgs(ctx, key, raw, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
}

// SessionAlive reports whether the session still exists (by public id).
func (s *State) SessionAlive(ctx context.Context, publicID string) (bool, error) {
	ch, err := s.rdb.Get(ctx, sidxKey(publicID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n, err := s.rdb.Exists(ctx, "identity:sess:"+ch).Result()
	return n == 1, err
}

// DeleteSession deletes a session by public id and returns it (nil when it did not exist).
func (s *State) DeleteSession(ctx context.Context, publicID string) (*Session, error) {
	ch, err := s.rdb.Get(ctx, sidxKey(publicID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key := "identity:sess:" + ch
	raw, err := s.rdb.Get(ctx, key).Bytes()
	var sess *Session
	if err == nil {
		sess = &Session{}
		if json.Unmarshal(raw, sess) != nil {
			sess = nil
		}
	} else if !errors.Is(err, redis.Nil) {
		return nil, err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, key, sidxKey(publicID))
	if sess != nil {
		pipe.SRem(ctx, usessKey(sess.UserID), publicID)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	return sess, nil
}

// ListUserSessions returns the live sessions of a user, newest first. Members of the set whose session
// expired (idle expiry never removes them) are dropped from it.
func (s *State) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	pids, err := s.rdb.SMembers(ctx, usessKey(userID)).Result()
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, pid := range pids {
		ch, err := s.rdb.Get(ctx, sidxKey(pid)).Result()
		if err == nil {
			var raw []byte
			if raw, err = s.rdb.Get(ctx, "identity:sess:"+ch).Bytes(); err == nil {
				var sess Session
				if json.Unmarshal(raw, &sess) == nil && sess.UserID == userID {
					out = append(out, sess)
				}
				continue
			}
		}
		if !errors.Is(err, redis.Nil) {
			return nil, err
		}
		if err := s.rdb.SRem(ctx, usessKey(userID), pid).Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// IsUserSession reports whether the session (by public id) is one of the user's.
func (s *State) IsUserSession(ctx context.Context, userID, publicID string) (bool, error) {
	return s.rdb.SIsMember(ctx, usessKey(userID), publicID).Result()
}

// DeleteUserSessions deletes every session of a user and returns them.
func (s *State) DeleteUserSessions(ctx context.Context, userID string) ([]Session, error) {
	pids, err := s.rdb.SMembers(ctx, usessKey(userID)).Result()
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, pid := range pids {
		sess, err := s.DeleteSession(ctx, pid)
		if err != nil {
			return out, err
		}
		if sess != nil {
			out = append(out, *sess)
		}
	}
	return out, s.rdb.Del(ctx, usessKey(userID)).Err()
}

// ---- authorization codes ----

// AuthCode is what a code stands for.
type AuthCode struct {
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	UserID        string    `json:"user_id"`
	Scope         string    `json:"scope"`
	Nonce         string    `json:"nonce,omitempty"`
	CodeChallenge string    `json:"code_challenge"`
	AuthTime      time.Time `json:"auth_time"`
	AMR           []string  `json:"amr"`
	ACR           string    `json:"acr,omitempty"`
	SessionID     string    `json:"sid,omitempty"`
}

const codeTTL = 60 * time.Second

// SaveCode stores a code for 60 seconds.
func (s *State) SaveCode(ctx context.Context, code string, ac AuthCode) error {
	raw, err := json.Marshal(ac)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, "identity:code:"+hash(code), raw, codeTTL).Err()
}

// TakeCode returns and deletes the code in one step: a code works once.
func (s *State) TakeCode(ctx context.Context, code string) (*AuthCode, error) {
	raw, err := s.rdb.GetDel(ctx, "identity:code:"+hash(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var ac AuthCode
	if err := json.Unmarshal(raw, &ac); err != nil {
		return nil, err
	}
	return &ac, nil
}

// ---- MFA challenges ----

// Challenge is a pending second factor after a correct password (or a step-up).
type Challenge struct {
	UserID    string
	ReturnTo  string
	SessionID string // public id of the session being stepped up, "" for a login
	AMR       []string
	Attempts  int64
	// Purpose tells what the challenge is for: "" is a second factor, PurposePassword a forced
	// password change after a correct password. One kind is never accepted for the other.
	Purpose string
}

// PurposePassword is the Purpose of a pending forced password change.
const PurposePassword = "password"

const challengeTTL = 5 * time.Minute

// SaveChallenge stores a challenge under a random id for 5 minutes.
func (s *State) SaveChallenge(ctx context.Context, id string, c Challenge) error {
	key := "identity:mfa:" + hash(id)
	amr, _ := json.Marshal(c.AMR)
	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{"uid": c.UserID, "ret": c.ReturnTo, "sid": c.SessionID, "amr": string(amr), "pur": c.Purpose, "n": 0})
	pipe.Expire(ctx, key, challengeTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// Attempt counts one try on the challenge (atomically) and returns it. After max tries the
// challenge is deleted and ErrNotFound is returned, so the password must be entered again.
func (s *State) Attempt(ctx context.Context, id string, max int64) (*Challenge, error) {
	key := "identity:mfa:" + hash(id)
	n, err := s.rdb.HIncrBy(ctx, key, "n", 1).Result()
	if err != nil {
		return nil, err
	}
	m, err := s.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if n > max || m["uid"] == "" {
		_ = s.rdb.Del(ctx, key).Err()
		return nil, ErrNotFound
	}
	c := &Challenge{UserID: m["uid"], ReturnTo: m["ret"], SessionID: m["sid"], Attempts: n, Purpose: m["pur"]}
	_ = json.Unmarshal([]byte(m["amr"]), &c.AMR)
	return c, nil
}

// PeekChallenge reads a challenge without counting a try (to render the form).
func (s *State) PeekChallenge(ctx context.Context, id string) (*Challenge, error) {
	m, err := s.rdb.HGetAll(ctx, "identity:mfa:"+hash(id)).Result()
	if err != nil {
		return nil, err
	}
	if m["uid"] == "" {
		return nil, ErrNotFound
	}
	n, _ := strconv.ParseInt(m["n"], 10, 64)
	c := &Challenge{UserID: m["uid"], ReturnTo: m["ret"], SessionID: m["sid"], Attempts: n, Purpose: m["pur"]}
	_ = json.Unmarshal([]byte(m["amr"]), &c.AMR)
	return c, nil
}

// DeleteChallenge removes a challenge after success.
func (s *State) DeleteChallenge(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, "identity:mfa:"+hash(id)).Err()
}

// ---- passkey ceremonies ----

// Purposes of a passkey ceremony. A ceremony begun for one is never accepted for another.
const (
	CeremonyLogin    = "login"    // usernameless sign in
	CeremonyMFA      = "mfa"      // second factor after the password (the id is the id of the MFA challenge)
	CeremonyRegister = "register" // a new passkey of a signed in user
)

// Ceremony is the state of a WebAuthn ceremony between its two steps.
type Ceremony struct {
	Purpose string          `json:"p"`
	UserID  string          `json:"u,omitempty"` // "" for the usernameless sign in
	Data    json.RawMessage `json:"d"`           // the webauthn session data
}

func ceremonyKey(id string) string { return "identity:wa:" + hash(id) }

// SaveCeremony stores a ceremony under id for 5 minutes (a second save under the same id replaces it).
func (s *State) SaveCeremony(ctx context.Context, id string, c Ceremony) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, ceremonyKey(id), raw, challengeTTL).Err()
}

// TakeCeremony returns and deletes the ceremony in one step: an answer can be tried once, whether it
// verifies or not.
func (s *State) TakeCeremony(ctx context.Context, id string) (*Ceremony, error) {
	raw, err := s.rdb.GetDel(ctx, ceremonyKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c Ceremony
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---- denylist, cutoff, rate limit ----

// Deny puts a jti on the denylist for ttl (the remaining life of the token).
func (s *State) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	return s.rdb.Set(ctx, "identity:deny:"+jti, 1, ttl).Err()
}

// Denied reports whether the jti is on the denylist.
func (s *State) Denied(ctx context.Context, jti string) (bool, error) {
	n, err := s.rdb.Exists(ctx, "identity:deny:"+jti).Result()
	return n == 1, err
}

// SetCutoff makes every token of the user issued before t invalid for introspection and
// token exchange (password reset, account takeover response). The key lives as long as the
// longest access token can.
func (s *State) SetCutoff(ctx context.Context, userID string, t time.Time, ttl time.Duration) error {
	return s.rdb.Set(ctx, "identity:cutoff:"+userID, t.Unix(), ttl).Err()
}

// Cutoff returns the cutoff of a user (zero time when none).
func (s *State) Cutoff(ctx context.Context, userID string) (time.Time, error) {
	v, err := s.rdb.Get(ctx, "identity:cutoff:"+userID).Int64()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(v, 0), nil
}

// Allow counts one event under key and reports whether it is within max per window.
// The window starts with the first event (fixed window).
func (s *State) Allow(ctx context.Context, key string, max int64, window time.Duration) (bool, error) {
	if s.LimitFactor > 1 {
		max *= s.LimitFactor
	}
	k := "identity:rl:" + key
	pipe := s.rdb.TxPipeline()
	incr := pipe.Incr(ctx, k)
	pipe.ExpireNX(ctx, k, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	return incr.Val() <= max, nil
}

// Reset clears a counter (after a successful login).
func (s *State) Reset(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, "identity:rl:"+key).Err()
}
