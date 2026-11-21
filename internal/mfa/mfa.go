// Package mfa builds on gocommon/otp (TOTP, RFC 6238, SHA-1, 6 digits, 30 seconds) for enrollment and
// replay-safe matching, and implements the sealing of the
// secrets at rest (AES-256-GCM, rotatable keys) and recovery codes.
package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/huponx/gocommon/otp"
)

const (
	period = otp.Period
	digits = otp.Digits
	// SecretBytes is the size of a TOTP secret (160 bits, the RFC 4226 recommendation).
	SecretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random TOTP secret.
func NewSecret() []byte {
	s := make([]byte, SecretBytes)
	if _, err := rand.Read(s); err != nil {
		panic("mfa: no randomness: " + err.Error())
	}
	return s
}

// EncodeSecret is the base32 form users type into an authenticator app.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// URI is the otpauth:// URI of the enrollment (rendered as a QR code).
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{
		"secret":    {EncodeSecret(secret)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(digits)},
		"period":    {fmt.Sprint(period)},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step is the time step of t.
func Step(t time.Time) int64 { return t.Unix() / period }

// Code is the TOTP of the secret at the time step (gocommon/otp).
func Code(secret []byte, step int64) string { return otp.Code(secret, step) }

// Match checks the code against the steps now-1, now and now+1 (clock drift) and returns the
// step that matched; it is the caller's job to refuse a step it has already accepted.
func Match(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != digits {
		return 0, false
	}
	cur := Step(now)
	matched := int64(-1)
	// every step is compared, so the time does not depend on which one matched
	for _, s := range []int64{cur - 1, cur, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(Code(secret, s)), []byte(code)) == 1 {
			matched = s
		}
	}
	return matched, matched >= 0
}

// Sealer encrypts the secrets at rest with AES-256-GCM. The first key seals; every key opens.
type Sealer struct {
	keys []sealKey
}

type sealKey struct {
	id   string
	aead cipher.AEAD
}

// NewSealer parses "id:base64key" entries (key = 32 bytes, standard or URL base64).
func NewSealer(entries []string) (*Sealer, error) {
	s := &Sealer{}
	for _, e := range entries {
		id, raw, ok := strings.Cut(strings.TrimSpace(e), ":")
		if !ok || id == "" || strings.ContainsAny(id, ":") {
			return nil, errors.New("mfa: key must look like id:base64")
		}
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			if key, err = base64.RawURLEncoding.DecodeString(raw); err != nil {
				return nil, fmt.Errorf("mfa: key %s: %w", id, err)
			}
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("mfa: key %s must be 32 bytes, got %d", id, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.keys = append(s.keys, sealKey{id: id, aead: aead})
	}
	if len(s.keys) == 0 {
		return nil, errors.New("mfa: no key")
	}
	return s, nil
}

// Seal returns id | 0x00 | nonce | ciphertext. The user id is bound as additional data, so a
// sealed secret copied to another user's row does not open.
func (s *Sealer) Seal(secret []byte, userID string) ([]byte, error) {
	k := s.keys[0]
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(k.id), 0)
	out = append(out, nonce...)
	return k.aead.Seal(out, nonce, secret, []byte(userID)), nil
}

// Open reverses Seal with the key named in the data.
func (s *Sealer) Open(sealed []byte, userID string) ([]byte, error) {
	i := 0
	for i < len(sealed) && sealed[i] != 0 {
		i++
	}
	if i == len(sealed) {
		return nil, errors.New("mfa: malformed sealed secret")
	}
	id, rest := string(sealed[:i]), sealed[i+1:]
	for _, k := range s.keys {
		if k.id != id {
			continue
		}
		n := k.aead.NonceSize()
		if len(rest) < n {
			return nil, errors.New("mfa: malformed sealed secret")
		}
		return k.aead.Open(nil, rest[:n], rest[n:], []byte(userID))
	}
	return nil, fmt.Errorf("mfa: unknown key %q", id)
}

// NeedsReseal reports that the data was sealed with a key that is not the current one.
func (s *Sealer) NeedsReseal(sealed []byte) bool {
	return !strings.HasPrefix(string(sealed), s.keys[0].id+"\x00")
}

// RecoveryCodes returns n codes like "k3x9-7fqa-m2pz" (60 bits each).
func RecoveryCodes(n int) []string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			panic("mfa: no randomness: " + err.Error())
		}
		var sb strings.Builder
		for j, v := range b {
			if j > 0 && j%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(v)%len(alphabet)])
		}
		out[i] = sb.String()
	}
	return out
}

// NormalizeRecoveryCode makes user input comparable: lower case, no spaces, dashes restored.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if len(s) != 12 {
		return ""
	}
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}
