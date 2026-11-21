// Package password hashes and checks user passwords (argon2id) and applies the password policy.
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP: m=19 MiB, t=2, p=1 is the floor; these are stronger).
const (
	memoryKiB = 64 * 1024
	timeCost  = 3
	threads   = 2
	keyLen    = 32
	saltLen   = 16
	minLen    = 12
	maxLen    = 256 // bounds the cost of hashing attacker supplied input
)

// Policy errors.
var (
	ErrTooShort = errors.New("password must have at least 12 characters")
	ErrTooLong  = errors.New("password is too long")
	ErrCommon   = errors.New("password is too common")
	ErrSame     = errors.New("password must differ from the previous one")
	ErrEmail    = errors.New("password must not contain the e-mail address")
)

// Hash returns the PHC string of the password.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memoryKiB, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify compares the password with a PHC string in constant time. A malformed hash never matches.
func Verify(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	// refuse parameters that would let a corrupted row exhaust memory or CPU
	if m < 8*1024 || m > 256*1024 || t < 1 || t > 10 || p < 1 || p > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// DummyVerify spends the time of a real check, so an unknown user cannot be told apart from a
// wrong password by timing.
func DummyVerify(password string) {
	Verify(password, dummyHash)
}

var dummyHash = func() string {
	h, err := Hash("dummy-password-for-timing")
	if err != nil {
		panic(err)
	}
	return h
}()

// Check applies the policy: length, not a common password, does not contain the e-mail local
// part, differs from the previous hash (empty previous skips that rule).
func Check(password, email, previousHash string) error {
	n := len([]rune(password))
	switch {
	case n < minLen:
		return ErrTooShort
	case len(password) > maxLen:
		return ErrTooLong
	}
	lower := strings.ToLower(password)
	if _, bad := common[lower]; bad {
		return ErrCommon
	}
	if local, _, ok := strings.Cut(strings.ToLower(email), "@"); ok && len(local) >= 4 && strings.Contains(lower, local) {
		return ErrEmail
	}
	if previousHash != "" && Verify(password, previousHash) {
		return ErrSame
	}
	return nil
}

// Random returns n random bytes, base64url encoded (tokens, codes, secrets).
func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("password: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Digest is the SHA-256 of a high entropy token, for lookup columns.
func Digest(token string) []byte {
	s := sha256.Sum256([]byte(token))
	return s[:]
}

// common is a short list of the passwords that pass a length check but are guessed first.
var common = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, p := range []string{
		"password1234", "password12345", "passwordpassword", "123456789012", "1234567890123",
		"qwertyuiop12", "qwertyuiopas", "qwerty123456", "iloveyou1234", "letmein12345",
		"administrator", "adminadmin123", "welcome12345", "changeme1234", "changemenow12",
		"abcdefghijkl", "abc123abc123", "111111111111", "000000000000", "asdfghjkl123",
		"passw0rd1234", "p@ssw0rd1234", "p@ssword1234", "trustno1trust", "monkey123456",
	} {
		m[p] = struct{}{}
	}
	return m
}()
