package mfa

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, secret "12345678901234567890", 8 digits there; the last 6 are ours.
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for unix, want := range cases {
		if got := Code(secret, Step(time.Unix(unix, 0))); got != want {
			t.Errorf("t=%d got %s want %s", unix, got, want)
		}
	}
}

func TestMatchWindowAndFormat(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_700_000_000, 0)
	cur := Step(now)
	for _, d := range []int64{-1, 0, 1} {
		step, ok := Match(secret, Code(secret, cur+d), now)
		if !ok || step != cur+d {
			t.Errorf("offset %d: ok=%v step=%d", d, ok, step)
		}
	}
	if _, ok := Match(secret, Code(secret, cur+2), now); ok {
		t.Error("2 steps ahead accepted")
	}
	if _, ok := Match(secret, Code(secret, cur-2), now); ok {
		t.Error("2 steps behind accepted")
	}
	code := Code(secret, cur)
	if _, ok := Match(secret, code[:3]+" "+code[3:], now); !ok {
		t.Error("space in the code must be tolerated")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Match(secret, bad, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestURI(t *testing.T) {
	u := URI("Example Corp", "bob@example.com", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Example%20Corp:bob@example.com", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Example+Corp", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("%s missing in %s", want, u)
		}
	}
}

func key() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestSealer(t *testing.T) {
	k1, k2 := "k1:"+key(), "k2:"+key()
	old, err := NewSealer([]string{k1})
	if err != nil {
		t.Fatal(err)
	}
	secret := NewSecret()
	sealed, err := old.Seal(secret, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("secret in clear")
	}

	// rotation: k2 seals, k1 still opens
	rotated, _ := NewSealer([]string{k2, k1})
	got, err := rotated.Open(sealed, "user-1")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open after rotation: %v", err)
	}
	if !rotated.NeedsReseal(sealed) {
		t.Error("old key must be reported")
	}
	fresh, _ := rotated.Seal(secret, "user-1")
	if rotated.NeedsReseal(fresh) {
		t.Error("current key must not need reseal")
	}

	// bound to the user, to the key, and tamper evident
	if _, err := rotated.Open(sealed, "user-2"); err == nil {
		t.Error("opened for another user")
	}
	onlyNew, _ := NewSealer([]string{k2})
	if _, err := onlyNew.Open(sealed, "user-1"); err == nil {
		t.Error("opened without the key")
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := old.Open(tampered, "user-1"); err == nil {
		t.Error("tampered data opened")
	}
	if _, err := old.Open([]byte("garbage"), "user-1"); err == nil {
		t.Error("garbage opened")
	}
}

func TestNewSealerValidation(t *testing.T) {
	for _, bad := range [][]string{nil, {"nokey"}, {"k:!!!"}, {"k:" + base64.StdEncoding.EncodeToString([]byte("short"))}, {":" + key()}} {
		if _, err := NewSealer(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := RecoveryCodes(10)
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if NormalizeRecoveryCode(strings.ToUpper(strings.ReplaceAll(c, "-", " "))) != c {
			t.Fatalf("normalize %q", c)
		}
	}
	if NormalizeRecoveryCode("short") != "" {
		t.Error("short code")
	}
}
