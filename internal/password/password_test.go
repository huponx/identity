package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("format %q", h)
	}
	if !Verify("correct horse battery staple", h) || Verify("wrong", h) {
		t.Fatal("verify")
	}
	h2, _ := Hash("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt must differ")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, h := range []string{
		"", "plain", "$argon2i$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=999999999,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$!!",
		"$argon2id$v=18$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if Verify("x", h) {
			t.Errorf("accepted %q", h)
		}
	}
}

func TestPolicy(t *testing.T) {
	prev, _ := Hash("previous-passphrase-1")
	cases := []struct {
		name, pw, email, prev string
		want                  error
	}{
		{"ok", "a long enough passphrase", "bob@example.com", prev, nil},
		{"short", "short", "bob@example.com", "", ErrTooShort},
		{"common", "PasswordPassword", "bob@example.com", "", ErrCommon},
		{"email", "xx-alexander-xx-123", "alexander@example.com", "", ErrEmail},
		{"same", "previous-passphrase-1", "bob@example.com", prev, ErrSame},
		{"long", strings.Repeat("a", 300), "bob@example.com", "", ErrTooLong},
	}
	for _, c := range cases {
		if err := Check(c.pw, c.email, c.prev); !errors.Is(err, c.want) {
			t.Errorf("%s: %v want %v", c.name, err, c.want)
		}
	}
}

func TestRandomAndDigest(t *testing.T) {
	a, b := Random(32), Random(32)
	if a == b || len(a) != 43 {
		t.Fatalf("random %q %q", a, b)
	}
	if len(Digest(a)) != 32 {
		t.Fatal("digest")
	}
}
