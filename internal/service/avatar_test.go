package service

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

func pngOf(t *testing.T, w, h int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCheckAvatar(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		mime string
		ok   bool
	}{
		{"small png", pngOf(t, 256, 256), "image/png", true},
		{"too wide", pngOf(t, 600, 10), "image/png", false},
		{"wrong type", pngOf(t, 10, 10), "image/jpeg", false},
		{"not an image", []byte("hello"), "image/png", false},
		{"unknown mime", pngOf(t, 10, 10), "image/gif", false},
		{"too big", append(pngOf(t, 10, 10), make([]byte, maxAvatarBytes)...), "image/png", false},
	}
	for _, c := range cases {
		if err := checkAvatar(c.data, c.mime); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok = %v", c.name, err, c.ok)
		}
	}
}

func TestAvatarURI(t *testing.T) {
	if got := avatarURI([]byte("ab"), "image/webp"); got != "data:image/webp;base64,YWI=" {
		t.Fatalf("got %q", got)
	}
	if !strings.HasPrefix(avatarURI(nil, "image/png"), "data:image/png;base64,") {
		t.Fatal("prefix")
	}
}

func TestUserStatus(t *testing.T) {
	cases := []struct {
		u    store.User
		want identityv1.UserStatus
	}{
		{store.User{}, identityv1.UserStatus_USER_STATUS_PENDING},
		{store.User{PasswordHash: "h"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
		{store.User{PasswordHash: "h", Disabled: true}, identityv1.UserStatus_USER_STATUS_DISABLED},
		{store.User{Disabled: true}, identityv1.UserStatus_USER_STATUS_DISABLED},
	}
	for _, c := range cases {
		if got := userStatus(&c.u); got != c.want {
			t.Errorf("%+v: got %v, want %v", c.u, got, c.want)
		}
	}
}
