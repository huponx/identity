package oauth

import (
	"bytes"
	"strings"
	"testing"
)

func TestPasswordChangeTemplate(t *testing.T) {
	var b bytes.Buffer
	err := tmpl.ExecuteTemplate(&b, "password-change", page{Title: "Choose a new password", CSRF: "tok", Fields: map[string]string{"c": "chal"}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`action="/login/password"`, `name="csrf" value="tok"`, `name="c" value="chal"`, `name="password"`, `name="password2"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in the page", want)
		}
	}
}
