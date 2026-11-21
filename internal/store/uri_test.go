package store

import "testing"

func TestValidURI(t *testing.T) {
	ok := []string{
		"https://app.example.com/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb",
		"com.example.app:/callback", "com.example.app://callback",
	}
	bad := []string{
		"", "http://app.example.com/cb", "https://app.example.com/cb#frag", "javascript:alert(1)",
		"myapp:/callback", "file:///etc/passwd", "com.example.app:/cb#x", "/relative",
	}
	for _, u := range ok {
		if !ValidURI(u) {
			t.Errorf("%q should be valid", u)
		}
	}
	for _, u := range bad {
		if ValidURI(u) {
			t.Errorf("%q should be invalid", u)
		}
	}
}
