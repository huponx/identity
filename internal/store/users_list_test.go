package store

import "testing"

func TestLikePrefix(t *testing.T) {
	cases := map[string]string{
		"":           "%",
		"ann":        "ann%",
		"a_b":        `a\_b%`,
		"100%":       `100\%%`,
		`back\slash`: `back\\slash%`,
	}
	for in, want := range cases {
		if got := likePrefix(in); got != want {
			t.Errorf("likePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
