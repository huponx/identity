package service

import (
	"encoding/base64"
	"strings"

	"github.com/huponx/gocommon/apperror"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
	// tokenSep separates the parts of a composite key inside a page token (it never occurs in a key).
	tokenSep = "\x00"
)

// pageSize applies the default and the maximum of every List call.
func pageSize(n int32) (int, error) {
	switch {
	case n < 0:
		return 0, apperror.InvalidArgument("page_size must not be negative")
	case n == 0:
		return defaultPageSize, nil
	case n > maxPageSize:
		return maxPageSize, nil
	}
	return int(n), nil
}

// encodePageToken turns the key of the last item of a page (one part, or several for a composite key) into the
// opaque token the caller sends back to get the next page.
func encodePageToken(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, tokenSep)))
}

// decodePageToken is the inverse of encodePageToken and returns n parts; an empty token (the first page) gives
// n empty parts.
func decodePageToken(token string, n int) ([]string, error) {
	out := make([]string, n)
	if token == "" {
		return out, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, apperror.InvalidArgument("invalid page_token")
	}
	parts := strings.Split(string(b), tokenSep)
	if len(parts) != n {
		return nil, apperror.InvalidArgument("invalid page_token")
	}
	return parts, nil
}
