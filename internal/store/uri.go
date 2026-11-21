package store

import (
	"context"
	"net/url"
	"strings"
)

// ValidURI accepts the URIs a client may register, without a fragment: absolute https URIs
// (http only for localhost), and private-use schemes of native apps in reverse domain form
// ("com.example.app:/callback", RFC 8252 section 7.1).
func ValidURI(raw string) bool {
	if raw == "" || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.Contains(u.Scheme, ".") { // reverse domain scheme of a native app, with or without "//host"
		return u.User == nil
	}
	if u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
}

// AddClientURIs adds redirect and post logout URIs to a client (existing ones are kept, no duplicates).
func (s *Store) AddClientURIs(ctx context.Context, id string, redirects, logouts []string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_clients SET
		redirect_uris = ARRAY(SELECT DISTINCT x FROM unnest(redirect_uris || $2::text[]) AS x ORDER BY x),
		post_logout_redirect_uris = ARRAY(SELECT DISTINCT x FROM unnest(post_logout_redirect_uris || $3::text[]) AS x ORDER BY x),
		updated_at = now() WHERE client_id = $1`, id, nz(redirects), nz(logouts))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
