package store

import "context"

// UserStats are counts over all users. The status follows the rule of the API: disabled first, then
// "no password yet" is pending, the rest is active.
type UserStats struct {
	Total, Active, Pending, Disabled    int64
	MFAEnabled, MFAEnforced, WithAvatar int64
	SignedIn30d, NeverSignedIn          int64
	CreatedThisMonth                    int64
}

// TouchLogin records a completed sign in.
func (s *Store) TouchLogin(ctx context.Context, id string) error {
	return s.execUser(ctx, id, `UPDATE identity_users SET last_login_at = now() WHERE id = $1`)
}

// UserStats counts the users in one query.
func (s *Store) UserStats(ctx context.Context) (*UserStats, error) {
	var st UserStats
	err := s.pool.QueryRow(ctx, `SELECT
		count(*),
		count(*) FILTER (WHERE NOT disabled AND password_hash IS NOT NULL),
		count(*) FILTER (WHERE NOT disabled AND password_hash IS NULL),
		count(*) FILTER (WHERE disabled),
		count(*) FILTER (WHERE mfa_enabled),
		count(*) FILTER (WHERE mfa_enforced),
		count(*) FILTER (WHERE avatar IS NOT NULL),
		count(*) FILTER (WHERE last_login_at > now() - interval '30 days'),
		count(*) FILTER (WHERE last_login_at IS NULL),
		count(*) FILTER (WHERE created_at >= date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
		FROM identity_users WHERE deleted_at IS NULL`).Scan(&st.Total, &st.Active, &st.Pending, &st.Disabled,
		&st.MFAEnabled, &st.MFAEnforced, &st.WithAvatar, &st.SignedIn30d, &st.NeverSignedIn, &st.CreatedThisMonth)
	if err != nil {
		return nil, mapErr(err)
	}
	return &st, nil
}
