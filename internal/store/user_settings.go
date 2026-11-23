package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UserSettings returns the JSON object an application stored for a user; "{}" when there is none.
func (s *Store) UserSettings(ctx context.Context, userID, app string) (string, error) {
	if _, err := uuid.Parse(userID); err != nil {
		return "", ErrNotFound
	}
	var out string
	err := s.pool.QueryRow(ctx, `SELECT settings::text FROM identity_user_settings WHERE user_id = $1 AND app = $2`, userID, app).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return "{}", nil
	}
	return out, mapErr(err)
}

// PutUserSettings replaces the JSON object an application stores for a user.
func (s *Store) PutUserSettings(ctx context.Context, userID, app, settings string) error {
	if _, err := uuid.Parse(userID); err != nil {
		return ErrNotFound
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO identity_user_settings (user_id, app, settings) VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (user_id, app) DO UPDATE SET settings = EXCLUDED.settings, updated_at = now()`, userID, app, settings)
	return mapErr(err)
}
