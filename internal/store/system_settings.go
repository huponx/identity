package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// SystemSettings returns every row of identity_system_settings by key; a setting without a row is not in the map.
func (s *Store) SystemSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM identity_system_settings`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var (
			k string
			v []byte
		)
		if err := rows.Scan(&k, &v); err != nil {
			return nil, mapErr(err)
		}
		out[k] = json.RawMessage(v)
	}
	return out, mapErr(rows.Err())
}

// PutSystemSettings upserts the given rows in one transaction; the other rows are left alone.
func (s *Store) PutSystemSettings(ctx context.Context, rows map[string]json.RawMessage) error {
	if len(rows) == 0 {
		return nil
	}
	return mapErr(pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for k, v := range rows {
			if _, err := tx.Exec(ctx, `INSERT INTO identity_system_settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, k, string(v)); err != nil {
				return err
			}
		}
		return nil
	}))
}

// UIStyle returns the look of the web apps (defaultStyle when no row is stored or the stored value is not a string).
func (s *Store) UIStyle(ctx context.Context, defaultStyle string) (string, error) {
	rows, err := s.SystemSettings(ctx)
	if err != nil {
		return "", err
	}
	var v string
	if raw, ok := rows[UIStyleKey]; ok && json.Unmarshal(raw, &v) == nil && v != "" {
		return v, nil
	}
	return defaultStyle, nil
}

// UIStyleKey is the key of the look of the web apps in identity_system_settings.
const UIStyleKey = "ui_style"

// UIPalettesKey is the key of the palette of each look (style name to palette name) in identity_system_settings.
const UIPalettesKey = "ui_palettes"

// UIPalettes returns the stored palette of each look; empty when no row is stored or the stored value is not a JSON object of strings.
func (s *Store) UIPalettes(ctx context.Context) (map[string]string, error) {
	rows, err := s.SystemSettings(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if raw, ok := rows[UIPalettesKey]; ok && json.Unmarshal(raw, &out) != nil {
		return map[string]string{}, nil
	}
	return out, nil
}
