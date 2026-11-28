package store

import (
	"context"
	"time"
)

// Passkey is a WebAuthn credential of a user.
type Passkey struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	SignCount       uint32
	AAGUID          []byte
	Transports      []string
	BackupEligible  bool
	BackupState     bool
	AttestationType string
	Name            string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

const passkeyCols = `id::text, user_id::text, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, attestation_type, name, created_at, last_used_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanPasskey(row rowScanner) (*Passkey, error) {
	var p Passkey
	var count int64
	if err := row.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &count, &p.AAGUID, &p.Transports,
		&p.BackupEligible, &p.BackupState, &p.AttestationType, &p.Name, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return nil, mapErr(err)
	}
	p.SignCount = uint32(count)
	return &p, nil
}

// ListPasskeys returns the passkeys of a user, oldest first.
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+passkeyCols+` FROM identity_user_passkeys WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PasskeyByCredential returns the passkey with this credential id, of any user.
func (s *Store) PasskeyByCredential(ctx context.Context, credentialID []byte) (*Passkey, error) {
	return scanPasskey(s.pool.QueryRow(ctx, `SELECT `+passkeyCols+` FROM identity_user_passkeys WHERE credential_id = $1`, credentialID))
}

// CountPasskeys is the number of passkeys of a user.
func (s *Store) CountPasskeys(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM identity_user_passkeys WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// InsertPasskey stores a new passkey; ErrConflict when the credential id is already registered.
func (s *Store) InsertPasskey(ctx context.Context, p Passkey) (*Passkey, error) {
	// pgx sends a nil slice as NULL; the columns are NOT NULL
	if p.Transports == nil {
		p.Transports = []string{}
	}
	if p.AAGUID == nil {
		p.AAGUID = []byte{}
	}
	return scanPasskey(s.pool.QueryRow(ctx, `INSERT INTO identity_user_passkeys
		(user_id, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backup_state, attestation_type, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING `+passkeyCols,
		p.UserID, p.CredentialID, p.PublicKey, int64(p.SignCount), p.AAGUID, p.Transports, p.BackupEligible, p.BackupState, p.AttestationType, p.Name))
}

// RenamePasskey renames a passkey of the user; ErrNotFound when it is not theirs.
func (s *Store) RenamePasskey(ctx context.Context, userID, id, name string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE identity_user_passkeys SET name = $3 WHERE id = $2 AND user_id = $1`, userID, id, name)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey deletes a passkey of the user; ErrNotFound when it is not theirs.
func (s *Store) DeletePasskey(ctx context.Context, userID, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM identity_user_passkeys WHERE id = $2 AND user_id = $1`, userID, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchPasskey records a use: the new sign count, the backup state and the time.
func (s *Store) TouchPasskey(ctx context.Context, id string, signCount uint32, backupState bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE identity_user_passkeys SET sign_count = $2, backup_state = $3, last_used_at = now() WHERE id = $1`, id, int64(signCount), backupState)
	return err
}

// DeleteUserPasskeys deletes every passkey of the user (admin reset) and returns how many there were.
func (s *Store) DeleteUserPasskeys(ctx context.Context, userID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM identity_user_passkeys WHERE user_id = $1`, userID)
	return tag.RowsAffected(), err
}
