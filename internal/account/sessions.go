package account

import (
	"context"
	"errors"

	"github.com/huponx/identity/internal/state"
)

// ErrSessionNotFound is returned for a session that does not exist or is not the user's.
var ErrSessionNotFound = errors.New("account: session not found")

// ListSessions returns the live SSO sessions of a user, newest first.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]state.Session, error) {
	return s.State.ListUserSessions(ctx, userID)
}

// EndUserSession ends one session of the user (see EndSession). A session that does not exist or belongs to
// someone else is ErrSessionNotFound, so a caller cannot tell the two apart.
func (s *Service) EndUserSession(ctx context.Context, userID, publicID string) error {
	ok, err := s.State.IsUserSession(ctx, userID, publicID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSessionNotFound
	}
	_, err = s.EndSession(ctx, publicID)
	return err
}

// EndOtherSessions ends every session of the user but keep ("" ends all) and returns how many it ended. Access
// tokens already issued stay valid until they expire wherever a service verifies them locally; refresh tokens and
// the sessions of the clients (back-channel logout) end at once.
func (s *Service) EndOtherSessions(ctx context.Context, userID, keep string) (int, error) {
	list, err := s.State.ListUserSessions(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sess := range list {
		if sess.PublicID == keep {
			continue
		}
		if _, err := s.EndSession(ctx, sess.PublicID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
