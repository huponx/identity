package service

import (
	"context"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/identity/internal/state"
	"github.com/huponx/identity/internal/useragent"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// sessionMsg is the API form of a session; the browser, OS and device are read from the User-Agent here, so a
// better rule table also describes the sessions that exist already.
func sessionMsg(sess state.Session, currentID string) *identityv1.Session {
	ua := useragent.Parse(sess.UserAgent)
	out := &identityv1.Session{
		Id: sess.PublicID, Ip: sess.IP, Browser: ua.Browser, BrowserVersion: ua.Version, Os: ua.OS, Device: ua.Device,
		Amr: sess.AMR, CreatedAt: sess.CreatedAt.Unix(), Current: currentID != "" && sess.PublicID == currentID,
	}
	if !sess.LastSeen.IsZero() {
		out.LastSeenAt = sess.LastSeen.Unix()
	}
	return out
}

func sessionMsgs(list []state.Session, currentID string) []*identityv1.Session {
	out := make([]*identityv1.Session, 0, len(list))
	for _, sess := range list {
		out = append(out, sessionMsg(sess, currentID))
	}
	return out
}

// mySessionID is the sid of the caller's token ("" when the token has none).
func mySessionID(ctx context.Context) string {
	if p := authn.FromContext(ctx); p != nil {
		return p.SessionID
	}
	return ""
}

func (s *Service) ListMySessions(ctx context.Context, _ *identityv1.ListMySessionsRequest) (*identityv1.ListMySessionsResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	list, err := s.Acct.ListSessions(ctx, id)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.ListMySessionsResponse{Sessions: sessionMsgs(list, mySessionID(ctx))}, nil
}

func (s *Service) RevokeMySession(ctx context.Context, req *identityv1.RevokeMySessionRequest) (*identityv1.RevokeMySessionResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.Acct.EndUserSession(ctx, id, req.GetId()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RevokeMySessionResponse{}, nil
}

func (s *Service) RevokeMyOtherSessions(ctx context.Context, _ *identityv1.RevokeMyOtherSessionsRequest) (*identityv1.RevokeMyOtherSessionsResponse, error) {
	id, err := meID(ctx)
	if err != nil {
		return nil, err
	}
	keep := mySessionID(ctx)
	if keep == "" { // without a sid there is no "other": ending all would sign the caller out unasked
		return nil, apperror.FailedPrecondition("the token does not belong to a session").WithReason("no_current_session")
	}
	n, err := s.Acct.EndOtherSessions(ctx, id, keep)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RevokeMyOtherSessionsResponse{Revoked: int32(n)}, nil
}

func (s *Service) ListUserSessions(ctx context.Context, req *identityv1.ListUserSessionsRequest) (*identityv1.ListUserSessionsResponse, error) {
	if _, err := s.Store.UserByID(ctx, req.GetUserId()); err != nil {
		return nil, toErr(err)
	}
	list, err := s.Acct.ListSessions(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.ListUserSessionsResponse{Sessions: sessionMsgs(list, "")}, nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, req *identityv1.RevokeUserSessionsRequest) (*identityv1.RevokeUserSessionsResponse, error) {
	if _, err := s.Store.UserByID(ctx, req.GetUserId()); err != nil {
		return nil, toErr(err)
	}
	list, err := s.Acct.ListSessions(ctx, req.GetUserId())
	if err != nil {
		return nil, toErr(err)
	}
	if err := s.Acct.RevokeUserAccess(ctx, req.GetUserId()); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.RevokeUserSessionsResponse{Revoked: int32(len(list))}, nil
}
