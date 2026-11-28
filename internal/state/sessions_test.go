package state

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// needs IDENTITY_TEST_REDIS_URL, for example redis://localhost:6379/15
func testState(t *testing.T, now func() time.Time) (*State, *redis.Client) {
	t.Helper()
	rd := os.Getenv("IDENTITY_TEST_REDIS_URL")
	if rd == "" {
		t.Skip("IDENTITY_TEST_REDIS_URL is not set")
	}
	opt, err := redis.ParseURL(rd)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	return NewWithClient(rdb, now), rdb
}

func TestLastSeenIsWrittenOncePerMinuteAndKeepsTheTTL(t *testing.T) {
	ctx := context.Background()
	clock := time.Now()
	s, rdb := testState(t, func() time.Time { return clock })
	uid, cookie := uuid.NewString(), uuid.NewString()
	if err := s.CreateSession(ctx, Session{UserID: uid, IP: "1.2.3.4", UserAgent: "ua"}, cookie, uuid.NewString(), time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DeleteUserSessions(ctx, uid) })

	first, err := s.GetSession(ctx, cookie, time.Hour, 2*time.Hour)
	if err != nil || !first.LastSeen.Equal(clock) || first.IP != "1.2.3.4" || first.UserAgent != "ua" {
		t.Fatalf("first read: %+v %v", first, err)
	}
	// 30 seconds later nothing is written
	clock = clock.Add(30 * time.Second)
	second, _ := s.GetSession(ctx, cookie, time.Hour, 2*time.Hour)
	stored := func() Session {
		list, err := s.ListUserSessions(ctx, uid)
		if err != nil || len(list) != 1 {
			t.Fatalf("list: %+v %v", list, err)
		}
		return list[0]
	}
	if got := stored().LastSeen; !got.Equal(first.LastSeen) || !second.LastSeen.Equal(first.LastSeen) {
		t.Errorf("written within a minute: %v", got)
	}
	// a minute after the first write it is written again, and the idle TTL is the one Expire set, not reset by the write
	clock = clock.Add(31 * time.Second)
	if _, err := s.GetSession(ctx, cookie, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := stored().LastSeen; !got.Equal(clock) {
		t.Errorf("not written after a minute: %v want %v", got, clock)
	}
	if ttl := rdb.TTL(ctx, sessKey(cookie)).Val(); ttl <= 0 || ttl > time.Hour {
		t.Errorf("ttl %v", ttl)
	}
}

func TestListUserSessionsPrunesTheExpiredOnes(t *testing.T) {
	ctx := context.Background()
	s, rdb := testState(t, nil)
	uid := uuid.NewString()
	t.Cleanup(func() { _, _ = s.DeleteUserSessions(ctx, uid) })
	live, gone := uuid.NewString(), uuid.NewString()
	if err := s.CreateSession(ctx, Session{UserID: uid}, "c-live-"+live, live, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, Session{UserID: uid}, "c-gone-"+gone, gone, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	// the idle expiry removes the session but never its member of the set
	rdb.Del(ctx, sessKey("c-gone-"+gone))

	list, err := s.ListUserSessions(ctx, uid)
	if err != nil || len(list) != 1 || list[0].PublicID != live {
		t.Fatalf("list: %+v %v", list, err)
	}
	if members := rdb.SMembers(ctx, usessKey(uid)).Val(); len(members) != 1 || members[0] != live {
		t.Errorf("set after the list: %v", members)
	}
	if ok, _ := s.IsUserSession(ctx, uid, live); !ok {
		t.Error("live session is not the user's")
	}
	if ok, _ := s.IsUserSession(ctx, uid, gone); ok {
		t.Error("expired session is still the user's")
	}
	if ok, _ := s.IsUserSession(ctx, uuid.NewString(), live); ok {
		t.Error("session of another user")
	}
}
