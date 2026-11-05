package server

import (
	"testing"
	"time"
)

func fakeClockStore(ttl time.Duration) (*ttlStore[string], *time.Time) {
	now := time.Unix(1_000_000, 0)
	s := newTTLStore[string](ttl)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestTTLStoreExpiresEntries(t *testing.T) {
	t.Parallel()
	s, now := fakeClockStore(time.Minute)
	id, err := s.put("value")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.get(id); !ok || v != "value" {
		t.Fatalf("get = %q, %v", v, ok)
	}
	*now = now.Add(time.Minute)
	if _, ok := s.get(id); ok {
		t.Fatal("entry still valid at its expiry time")
	}
}

func TestTTLStoreTakeIsOneShotAndRejectionKeepsEntry(t *testing.T) {
	t.Parallel()
	s, _ := fakeClockStore(time.Minute)
	id, _ := s.put("secret")

	if _, ok := s.take(id, func(v string) bool { return v == "wrong" }); ok {
		t.Fatal("take accepted a rejected value")
	}
	if _, ok := s.get(id); !ok {
		t.Fatal("a rejected take consumed the entry")
	}
	if v, ok := s.take(id, func(v string) bool { return v == "secret" }); !ok || v != "secret" {
		t.Fatalf("take = %q, %v", v, ok)
	}
	if _, ok := s.take(id, func(string) bool { return true }); ok {
		t.Fatal("entry could be taken twice")
	}
}

func TestTTLStoreSweepRemovesOnlyExpired(t *testing.T) {
	t.Parallel()
	s, now := fakeClockStore(time.Minute)
	old, _ := s.put("old")
	*now = now.Add(45 * time.Second)
	fresh, _ := s.put("fresh")
	*now = now.Add(30 * time.Second)
	s.sweep()
	if len(s.m) != 1 {
		t.Fatalf("entries after sweep = %d, want 1", len(s.m))
	}
	if _, ok := s.m[old]; ok {
		t.Fatal("expired entry survived sweep")
	}
	if _, ok := s.get(fresh); !ok {
		t.Fatal("fresh entry removed by sweep")
	}
}
