package gateway

import (
	"fmt"
	"testing"
	"time"
)

func TestSessionsPerSubjectCap(t *testing.T) {
	s := newSessions()
	s.bind("bob-1", "bob")
	for i := 0; i <= maxSessionsPerSubject; i++ {
		s.bind(fmt.Sprintf("alice-%d", i), "alice")
	}
	if s.allow("alice-0", "alice") {
		t.Error("alice's oldest session not evicted")
	}
	if !s.allow(fmt.Sprintf("alice-%d", maxSessionsPerSubject), "alice") {
		t.Error("alice's newest session missing")
	}
	if !s.allow("bob-1", "bob") {
		t.Error("alice's sessions evicted bob's")
	}
	if s.len() != maxSessionsPerSubject+1 {
		t.Errorf("len = %d", s.len())
	}
}

func TestSessionsGlobalCapFailsClosed(t *testing.T) {
	s := newSessions()
	for i := 0; s.len() < maxSessions; i++ {
		s.bind(fmt.Sprintf("s%d", i), fmt.Sprintf("user%d", i/maxSessionsPerSubject))
	}
	s.bind("late", "newcomer")
	if s.known("late") {
		t.Error("a session was bound past the global cap")
	}
	if !s.allow("s0", "user0") {
		t.Error("an existing session was evicted to make room")
	}
	if _, ok := s.bySubject["newcomer"]; ok {
		t.Error("an empty entry was left for the refused subject")
	}
}

func TestSessionsBindRules(t *testing.T) {
	s := newSessions()
	s.bind("x", "alice")
	s.bind("x", "bob")
	if s.allow("x", "bob") || !s.allow("x", "alice") {
		t.Error("rebinding changed the owner")
	}
	s.bind("", "alice")
	if s.known("") {
		t.Error("empty session ID bound")
	}
	s.unbind("x")
	if s.known("x") || s.len() != 0 {
		t.Error("unbind left the session")
	}
}

func TestSessionsIdleExpireWhenFull(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	s := newSessions()
	s.now = func() time.Time { return now }
	for i := 0; s.len() < maxSessions; i++ {
		s.bind(fmt.Sprintf("s%d", i), fmt.Sprintf("user%d", i/maxSessionsPerSubject))
	}
	now = now.Add(sessionIdle + time.Minute)
	if !s.allow("s0", "user0") {
		t.Fatal("s0 missing before expiry")
	}
	s.bind("late", "newcomer")
	if !s.known("late") {
		t.Fatal("idle sessions were not expired to make room")
	}
	if !s.known("s0") {
		t.Error("a recently used session was expired")
	}
	if s.known("s1") {
		t.Error("an idle session survived a full table")
	}
}
