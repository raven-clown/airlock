package gateway

import (
	"fmt"
	"testing"
)

func TestSessionsCapEvictsOldest(t *testing.T) {
	s := newSessions()
	for i := 0; i <= maxSessions; i++ {
		s.bind(fmt.Sprintf("s%d", i), "alice")
	}
	if s.len() != maxSessions {
		t.Fatalf("len = %d", s.len())
	}
	if s.allow("s0", "alice") {
		t.Error("oldest session not evicted")
	}
	if !s.allow(fmt.Sprintf("s%d", maxSessions), "alice") {
		t.Error("newest session missing")
	}
	s.bind("s1", "bob")
	if s.allow("s1", "bob") {
		t.Error("rebinding changed the owner")
	}
	s.bind("", "alice")
	if s.known("") {
		t.Error("empty session ID bound")
	}
}
