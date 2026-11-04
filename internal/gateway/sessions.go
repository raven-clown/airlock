package gateway

import "sync"

// sessions remembers which subject opened each MCP session, so a leaked
// session ID cannot be used with someone else's login.
type sessions struct {
	mu     sync.Mutex
	owners map[string]string
}

func newSessions() *sessions { return &sessions{owners: map[string]string{}} }

func (s *sessions) bind(id, subject string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.owners[id]; !ok {
		s.owners[id] = subject
	}
}

func (s *sessions) unbind(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.owners, id)
}

// allow reports whether subject may use session id. An unknown session is
// claimed by its first caller, in case the register hook ran without an identity.
func (s *sessions) allow(id, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[id]
	if !ok {
		s.owners[id] = subject
		return true
	}
	return owner == subject
}
