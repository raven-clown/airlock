package gateway

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

const (
	maxSessions           = 10000
	maxSessionsPerSubject = 100
	// sessionIdle is how long an unused session keeps its place once the table is full.
	sessionIdle = 30 * time.Minute
)

// sessions remembers which subject each MCP session was minted for, so a
// leaked session ID cannot be used with someone else's login. Unknown IDs are
// refused: entries only come from session IDs airlock itself handed out.
// Each subject keeps at most maxSessionsPerSubject, losing its own oldest
// first. When the table is full, sessions idle for sessionIdle are dropped,
// and if none are, the new session is left unbound so it fails closed
// instead of pushing out someone else's.
type sessions struct {
	mu        sync.Mutex
	owners    map[string]*list.Element
	bySubject map[string]*list.List
	now       func() time.Time
}

type sessionOwner struct {
	id, subject string
	lastUsed    time.Time
}

func newSessions() *sessions {
	return &sessions{owners: map[string]*list.Element{}, bySubject: map[string]*list.List{}, now: time.Now}
}

func (s *sessions) bind(id, subject string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.owners[id]; ok {
		return
	}
	if own := s.bySubject[subject]; own != nil && own.Len() >= maxSessionsPerSubject {
		s.removeLocked(own.Front())
	} else if len(s.owners) >= maxSessions {
		s.expireIdleLocked()
		if len(s.owners) >= maxSessions {
			return
		}
	}
	own := s.bySubject[subject]
	if own == nil {
		own = list.New()
		s.bySubject[subject] = own
	}
	s.owners[id] = own.PushBack(&sessionOwner{id: id, subject: subject, lastUsed: s.now()})
}

func (s *sessions) unbind(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.owners[id]; ok {
		s.removeLocked(el)
	}
}

func (s *sessions) expireIdleLocked() {
	cutoff := s.now().Add(-sessionIdle)
	for _, el := range s.owners {
		if el.Value.(*sessionOwner).lastUsed.Before(cutoff) {
			s.removeLocked(el)
		}
	}
}

func (s *sessions) removeLocked(el *list.Element) {
	o := el.Value.(*sessionOwner)
	own := s.bySubject[o.subject]
	own.Remove(el)
	if own.Len() == 0 {
		delete(s.bySubject, o.subject)
	}
	delete(s.owners, o.id)
}

// allow reports whether subject owns session id.
func (s *sessions) allow(id, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.owners[id]
	if !ok {
		return false
	}
	o := el.Value.(*sessionOwner)
	if o.subject != subject {
		return false
	}
	o.lastUsed = s.now()
	return true
}

func (s *sessions) known(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.owners[id]
	return ok
}

func (s *sessions) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.owners)
}

// mintWriter binds the session ID mcp-go sets on a response to the caller.
type mintWriter struct {
	http.ResponseWriter
	sessions *sessions
	subject  string
	done     bool
}

func (w *mintWriter) capture() {
	if !w.done {
		w.done = true
		w.sessions.bind(w.Header().Get("Mcp-Session-Id"), w.subject)
	}
}

func (w *mintWriter) WriteHeader(code int) {
	w.capture()
	w.ResponseWriter.WriteHeader(code)
}

func (w *mintWriter) Write(b []byte) (int, error) {
	w.capture()
	return w.ResponseWriter.Write(b)
}

// Flush keeps streamed responses working through the wrapper.
func (w *mintWriter) Flush() {
	w.capture()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *mintWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
