package gateway

import (
	"container/list"
	"net/http"
	"sync"
)

const maxSessions = 10000

// sessions remembers which subject each MCP session was minted for, so a
// leaked session ID cannot be used with someone else's login. Unknown IDs are
// refused: entries only come from session IDs airlock itself handed out.
type sessions struct {
	mu     sync.Mutex
	owners map[string]*list.Element
	order  *list.List
}

type sessionOwner struct {
	id, subject string
}

func newSessions() *sessions {
	return &sessions{owners: map[string]*list.Element{}, order: list.New()}
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
	s.owners[id] = s.order.PushBack(sessionOwner{id: id, subject: subject})
	for s.order.Len() > maxSessions {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.owners, oldest.Value.(sessionOwner).id)
	}
}

func (s *sessions) unbind(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.owners[id]; ok {
		s.order.Remove(el)
		delete(s.owners, id)
	}
}

// allow reports whether subject owns session id.
func (s *sessions) allow(id, subject string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.owners[id]
	return ok && el.Value.(sessionOwner).subject == subject
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
