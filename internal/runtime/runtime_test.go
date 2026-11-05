package runtime

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/policy"
)

const keyPlain = apikey.Prefix + "runtime-test"

func allows(s *Snapshot, tool string) bool {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+keyPlain)
	id, err := s.Authenticator.Authenticate(context.Background(), r)
	if err != nil {
		return false
	}
	return s.Policy.Decide(context.Background(), policy.Request{Identity: id, Tool: tool}).Allow
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestHolderConcurrent(t *testing.T) {
	a, b := &Snapshot{ListenAddr: "a"}, &Snapshot{ListenAddr: "b"}
	h := NewHolder(a)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if s := h.Current(); s != a && s != b {
						t.Error("saw a torn snapshot")
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			h.Swap(b)
		} else {
			h.Swap(a)
		}
	}
	close(stop)
	wg.Wait()
}
