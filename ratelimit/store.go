package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Bucket is the outcome of a Take.
type Bucket struct {
	OK         bool
	Remaining  int64
	Reset      time.Duration
	RetryAfter time.Duration
}

// Store keeps counters. A shared store, such as one in Postgres or Valkey, lets every
// replica see the same counts.
type Store interface {
	// Take spends one unit of key's rate, unless the rate has no room left.
	Take(ctx context.Context, key string, r Rate, now time.Time) (Bucket, error)
	// Acquire takes one of limit concurrent slots for key. release frees it and may be
	// called more than once.
	Acquire(ctx context.Context, key string, limit int64) (ok bool, release func(), err error)
}

// MemoryStore counts in this process, with GCRA for rates.
type MemoryStore struct {
	mu       sync.Mutex
	tats     map[string]time.Time
	sweepAt  int
	inflight map[string]int64
}

const minSweep = 1024

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tats: map[string]time.Time{}, sweepAt: minSweep, inflight: map[string]int64{}}
}

// Take implements Store. The bucket holds Count units and one comes back every Interval.
func (s *MemoryStore) Take(_ context.Context, key string, r Rate, now time.Time) (Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tat := s.tats[key]
	if tat.Before(now) {
		tat = now
	}
	next := tat.Add(r.Interval())
	if allowAt := next.Add(-r.Period); allowAt.After(now) {
		return Bucket{RetryAfter: allowAt.Sub(now), Reset: tat.Sub(now), Remaining: remaining(r, tat.Sub(now))}, nil
	}
	s.tats[key] = next
	if len(s.tats) >= s.sweepAt {
		s.sweep(now)
	}
	return Bucket{OK: true, Remaining: remaining(r, next.Sub(now)), Reset: next.Sub(now)}, nil
}

// sweep drops keys whose bucket is full again, which are the same as absent ones, so
// the map grows with the callers active in the last period, not every caller ever seen.
func (s *MemoryStore) sweep(now time.Time) {
	for k, tat := range s.tats {
		if !tat.After(now) {
			delete(s.tats, k)
		}
	}
	s.sweepAt = max(2*len(s.tats), minSweep)
}

// Len returns how many keys hold rate state.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tats)
}

func remaining(r Rate, ahead time.Duration) int64 {
	return max(int64((r.Period-ahead)/r.Interval()), 0)
}

// Acquire implements Store.
func (s *MemoryStore) Acquire(_ context.Context, key string, limit int64) (bool, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[key] >= limit {
		return false, func() {}, nil
	}
	s.inflight[key]++
	var once sync.Once
	return true, func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.inflight[key]--; s.inflight[key] <= 0 {
				delete(s.inflight, key)
			}
		})
	}, nil
}
