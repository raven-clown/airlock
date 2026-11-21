package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTakeBurstAndRefill(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	r := Rate{Count: 3, Period: 3 * time.Second}
	now := time.Unix(1000, 0)
	for i := range 3 {
		b, err := s.Take(ctx, "k", r, now)
		if err != nil || !b.OK {
			t.Fatalf("take %d: %+v %v", i, b, err)
		}
		if b.Remaining != int64(2-i) {
			t.Fatalf("take %d: remaining %d", i, b.Remaining)
		}
	}
	b, _ := s.Take(ctx, "k", r, now)
	if b.OK || b.RetryAfter != time.Second {
		t.Fatalf("fourth take: %+v", b)
	}
	if b, _ := s.Take(ctx, "other", r, now); !b.OK {
		t.Fatal("another key shares the bucket")
	}
	if b, _ := s.Take(ctx, "k", r, now.Add(time.Second)); !b.OK {
		t.Fatalf("no refill after one interval: %+v", b)
	}
	if b, _ := s.Take(ctx, "k", r, now.Add(time.Second)); b.OK {
		t.Fatal("refilled more than one")
	}
}

func TestTakeReset(t *testing.T) {
	s := NewMemoryStore()
	r := Rate{Count: 60, Period: time.Minute}
	b, _ := s.Take(context.Background(), "k", r, time.Unix(0, 0))
	if b.Reset != time.Second || b.Remaining != 59 {
		t.Fatalf("%+v", b)
	}
}

func TestSweepDropsFullBuckets(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	r := Rate{Count: 10, Period: time.Second}
	start := time.Unix(0, 0)
	for i := range minSweep - 1 {
		_, _ = s.Take(ctx, fmt.Sprint("old", i), r, start)
	}
	later := start.Add(time.Hour)
	_, _ = s.Take(ctx, "new", r, later)
	if n := s.Len(); n != 1 {
		t.Fatalf("%d keys kept, want only the active one", n)
	}
}

func TestAcquire(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	ok1, rel1, _ := s.Acquire(ctx, "k", 2)
	ok2, _, _ := s.Acquire(ctx, "k", 2)
	ok3, _, _ := s.Acquire(ctx, "k", 2)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("got %v %v %v", ok1, ok2, ok3)
	}
	rel1()
	rel1()
	if ok, _, _ := s.Acquire(ctx, "k", 2); !ok {
		t.Fatal("release did not free a slot")
	}
	if ok, _, _ := s.Acquire(ctx, "k", 2); ok {
		t.Fatal("a second release freed another slot")
	}
}
