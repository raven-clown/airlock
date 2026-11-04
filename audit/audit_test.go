package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memSink struct {
	mu     sync.Mutex
	events []Event
	gate   chan struct{}
	err    error
}

func (m *memSink) Write(_ context.Context, es []Event) error {
	if m.gate != nil {
		<-m.gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, es...)
	return m.err
}

func (m *memSink) Close() error { return nil }

func (m *memSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestStdoutSink(t *testing.T) {
	var buf bytes.Buffer
	s := NewStdoutSink(&buf)
	e := Event{Time: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC), Kind: KindTool, Subject: "alice", Server: "github", Tool: "create_issue", Decision: "allow", Rule: "eng", Outcome: OutcomeOK, DurationMS: 12}
	if err := s.Write(context.Background(), []Event{e}); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasPrefix(line, `{"log":"audit",`) || strings.Count(line, "\n") != 1 {
		t.Fatalf("line = %q", line)
	}
	var got Event
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice" || got.Outcome != OutcomeOK || got.DurationMS != 12 || !got.Time.Equal(e.Time) {
		t.Errorf("round trip = %+v", got)
	}
	if strings.Contains(line, `"args"`) || strings.Contains(line, `"error"`) {
		t.Errorf("empty optional fields written: %s", line)
	}
}

func TestFileSinkAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, subject := range []string{"alice", "bob"} {
		s, err := NewFileSink(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Write(context.Background(), []Event{{Subject: subject}}); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var subjects []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, e.Subject)
	}
	if strings.Join(subjects, ",") != "alice,bob" {
		t.Errorf("subjects = %v", subjects)
	}
}

func TestPipelineFlushOnClose(t *testing.T) {
	sink := &memSink{}
	p := NewPipeline([]Sink{sink}, PipelineOptions{BufferSize: 100, Logger: quiet})
	for i := 0; i < 10; i++ {
		p.Record(Event{Subject: "alice"})
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 10 {
		t.Errorf("sink got %d events, want 10", sink.count())
	}
	p.Record(Event{})
}

func TestPipelineFlushesOnTimer(t *testing.T) {
	sink := &memSink{}
	p := NewPipeline([]Sink{sink}, PipelineOptions{BufferSize: 100, FlushEvery: 10 * time.Millisecond, Logger: quiet})
	defer func() { _ = p.Close(context.Background()) }()
	p.Record(Event{})
	deadline := time.Now().Add(5 * time.Second)
	for sink.count() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("event not flushed by the timer")
		}
		time.Sleep(time.Millisecond)
	}
}

func returnsWithin(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func TestPipelineDrops(t *testing.T) {
	sink := &memSink{gate: make(chan struct{})}
	p := NewPipeline([]Sink{sink}, PipelineOptions{BufferSize: 1, BatchSize: 1, Logger: quiet})
	for i := 0; i < 5; i++ {
		if !returnsWithin(time.Second, func() { p.Record(Event{}) }) {
			t.Fatal("Record blocked in drop mode")
		}
	}
	if p.Dropped() < 3 {
		t.Errorf("Dropped = %d, want at least 3", p.Dropped())
	}
	close(sink.gate)
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPipelineBlockMode(t *testing.T) {
	sink := &memSink{gate: make(chan struct{})}
	p := NewPipeline([]Sink{sink}, PipelineOptions{BufferSize: 1, BatchSize: 1, Block: true, Logger: quiet})
	p.Record(Event{})
	deadline := time.Now().Add(5 * time.Second)
	for len(p.ch) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("first event not picked up")
		}
		time.Sleep(time.Millisecond)
	}
	p.Record(Event{})
	third := make(chan struct{})
	go func() { p.Record(Event{}); close(third) }()
	select {
	case <-third:
		t.Fatal("Record did not block with a full buffer")
	case <-time.After(100 * time.Millisecond):
	}
	close(sink.gate)
	select {
	case <-third:
	case <-time.After(5 * time.Second):
		t.Fatal("Record stayed blocked after the sink was released")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.Dropped() != 0 || sink.count() != 3 {
		t.Errorf("dropped %d, written %d", p.Dropped(), sink.count())
	}
}

func TestPipelineSinkError(t *testing.T) {
	var logs bytes.Buffer
	failing := &memSink{err: errors.New("disk full")}
	ok := &memSink{}
	p := NewPipeline([]Sink{failing, ok}, PipelineOptions{BufferSize: 10, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	p.Record(Event{})
	p.Record(Event{})
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok.count() != 2 {
		t.Errorf("healthy sink got %d events", ok.count())
	}
	if !strings.Contains(logs.String(), "disk full") {
		t.Errorf("sink error not logged: %s", logs.String())
	}
}

func TestRegisteredSinks(t *testing.T) {
	if _, ok := LookupSink("stdout"); !ok {
		t.Error("stdout not registered")
	}
	f, ok := LookupSink("file")
	if !ok {
		t.Fatal("file not registered")
	}
	s, err := f(json.RawMessage(`{"path":"` + filepath.ToSlash(filepath.Join(t.TempDir(), "a.jsonl")) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := f(json.RawMessage(`{}`)); err == nil {
		t.Error("file sink without path accepted")
	}
}
