package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type line struct {
	Log string `json:"log"`
	Event
}

func writeLines(w io.Writer, events []Event, tagged bool) error {
	for _, e := range events {
		var b []byte
		var err error
		if tagged {
			b, err = json.Marshal(line{Log: "audit", Event: e})
		} else {
			b, err = json.Marshal(e)
		}
		if err != nil {
			return fmt.Errorf("encoding audit record: %w", err)
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("writing audit record: %w", err)
		}
	}
	return nil
}

type stdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink writes one JSON line per record to w, tagged "log":"audit" so it can be split from normal logs.
func NewStdoutSink(w io.Writer) Sink { return &stdoutSink{w: w} }

func (s *stdoutSink) Write(_ context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeLines(s.w, events, true)
}

func (s *stdoutSink) Close() error { return nil }

type fileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink appends JSON lines to path, creating it with mode 0600.
func NewFileSink(path string) (Sink, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit file: %w", err)
	}
	return &fileSink{f: f}, nil
}

func (s *fileSink) Write(_ context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeLines(s.f, events, false)
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

func init() {
	RegisterSink("stdout", func(json.RawMessage) (Sink, error) { return NewStdoutSink(os.Stdout), nil })
	RegisterSink("file", func(raw json.RawMessage) (Sink, error) {
		var c struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("file sink config: %w", err)
		}
		if c.Path == "" {
			return nil, errors.New("file sink: path is required")
		}
		return NewFileSink(c.Path)
	})
}
