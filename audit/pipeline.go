package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// PipelineOptions tune buffering. Zero values get defaults.
type PipelineOptions struct {
	BufferSize int
	// Block makes Record wait for room instead of dropping records.
	Block      bool
	BatchSize  int
	FlushEvery time.Duration
	Logger     *slog.Logger
}

// Pipeline buffers records and writes them to every sink in batches, off the request path.
type Pipeline struct {
	sinks []Sink
	opts  PipelineOptions
	ch    chan Event
	done  chan struct{}

	mu      sync.RWMutex
	closed  bool
	dropped atomic.Uint64
}

// NewPipeline starts a pipeline writing to sinks.
func NewPipeline(sinks []Sink, opts PipelineOptions) *Pipeline {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = 500 * time.Millisecond
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	p := &Pipeline{sinks: sinks, opts: opts, ch: make(chan Event, opts.BufferSize), done: make(chan struct{})}
	go p.run()
	return p
}

// Record queues e. In drop mode it never blocks, and counts what it cannot queue.
func (p *Pipeline) Record(e Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.dropped.Add(1)
		return
	}
	if p.opts.Block {
		p.ch <- e
		return
	}
	select {
	case p.ch <- e:
	default:
		p.dropped.Add(1)
	}
}

// Dropped returns how many records were lost to a full buffer.
func (p *Pipeline) Dropped() uint64 { return p.dropped.Load() }

// Close flushes queued records and closes the sinks.
func (p *Pipeline) Close(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	p.mu.Unlock()
	select {
	case <-p.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	var errs []error
	for _, s := range p.sinks {
		errs = append(errs, s.Close())
	}
	return errors.Join(errs...)
}

func (p *Pipeline) run() {
	defer close(p.done)
	ticker := time.NewTicker(p.opts.FlushEvery)
	defer ticker.Stop()
	batch := make([]Event, 0, p.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for _, s := range p.sinks {
			if err := s.Write(context.Background(), batch); err != nil {
				p.opts.Logger.Error("audit sink failed", "error", err, "records", len(batch))
			}
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-p.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= p.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
