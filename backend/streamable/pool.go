package streamable

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
)

// pool keeps one upstream session per caller and token, so a backend never sees two users on one session.
type pool struct {
	max  int
	idle time.Duration
	now  func() time.Time
	dial func(ctx context.Context, token string) (*client.Client, error)

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

type entry struct {
	key      string
	cli      *client.Client
	lastUsed time.Time
}

func newPool(maxSessions int, idle time.Duration, now func() time.Time, dial func(context.Context, string) (*client.Client, error)) *pool {
	return &pool{max: maxSessions, idle: idle, now: now, dial: dial, entries: map[string]*list.Element{}, lru: list.New()}
}

func poolKey(subject, token string) string {
	sum := sha256.Sum256([]byte(token))
	return subject + "\x00" + hex.EncodeToString(sum[:])
}

func (p *pool) get(ctx context.Context, subject, token string) (*client.Client, error) {
	key := poolKey(subject, token)
	p.mu.Lock()
	if el, ok := p.entries[key]; ok {
		e := el.Value.(*entry)
		e.lastUsed = p.now()
		p.lru.MoveToFront(el)
		p.mu.Unlock()
		return e.cli, nil
	}
	p.mu.Unlock()

	cli, err := p.dial(ctx, token)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if el, ok := p.entries[key]; ok {
		p.mu.Unlock()
		_ = cli.Close()
		return el.Value.(*entry).cli, nil
	}
	p.entries[key] = p.lru.PushFront(&entry{key: key, cli: cli, lastUsed: p.now()})
	var evicted []*client.Client
	for p.lru.Len() > p.max {
		evicted = append(evicted, p.removeLocked(p.lru.Back()))
	}
	p.mu.Unlock()
	closeAll(evicted)
	return cli, nil
}

// drop closes the session for subject and token, used after it fails.
func (p *pool) drop(subject, token string) {
	p.mu.Lock()
	var cli *client.Client
	if el, ok := p.entries[poolKey(subject, token)]; ok {
		cli = p.removeLocked(el)
	}
	p.mu.Unlock()
	if cli != nil {
		_ = cli.Close()
	}
}

func (p *pool) sweep() {
	cutoff := p.now().Add(-p.idle)
	p.mu.Lock()
	var stale []*client.Client
	for el := p.lru.Back(); el != nil; {
		prev := el.Prev()
		if el.Value.(*entry).lastUsed.Before(cutoff) {
			stale = append(stale, p.removeLocked(el))
		}
		el = prev
	}
	p.mu.Unlock()
	closeAll(stale)
}

func (p *pool) closeAll() {
	p.mu.Lock()
	var all []*client.Client
	for el := p.lru.Front(); el != nil; el = p.lru.Front() {
		all = append(all, p.removeLocked(el))
	}
	p.mu.Unlock()
	closeAll(all)
}

func (p *pool) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lru.Len()
}

func (p *pool) removeLocked(el *list.Element) *client.Client {
	e := el.Value.(*entry)
	p.lru.Remove(el)
	delete(p.entries, e.key)
	return e.cli
}

func closeAll(cs []*client.Client) {
	for _, c := range cs {
		_ = c.Close()
	}
}
