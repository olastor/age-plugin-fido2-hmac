package plugin

import (
	"errors"
	"sync"
)

// SessionCache keeps derived version-2 HMAC secrets alive for the lifetime of
// one explicit session. It never persists a PIN or an identity encoding.
//
// The cached byte slices are owned by the cache. Callers must treat the
// returned bytes as immutable and must not clear them directly.
type SessionCache struct {
	mu      sync.Mutex
	entries map[string][]byte
	loading map[string]*sessionLoad
	closed  bool
}

type sessionLoad struct {
	done   chan struct{}
	secret []byte
	err    error
}

// NewSessionCache creates an empty cache for one command-scoped session.
func NewSessionCache() *SessionCache {
	return &SessionCache{
		entries: make(map[string][]byte),
		loading: make(map[string]*sessionLoad),
	}
}

// Has reports whether key has already been loaded in this session.
func (c *SessionCache) Has(key string) bool {
	_, ok := c.Get(key)
	return ok
}

// Get returns a cached secret without transferring ownership to the caller.
// The returned slice remains owned by the cache and is cleared when the
// command-scoped session closes.
func (c *SessionCache) Get(key string) ([]byte, bool) {
	if c == nil || key == "" {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	secret, ok := c.entries[key]
	return secret, ok && !c.closed
}

// Load returns the cached value or calls load exactly once for concurrent
// callers requesting the same key. The load function must return a secret that
// has already been mlocked by the caller.
func (c *SessionCache) Load(key string, load func() ([]byte, error)) ([]byte, error) {
	if c == nil || key == "" {
		return load()
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("session cache is closed")
	}
	if secret, ok := c.entries[key]; ok {
		c.mu.Unlock()
		return secret, nil
	}
	if pending, ok := c.loading[key]; ok {
		c.mu.Unlock()
		<-pending.done
		return pending.secret, pending.err
	}

	pending := &sessionLoad{done: make(chan struct{})}
	c.loading[key] = pending
	c.mu.Unlock()

	secret, err := load()

	c.mu.Lock()
	delete(c.loading, key)
	pending.secret = secret
	pending.err = err
	if err == nil && c.closed {
		pending.err = errors.New("session cache closed while loading secret")
	} else if err == nil {
		c.entries[key] = secret
	}
	close(pending.done)
	c.mu.Unlock()

	if pending.err != nil && err == nil {
		for i := range secret {
			secret[i] = 0
		}
		return nil, pending.err
	}
	return secret, pending.err
}

// Close clears every cached secret. It is idempotent and should be called by
// the session wrapper on every exit path.
func (c *SessionCache) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	for key, secret := range c.entries {
		for i := range secret {
			secret[i] = 0
		}
		delete(c.entries, key)
	}
	c.mu.Unlock()
}
