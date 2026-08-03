package auth

import (
	"sync"
	"time"
)

// Limiter throttles repeated failures from the same key (typically a client IP).
type Limiter struct {
	mu       sync.Mutex
	entries  map[string]*limiterEntry
	maxFails int
	window   time.Duration
}

type limiterEntry struct {
	fails   int
	resetAt time.Time
}

// NewLimiter creates a Limiter allowing maxFails failures per window.
func NewLimiter(maxFails int, window time.Duration) *Limiter {
	l := &Limiter{entries: make(map[string]*limiterEntry), maxFails: maxFails, window: window}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			l.mu.Lock()
			now := time.Now()
			for k, e := range l.entries {
				if now.After(e.resetAt) {
					delete(l.entries, k)
				}
			}
			l.mu.Unlock()
		}
	}()
	return l
}

// Allow reports whether another attempt from key is permitted.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.After(e.resetAt) {
		l.entries[key] = &limiterEntry{resetAt: now.Add(l.window)}
		return true
	}
	return e.fails < l.maxFails
}

// Record counts a failed attempt against key.
func (l *Limiter) Record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.After(e.resetAt) {
		l.entries[key] = &limiterEntry{fails: 1, resetAt: now.Add(l.window)}
		return
	}
	e.fails++
}

// Reset clears the failure count for key after a successful attempt.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
