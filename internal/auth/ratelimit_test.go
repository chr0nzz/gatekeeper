package auth

import (
	"testing"
	"time"
)

func TestLimiterBlocksAfterMaxFailures(t *testing.T) {
	l := NewLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("attempt %d blocked too early", i+1)
		}
		l.Record("10.0.0.1")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("attempt allowed after reaching the failure limit")
	}
	if !l.Allow("10.0.0.2") {
		t.Fatal("a different address was blocked")
	}
}

func TestLimiterResetOnSuccess(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	l.Record("10.0.0.1")
	l.Record("10.0.0.1")
	if l.Allow("10.0.0.1") {
		t.Fatal("expected to be blocked before reset")
	}
	l.Reset("10.0.0.1")
	if !l.Allow("10.0.0.1") {
		t.Fatal("reset did not clear the failure count")
	}
}

func TestLimiterWindowExpiry(t *testing.T) {
	l := NewLimiter(1, 10*time.Millisecond)
	l.Record("10.0.0.1")
	if l.Allow("10.0.0.1") {
		t.Fatal("expected block inside the window")
	}
	time.Sleep(20 * time.Millisecond)
	if !l.Allow("10.0.0.1") {
		t.Fatal("failures did not expire after the window")
	}
}
