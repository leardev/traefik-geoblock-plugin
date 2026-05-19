package traefik_geoblock_plugin

// regression_test.go — Regression tests for the two bugs that caused OOM kills.
//
// These tests were written against the original (buggy) code: each test FAILS
// before the fix and PASSES after it is applied.
//
// Run individually:
//   go test -v -run TestBug_ ./...

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBug_StaleReaderAfterUpdate verifies that every middleware instance sharing
// a database path receives the new DB reader after the shared updater goroutine
// downloads an update — not only the single goroutine-owned instance (g0).
//
// Original bug: registerUpdater(g) starts the goroutine with g0 as its target.
// When g0.runUpdate() fires, only g0.db is updated.  All other instances (g1 …
// g57 in production) are left with a nil/stale db permanently.  This means:
//  1. Those instances return the wrong (default) response for every request.
//  2. The old reader held by those instances can never be GC'd, accumulating
//     ~37 MiB per update cycle per stale instance.
//
// Fix: sharedUpdaterLoop fans out the new reader to every registered instance
// immediately after g.runUpdate() returns.
func TestBug_StaleReaderAfterUpdate(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)

	// A gate channel blocks the download response until we say so.  This
	// guarantees that h1 is created (and g1.db is still nil) before the
	// goroutine's first update completes.
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-gate
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "stale.mmdb")
	// No pre-written file — both instances start with g.db == nil.

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	cfg := &Config{
		AllowedCountries: []string{"DE"},
		Token:            "test",
		DatabaseMMDBPath: mmdbPath,
		DatabaseMMDBURL:  srv.URL,
		AllowPrivate:     true,
		DefaultAllow:     false, // 403 when db is nil — makes the bug visible
		HTTPStatusCode:   http.StatusForbidden,
		UpdateInterval:   24,
	}

	// h0 is registered first.  The shared updater goroutine starts with g0 as
	// its target and immediately tries to download — but blocks on the gate.
	h0, err := New(context.Background(), next, cfg, "stale-0")
	if err != nil {
		t.Fatalf("New h0: %v", err)
	}

	// h1 is registered second.  It shares the same updater goroutine and starts
	// with g1.db == nil (the file does not exist on disk yet).
	h1, err := New(context.Background(), next, cfg, "stale-1")
	if err != nil {
		t.Fatalf("New h1: %v", err)
	}

	// Unblock the download.  The goroutine will set g0.db and — after the fix —
	// fan out the new reader to g1 as well.
	close(gate)

	// Wait until h0 is serving correctly (its DB has been loaded).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "91.0.0.1:1234" // 91.0.0.0/24 → DE in mmdbTestEntries
		rec := httptest.NewRecorder()
		h0.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "91.0.0.1:1234"
	rec := httptest.NewRecorder()
	h0.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("h0 still has no DB after 10 s — test setup problem (got %d)", rec.Code)
	}

	// Give the fan-out goroutine a moment to propagate (relevant for the fix only).
	time.Sleep(20 * time.Millisecond)

	// h1 shares the same config.  After the fix, it must also have the new
	// reader and serve DE requests as 200 OK.
	// With the original bug, h1.db is nil → DefaultAllow=false → 403.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "91.0.0.1:1234" // DE — should be allowed
	rec = httptest.NewRecorder()
	h1.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf(
			"Bug: h1 returned HTTP %d for a DE request — expected 200 OK.\n"+
				"The shared updater goroutine only set g0.db; h1 was left with a nil\n"+
				"DB and falls back to DefaultAllow=false, returning 403 for every request.\n"+
				"This also prevents the old reader from being garbage-collected, leaking\n"+
				"~37 MiB of memory per update cycle per stale instance.",
			rec.Code,
		)
	}
}

// TestBug_ContextCancelCleanup verifies that cancelling the context.Context
// passed to New() promptly unregisters the middleware instance and decrements
// the shared updater's refCount.
//
// Original bug: New() declared its context parameter as `_ context.Context`,
// silently ignoring it.  Cleanup relied on runtime.SetFinalizer on a
// geoBlockHandler wrapper.  Under GOMAXPROCS=1 and high GC pressure, finalizers
// are non-deterministic and can be delayed by many GC cycles.  During that
// window every old instance holds a reference to its DB reader, preventing
// collection even after the updater goroutine has loaded a new one.
//
// In production: 58 instances per hot-reload × unreliable finalizers × 4-hour
// update cycles → old 37 MiB readers accumulate → OOM kill.
//
// Fix: New() starts a goroutine that calls unregister() as soon as ctx is
// cancelled, giving Traefik's hot-reload a reliable, prompt cleanup path.
func TestBug_ContextCancelCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "ctx.mmdb")
	if err := os.WriteFile(mmdbPath, buildTestMMDB(t, mmdbTestEntries), 0600); err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // belt-and-suspenders cleanup

	_, err := New(ctx, next, &Config{
		AllowedCountries: []string{"DE"},
		Token:            "test",
		DatabaseMMDBPath: mmdbPath,
		DatabaseMMDBURL:  "http://unused.invalid",
		AllowPrivate:     true,
		DefaultAllow:     false,
		HTTPStatusCode:   http.StatusForbidden,
		UpdateInterval:   24,
	}, "ctx-cleanup")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := "mmdb:" + mmdbPath

	// Sanity: instance must be registered.
	sharedUpdaters.mu.Lock()
	registered := sharedUpdaters.entries[key] != nil
	sharedUpdaters.mu.Unlock()
	if !registered {
		t.Fatal("expected shared updater to be registered after New()")
	}

	// Simulate Traefik cancelling the middleware context on a hot-reload.
	cancel()

	// Allow time for the cleanup goroutine to observe ctx.Done() and call
	// unregister().  50 ms is generous — it should fire within microseconds.
	time.Sleep(50 * time.Millisecond)

	// After context cancel the entry must be gone: refCount decremented to 0,
	// the updater goroutine cancelled, and the map entry deleted.
	sharedUpdaters.mu.Lock()
	su := sharedUpdaters.entries[key]
	sharedUpdaters.mu.Unlock()

	if su != nil {
		t.Errorf(
			"Bug: shared updater entry still present after context cancel (refCount=%d).\n"+
				"New() is ignoring the context parameter; cleanup only fires when the GC\n"+
				"runs SetFinalizer on the handler wrapper.  Under GOMAXPROCS=1 and high\n"+
				"allocation pressure this can be delayed indefinitely, causing old DB\n"+
				"readers to accumulate across every Traefik hot-reload.",
			su.refCount,
		)
	}
}
