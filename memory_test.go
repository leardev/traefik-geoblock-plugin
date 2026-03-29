package traefik_geoblock_plugin

// memory_test.go — Two complementary memory test suites:
//
// 1. Assertion tests (TestMemory_*): assert hard upper bounds on heap growth
//    for each memory-intensive code path.  These fail CI if a regression occurs.
//    Limits:
//      - MMDB update peak:    < 120 MiB  (was ~150 MiB before streaming write)
//      - MMDB parse (single): <  60 MiB  (the file itself; no download buffer)
//      - CSV parse (stream):  <  30 MiB  (no compressed-bytes buffer)
//      - CSV load from disk:  <  30 MiB  (stream-parsed; no read-all buffer)
//      - 10 config reloads:   <  60 MiB  net growth (goroutine-leak regression)
//
// 2. Integration watch tests (TestMemWatch_*): run the full update lifecycle
//    with a realistically-sized database (~50 MiB MMDB / representative CSV)
//    and emit a per-stage memory report via t.Log.  These never fail on memory
//    alone — they exist to give operators visibility into real-world heap usage.
//    Run with -v to see the report:
//      go test -v -run TestMemWatch ./...

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// heapInuse returns the current HeapInuse value after a forced GC so that
// prior-cycle garbage does not inflate the before/after delta.
func heapInuse(t *testing.T) uint64 {
	t.Helper()
	runtime.GC()
	runtime.GC() // two passes to ensure finalizers have run
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// assertHeapDelta fails the test if the heap grew by more than limitBytes
// between the before and after snapshots.
func assertHeapDelta(t *testing.T, before, after uint64, limitBytes uint64, label string) {
	t.Helper()
	if after < before {
		// HeapInuse shrank — definitely fine.
		return
	}
	delta := after - before
	limitMiB := float64(limitBytes) / (1 << 20)
	deltaMiB := float64(delta) / (1 << 20)
	if delta > limitBytes {
		t.Errorf("%s: heap grew by %.1f MiB, limit is %.1f MiB", label, deltaMiB, limitMiB)
	} else {
		t.Logf("%s: heap grew by %.1f MiB (limit %.1f MiB) — OK", label, deltaMiB, limitMiB)
	}
}

// --------------------------------------------------------------------------
// buildLargeCSVGz builds a representative gzipped CSV that mimics the size of
// the real IPInfo Lite database (≈600 k IPv4 + 200 k IPv6 rows).
// We write real CIDRs so the parser accepts them; country codes cycle through
// a small set so the binary-search structure is populated.
// --------------------------------------------------------------------------

func buildLargeCSVGz(t *testing.T) []byte {
	t.Helper()

	ccs := []string{"US", "DE", "CN", "AU", "GB", "FR", "JP", "BR", "IN", "RU"}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	header := "network,country,country_code,continent,continent_code,asn,as_name,as_domain\n"
	if _, err := gz.Write([]byte(header)); err != nil {
		t.Fatal(err)
	}

	// 600 000 IPv4 /24 rows: 0.x.x.0/24 to 255.x.x.0/24
	count := 0
	for a := 0; a < 256 && count < 600000; a++ {
		for b := 0; b < 256 && count < 600000; b++ {
			for c := 0; c < 256 && count < 600000; c++ {
				cc := ccs[count%len(ccs)]
				row := strings.Join([]string{
					formatIPv4CIDR(a, b, c),
					"Country", cc, "Continent", "CO",
					"", "", "",
				}, ",") + "\n"
				if _, err := gz.Write([]byte(row)); err != nil {
					t.Fatal(err)
				}
				count++
			}
		}
	}

	// 200 000 IPv6 /48 rows
	for i := 0; i < 200000; i++ {
		hi := uint16(i >> 8)
		lo := uint16(i & 0xff)
		cc := ccs[i%len(ccs)]
		cidr := formatIPv6CIDR(hi, lo)
		row := strings.Join([]string{
			cidr, "Country", cc, "Continent", "CO", "", "", "",
		}, ",") + "\n"
		if _, err := gz.Write([]byte(row)); err != nil {
			t.Fatal(err)
		}
	}

	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func formatIPv4CIDR(a, b, c int) string {
	// Use a fixed first octet offset to stay outside private ranges.
	return strings.Join([]string{
		itoa(10 + a%246), itoa(b), itoa(c), "0/24",
	}, ".")
}

func formatIPv6CIDR(hi, lo uint16) string {
	// 2001:0100:: through 2001:xxxx::  — real-world unicast space.
	return "2001:" + hex16(0x0100+hi) + ":" + hex16(lo) + "::/48"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 3)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func hex16(v uint16) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{
		hexChars[(v>>12)&0xf],
		hexChars[(v>>8)&0xf],
		hexChars[(v>>4)&0xf],
		hexChars[v&0xf],
	})
}

// --------------------------------------------------------------------------
// TestMemory_CSVParse: parsing the full CSV should not allocate more than
// 30 MiB above baseline (the parsed ipDatabase is ~8–10 MiB; the streaming
// decompressor adds minimal overhead because we no longer ReadAll the bytes).
// --------------------------------------------------------------------------

func TestMemory_CSVParse(t *testing.T) {
	data := buildLargeCSVGz(t)

	before := heapInuse(t)
	db, err := parseGzippedCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	after := heapInuse(t)

	// Keep db alive until after the measurement.
	_ = len(db.v4) + len(db.v6)

	// 30 MiB: the parsed ipDatabase itself is the dominant cost;
	// no extra buffer for the compressed bytes should be allocated inside
	// parseGzippedCSV since it uses a bytes.NewReader.
	assertHeapDelta(t, before, after, 30<<20, "CSV parse")
}

// --------------------------------------------------------------------------
// TestMemory_CSVLoadFromDisk: loadDatabaseFromDisk must stream-parse without
// reading the full compressed file into a []byte first.
// --------------------------------------------------------------------------

func TestMemory_CSVLoadFromDisk(t *testing.T) {
	data := buildLargeCSVGz(t)

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "test.csv.gz")
	if err := os.WriteFile(csvPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	before := heapInuse(t)
	db, err := loadDatabaseFromDisk(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	after := heapInuse(t)
	_ = len(db.v4) + len(db.v6)

	// 30 MiB: stream-parsed so only the parsed ipDatabase is resident.
	// The old implementation allocated an extra ~10–20 MiB for the
	// compressed-file bytes via io.ReadAll.
	assertHeapDelta(t, before, after, 30<<20, "CSV load from disk")
}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------
// TestMemory_ConfigReloads: simulates 10 Traefik config reloads (each creates
// a new middleware instance via New() and cancels the previous context).  The
// heap must not grow linearly — the orphaned goroutine fix means each old
// instance is released after its context is cancelled and GC runs.
// Limit: < 60 MiB net growth across all 10 reloads (one DB worth of slack).
// --------------------------------------------------------------------------

func TestMemory_ConfigReloads(t *testing.T) {
	// Use a ~10 MiB MMDB (smaller than real-world but large enough to show
	// linear growth clearly if the goroutine leak regresses).
	const targetMiB = 10
	padded := buildPaddedMMDB(t, targetMiB)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(padded)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()

	// Pre-download the MMDB to a single shared path on disk before creating any
	// instance.  This means loadCachedDB() inside New() will load the DB
	// synchronously, so every instance holds a live mmdbReader immediately —
	// no goroutine timing races, and no "could not load from disk" log noise.
	sharedPath := filepath.Join(tmpDir, "shared.mmdb")
	if err := downloadToFile(srv.URL, "test", defaultMMDBBaseURL, sharedPath); err != nil {
		t.Fatalf("pre-download: %v", err)
	}

	newInstance := func(ctx context.Context, i int) http.Handler {
		h, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}), &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: sharedPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		}, fmt.Sprintf("reload-%d", i))
		if err != nil {
			t.Fatalf("New() reload %d: %v", i, err)
		}
		return h
	}

	// Baseline: one instance fully loaded (DB is in memory from loadCachedDB).
	ctx0, cancel0 := context.WithCancel(context.Background())
	_ = newInstance(ctx0, 0)

	before := heapInuse(t)

	// 10 successive reloads: each creates a new instance (which loads the DB
	// synchronously from the shared file) then cancels the previous context,
	// exactly as Traefik does on a config reload.
	var cancelPrev context.CancelFunc = cancel0
	for i := 1; i <= 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		_ = newInstance(ctx, i)
		cancelPrev()
		cancelPrev = cancel
	}
	// Cancel the last instance so nothing is artificially kept alive.
	cancelPrev()

	// Give goroutines a moment to observe ctx.Done() and exit.
	time.Sleep(50 * time.Millisecond)

	after := heapInuse(t)

	// Allow at most one extra DB worth of headroom (60 MiB) across all 10
	// reloads.  If the goroutine leak regresses, each of the 10 orphaned
	// mmdbReaders (~10 MiB each in this test) would accumulate, growing the
	// heap by ~100 MiB — well above this threshold.
	assertHeapDelta(t, before, after, 60<<20, "10 config reloads (goroutine-leak regression)")
}

// TestMemory_MMDBLoad: opening an MMDB reads the file once into a []byte;
// that byte slice IS the working memory for the reader.  We synthesise a
// realistically-sized MMDB (~50 MiB) and verify heap growth stays < 60 MiB.
// --------------------------------------------------------------------------

func TestMemory_MMDBLoad(t *testing.T) {
	// Build a synthetically large MMDB by padding it with trailing zeros
	// after the metadata so it is ~50 MiB in size.  The MMDB reader holds
	// the whole byte slice, so this accurately exercises the footprint.
	baseData := buildTestMMDB(t, mmdbTestEntries)
	padding := make([]byte, 50<<20-len(baseData)) // pad to ~50 MiB total

	// The metadata marker must be the LAST occurrence; we can safely append
	// padding before it by rebuilding: [tree][sep][data][padding][marker][meta].
	// Easiest: just prepend padding to the data section portion.
	// Actually, openMMDB searches for the LAST occurrence of the marker, so we
	// can simply place our padding before the existing blob — wait, the marker
	// is searched from the end so placing padding AFTER the entire blob would
	// be wrong.  Instead, insert padding between data section and marker.
	//
	// The test MMDB layout is:
	//   [treeSec][16-zero-sep][dataSec][marker][metaSec]
	// We need padding such that:
	//   [treeSec][16-zero-sep][dataSec][PADDING][marker][metaSec]
	// Since openMMDB searches for the LAST occurrence of the marker in the raw
	// bytes, and the marker is a fixed 14-byte sequence that won't appear in the
	// padding (all zeros), this is safe.

	markerBytes := []byte(mmdbMetadataMarker)
	markerIdx := lastIndex(baseData, markerBytes)
	if markerIdx < 0 {
		t.Fatal("could not locate metadata marker in test MMDB")
	}

	paddedData := make([]byte, 0, len(baseData)+len(padding))
	paddedData = append(paddedData, baseData[:markerIdx]...)
	paddedData = append(paddedData, padding...)
	paddedData = append(paddedData, baseData[markerIdx:]...)

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "large.mmdb")
	if err := os.WriteFile(mmdbPath, paddedData, 0600); err != nil {
		t.Fatal(err)
	}

	before := heapInuse(t)
	r, err := openMMDB(mmdbPath)
	if err != nil {
		t.Fatal(err)
	}
	after := heapInuse(t)
	_ = r.nodeCount

	// 60 MiB: the ~50 MiB []byte plus small overhead.  No duplicate buffer.
	assertHeapDelta(t, before, after, 60<<20, "MMDB load from disk")
}

// lastIndex returns the byte offset of the last occurrence of needle in haystack,
// or -1 if not found.
func lastIndex(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := len(haystack) - len(needle); i >= 0; i-- {
		if bytes.Equal(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

// --------------------------------------------------------------------------
// TestMemory_MMDBUpdatePeak: the update path must NOT buffer the full download
// in memory before writing to disk.  Before the fix, updateMMDB called
// downloadRaw (→ ~50 MiB buffer) and then openMMDB (→ another ~50 MiB for
// data) while the old mmdbReader was still live — peaking at ~150 MiB.
// After the fix, downloadToFile streams directly to disk, so the peak is
// only: old reader (~50 MiB, freed after swap) + new reader (~50 MiB) ≈ 50 MiB
// extra on top of what was already in place.
// --------------------------------------------------------------------------

func TestMemory_MMDBUpdatePeak(t *testing.T) {
	rawMMDB := buildTestMMDB(t, mmdbTestEntries)

	// Pad to a realistic size (~50 MiB) as in TestMemory_MMDBLoad.
	markerBytes := []byte(mmdbMetadataMarker)
	markerIdx := lastIndex(rawMMDB, markerBytes)
	if markerIdx < 0 {
		t.Fatal("could not locate metadata marker in test MMDB")
	}
	padding := make([]byte, 50<<20-len(rawMMDB))
	paddedData := make([]byte, 0, len(rawMMDB)+len(padding))
	paddedData = append(paddedData, rawMMDB[:markerIdx]...)
	paddedData = append(paddedData, padding...)
	paddedData = append(paddedData, rawMMDB[markerIdx:]...)

	// Serve the padded MMDB via an in-process HTTP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(paddedData)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "update.mmdb")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}),
		name: "mem-test",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: mmdbPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	// Load an initial DB so a swap occurs during the update.
	initialMMDB, err := parseMMDB(paddedData)
	if err != nil {
		t.Fatal(err)
	}
	g.db = initialMMDB

	before := heapInuse(t)
	g.updateMMDB()
	after := heapInuse(t)

	if g.db == nil {
		t.Fatal("db should be set after updateMMDB")
	}

	// 120 MiB: old reader is freed before GC inside updateMMDB; new reader is
	// ~50 MiB.  The download never materialises as a []byte in the process.
	// Pre-fix this peaked at ~150 MiB (download buf + new reader + old reader).
	assertHeapDelta(t, before, after, 120<<20, "MMDB update peak")
}

// ==========================================================================
// memWatcher — per-stage memory reporter for integration watch tests.
//
// Usage:
//
//	w := newMemWatcher(t)
//	w.snapshot("baseline")
//	// ... do work ...
//	w.snapshot("after load")
//	// ... do more work ...
//	w.snapshot("after swap")
//	w.report()   // emits a formatted table via t.Log (visible with -v)
//
// Each snapshot forces two GC cycles so transient allocations do not skew
// the readings.  The report shows HeapInuse, HeapSys, HeapAlloc and the
// delta from the previous stage, making it easy to see exactly where memory
// is consumed during an update cycle.
// ==========================================================================

type memStage struct {
	label     string
	heapInuse uint64 // live heap pages mapped to the allocator
	heapSys   uint64 // total virtual memory reserved by the heap
	heapAlloc uint64 // bytes currently allocated (live objects only)
}

type memWatcher struct {
	t      *testing.T
	stages []memStage
}

func newMemWatcher(t *testing.T) *memWatcher {
	t.Helper()
	return &memWatcher{t: t}
}

// snapshot records current heap stats under label after forcing a full GC.
func (w *memWatcher) snapshot(label string) {
	w.t.Helper()
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	w.stages = append(w.stages, memStage{
		label:     label,
		heapInuse: ms.HeapInuse,
		heapSys:   ms.HeapSys,
		heapAlloc: ms.HeapAlloc,
	})
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }

func signedMiB(a, b uint64) string {
	if b >= a {
		return fmt.Sprintf("+%.1f MiB", mib(b-a))
	}
	return fmt.Sprintf("-%.1f MiB", mib(a-b))
}

// report emits a formatted per-stage memory table via t.Log.
// It is always called — the table is only visible when running with -v.
func (w *memWatcher) report() {
	w.t.Helper()
	if len(w.stages) == 0 {
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%-28s  %10s  %10s  %10s  %12s\n",
		"Stage", "HeapInuse", "HeapSys", "HeapAlloc", "Δ from prev")
	fmt.Fprintf(&sb, "%s\n", strings.Repeat("-", 78))
	for i, s := range w.stages {
		delta := "—"
		if i > 0 {
			delta = signedMiB(w.stages[i-1].heapInuse, s.heapInuse)
		}
		fmt.Fprintf(&sb, "%-28s  %8.1f MiB  %8.1f MiB  %8.1f MiB  %12s\n",
			s.label,
			mib(s.heapInuse),
			mib(s.heapSys),
			mib(s.heapAlloc),
			delta,
		)
	}
	w.t.Log(sb.String())
}

// ==========================================================================
// Integration watch tests — full lifecycle with realistic database sizes.
// These never fail on memory alone; they surface numbers for operators.
// Run: go test -v -run TestMemWatch ./...
// ==========================================================================

// buildPaddedMMDB returns a syntactically valid MMDB padded to ~targetMiB.
func buildPaddedMMDB(t *testing.T, targetMiB int) []byte {
	t.Helper()
	base := buildTestMMDB(t, mmdbTestEntries)
	if len(base) >= targetMiB<<20 {
		return base
	}
	marker := []byte(mmdbMetadataMarker)
	idx := lastIndex(base, marker)
	if idx < 0 {
		t.Fatal("metadata marker not found in test MMDB")
	}
	pad := make([]byte, (targetMiB<<20)-len(base))
	out := make([]byte, 0, len(base)+len(pad))
	out = append(out, base[:idx]...)
	out = append(out, pad...)
	out = append(out, base[idx:]...)
	return out
}

// TestMemWatch_CSVLifecycle monitors heap across the full CSV update lifecycle:
// baseline → initial load from download → swap into middleware.
func TestMemWatch_CSVLifecycle(t *testing.T) {
	data := buildLargeCSVGz(t)

	// Serve the gzipped CSV from an in-process server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "ipinfo_lite.csv.gz")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}),
		name: "memwatch-csv",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabasePath:     csvPath,
			DatabaseURL:      srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	w := newMemWatcher(t)
	w.snapshot("baseline (no db loaded)")

	// First download + parse: no existing DB in place.
	g.updateDatabase()
	w.snapshot("after initial CSV download+parse")

	g.mu.RLock()
	db, _ := g.db.(*ipDatabase)
	g.mu.RUnlock()
	if db == nil {
		t.Fatal("db should be set after updateDatabase")
	}
	t.Logf("CSV database: %d IPv4 ranges, %d IPv6 ranges, file size %.1f MiB (compressed)",
		len(db.v4), len(db.v6), mib(uint64(len(data))))

	// Second update: exercises the old→new swap path.
	g.updateDatabase()
	w.snapshot("after second CSV update (swap)")

	w.report()
}

// TestMemWatch_MMDBLifecycle monitors heap across the full MMDB update lifecycle:
// baseline → first download (streamed to disk) → initial load →
// second update (swap old→new reader).
func TestMemWatch_MMDBLifecycle(t *testing.T) {
	// Use a ~50 MiB MMDB to match real-world IPInfo Lite MMDB size.
	paddedMMDB := buildPaddedMMDB(t, 50)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(paddedMMDB)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "ipinfo_lite.mmdb")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}),
		name: "memwatch-mmdb",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: mmdbPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	w := newMemWatcher(t)
	w.snapshot("baseline (no db loaded)")

	// First download: streams to disk, then opens from disk.
	g.updateMMDB()
	w.snapshot("after initial MMDB download+open")

	g.mu.RLock()
	mmdb, _ := g.db.(*mmdbReader)
	g.mu.RUnlock()
	if mmdb == nil {
		t.Fatal("db should be set after updateMMDB")
	}
	t.Logf("MMDB database: nodeCount=%d recordSize=%d ipVersion=%d file size %.1f MiB",
		mmdb.nodeCount, mmdb.recordSize, mmdb.ipVersion, mib(uint64(len(paddedMMDB))))

	// Second update: old reader swapped out, new reader loaded.
	g.updateMMDB()
	w.snapshot("after second MMDB update (swap old reader)")

	w.report()
}

// TestMemWatch_MMDBConcurrentReads confirms memory profile is stable while
// the middleware is actively serving requests during a background DB swap.
func TestMemWatch_MMDBConcurrentReads(t *testing.T) {
	paddedMMDB := buildPaddedMMDB(t, 50)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(paddedMMDB)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "concurrent.mmdb")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}),
		name: "memwatch-concurrent",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: mmdbPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	// Load the initial DB.
	g.updateMMDB()

	w := newMemWatcher(t)
	w.snapshot("after initial load (before concurrent reads)")

	// Fire 500 ServeHTTP calls (simulates in-flight requests during an update).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "91.0.0.1:1234" // DE — in allowlist
	rec := httptest.NewRecorder()
	for i := 0; i < 500; i++ {
		g.ServeHTTP(rec, req)
	}
	w.snapshot("after 500 concurrent reads")

	// Swap DB while reads are logically in-flight (sequential here, but
	// exercises the same lock path as concurrent goroutines).
	g.updateMMDB()
	w.snapshot("after DB swap during reads")

	w.report()
}

// ==========================================================================
// Real-database integration tests — skipped unless IPINFO_TOKEN is set.
//
// These download the actual IPInfo Lite databases (CSV and MMDB) and run the
// full update lifecycle against them, giving true real-world memory numbers.
//
// Run locally:
//
//	IPINFO_TOKEN=your_token go test -v -run TestMemWatchReal -timeout 5m ./...
//
// They are skipped automatically in CI where IPINFO_TOKEN is absent.
// ==========================================================================

// TestMemWatchReal_MMDB downloads the real IPInfo Lite MMDB (~50 MiB) and
// measures heap across the full lifecycle: initial download → open → second
// update (swap).  Reports exact file size and node count from the live DB.
func TestMemWatchReal_MMDB(t *testing.T) {
	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		t.Skip("IPINFO_TOKEN not set — skipping real-database MMDB memory test")
	}

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "ipinfo_lite_real.mmdb")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}),
		name: "real-mmdb",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            token,
			DatabaseMMDBPath: mmdbPath,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	w := newMemWatcher(t)
	w.snapshot("baseline")

	t.Log("downloading real MMDB from IPInfo…")
	g.updateMMDB()
	w.snapshot("after initial MMDB download+open")

	g.mu.RLock()
	mmdb, ok := g.db.(*mmdbReader)
	g.mu.RUnlock()
	if !ok || mmdb == nil {
		t.Fatal("MMDB not loaded — check token and network connectivity")
	}

	fi, _ := os.Stat(mmdbPath)
	if fi != nil {
		t.Logf("real MMDB: nodeCount=%d recordSize=%d ipVersion=%d file size on disk=%.1f MiB",
			mmdb.nodeCount, mmdb.recordSize, mmdb.ipVersion, mib(uint64(fi.Size())))
	}

	// Spot-check a well-known IP so we know the DB is functional.
	country := mmdb.lookup(net.ParseIP("8.8.8.8"))
	t.Logf("real MMDB lookup 8.8.8.8 → %q (expect US)", country)

	t.Log("running second update (swap)…")
	g.updateMMDB()
	w.snapshot("after second MMDB update (swap)")

	w.report()
}

// TestMemWatchReal_CSV downloads the real IPInfo Lite CSV (~10 MiB gzipped,
// ~150 MiB parsed) and measures heap across the full lifecycle: download →
// parse → second update (swap).  Reports IPv4/IPv6 range counts from the live DB.
func TestMemWatchReal_CSV(t *testing.T) {
	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		t.Skip("IPINFO_TOKEN not set — skipping real-database CSV memory test")
	}

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "ipinfo_lite_real.csv.gz")

	g := &GeoBlock{
		next: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {}),
		name: "real-csv",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            token,
			DatabasePath:     csvPath,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	w := newMemWatcher(t)
	w.snapshot("baseline")

	t.Log("downloading real CSV from IPInfo…")
	g.updateDatabase()
	w.snapshot("after initial CSV download+parse")

	g.mu.RLock()
	db, ok := g.db.(*ipDatabase)
	g.mu.RUnlock()
	if !ok || db == nil {
		t.Fatal("CSV DB not loaded — check token and network connectivity")
	}

	fi, _ := os.Stat(csvPath)
	compressedSize := "unknown"
	if fi != nil {
		compressedSize = fmt.Sprintf("%.1f MiB", mib(uint64(fi.Size())))
	}
	t.Logf("real CSV: %d IPv4 ranges, %d IPv6 ranges, compressed file size=%s",
		len(db.v4), len(db.v6), compressedSize)

	// Spot-check a well-known IP.
	country := db.lookup(net.ParseIP("8.8.8.8"))
	t.Logf("real CSV lookup 8.8.8.8 → %q (expect US)", country)

	t.Log("running second update (swap)…")
	g.updateDatabase()
	w.snapshot("after second CSV update (swap)")

	w.report()
}

// TestMemWatchReal_ConfigReloads downloads the real IPInfo Lite MMDB once,
// then simulates 10 successive Traefik config reloads using New() + context
// cancellation.  It asserts that the heap does not grow linearly (goroutine-
// leak regression) and emits a per-reload memory table via t.Log.
//
// Run locally:
//
//	IPINFO_TOKEN=your_token go test -v -run TestMemWatchReal_ConfigReloads -timeout 5m ./...
func TestMemWatchReal_ConfigReloads(t *testing.T) {
	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		t.Skip("IPINFO_TOKEN not set — skipping real-database config-reload memory test")
	}

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "ipinfo_lite_real.mmdb")

	// Download the real MMDB once — all instances share this path so
	// loadCachedDB() loads the DB synchronously inside New().
	t.Log("downloading real MMDB from IPInfo…")
	if err := downloadToFile("", token, defaultMMDBBaseURL, mmdbPath); err != nil {
		t.Fatalf("download: %v", err)
	}

	fi, err := os.Stat(mmdbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	dbSizeMiB := mib(uint64(fi.Size()))
	t.Logf("real MMDB size on disk: %.1f MiB", dbSizeMiB)

	newInstance := func(ctx context.Context, i int) http.Handler {
		h, err := New(ctx, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}), &Config{
			AllowedCountries: []string{"DE"},
			Token:            token,
			DatabaseMMDBPath: mmdbPath,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
			UpdateInterval:   24,
		}, fmt.Sprintf("real-reload-%d", i))
		if err != nil {
			t.Fatalf("New() reload %d: %v", i, err)
		}
		return h
	}

	w := newMemWatcher(t)

	// Baseline: one instance fully loaded.
	ctx0, cancel0 := context.WithCancel(context.Background())
	_ = newInstance(ctx0, 0)
	w.snapshot("after initial load (reload-0)")

	var cancelPrev context.CancelFunc = cancel0
	for i := 1; i <= 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		_ = newInstance(ctx, i)
		cancelPrev()
		cancelPrev = cancel
		w.snapshot(fmt.Sprintf("after reload-%d (prev ctx cancelled)", i))
	}
	cancelPrev()
	time.Sleep(50 * time.Millisecond) // let goroutines observe ctx.Done()

	w.snapshot("final (all contexts cancelled)")
	w.report()

	// Hard assertion: total heap growth across all 10 reloads must stay below
	// 2× the DB size.  If the goroutine leak regresses, 10 orphaned mmdbReaders
	// accumulate ~10× the DB size — well above this threshold.
	first := w.stages[0].heapInuse
	last := w.stages[len(w.stages)-1].heapInuse
	limitBytes := uint64(2 * dbSizeMiB * (1 << 20))
	assertHeapDelta(t, first, last, limitBytes, "10 real config reloads (goroutine-leak regression)")
}
