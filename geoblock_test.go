package traefik_geoblock_plugin

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- CSV parsing tests ---

func buildTestCSVGz(t *testing.T, csv string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(csv)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const testCSV = `network,country,country_code,continent,continent_code,asn,as_name,as_domain
1.0.0.0/24,Australia,AU,Oceania,OC,AS13335,"Cloudflare, Inc.",cloudflare.com
1.0.1.0/24,China,CN,Asia,AS,,,
1.0.2.0/23,China,CN,Asia,AS,,,
8.8.8.0/24,United States,US,North America,NA,AS15169,"Google LLC",google.com
91.0.0.0/24,Germany,DE,Europe,EU,,,
192.0.2.0/24,United States,US,North America,NA,,,
2001:4860:4860::/48,United States,US,North America,NA,AS15169,"Google LLC",google.com
2a00:1450::/32,Germany,DE,Europe,EU,AS15169,"Google LLC",google.com
`

func TestParseCSV(t *testing.T) {
	data := buildTestCSVGz(t, testCSV)
	db, err := parseGzippedCSV(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(db.v4) != 6 {
		t.Errorf("expected 6 IPv4 ranges, got %d", len(db.v4))
	}
	if len(db.v6) != 2 {
		t.Errorf("expected 2 IPv6 ranges, got %d", len(db.v6))
	}
}

// --- Lookup tests ---

func setupTestDB(t *testing.T) *ipDatabase {
	t.Helper()
	data := buildTestCSVGz(t, testCSV)
	db, err := parseGzippedCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestLookupV4(t *testing.T) {
	db := setupTestDB(t)

	tests := []struct {
		ip      string
		want    string
		comment string
	}{
		{"1.0.0.1", "AU", "Australia range"},
		{"1.0.0.255", "AU", "Australia range end"},
		{"1.0.1.0", "CN", "China range start"},
		{"1.0.2.100", "CN", "China range middle"},
		{"8.8.8.8", "US", "Google DNS"},
		{"91.0.0.128", "DE", "Germany"},
		{"192.0.2.1", "US", "US doc range"},
		{"10.0.0.1", "", "private - not in DB"},
		{"203.0.113.1", "", "not in DB"},
		{"0.0.0.0", "", "zero address"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := db.lookup(ip)
			if got != tt.want {
				t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestLookupV6(t *testing.T) {
	db := setupTestDB(t)

	tests := []struct {
		ip      string
		want    string
		comment string
	}{
		{"2001:4860:4860::8888", "US", "Google DNS v6"},
		{"2001:4860:4860::1", "US", "Google range start area"},
		{"2a00:1450::1", "DE", "Germany v6"},
		{"2001:db8::1", "", "not in DB"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := db.lookup(ip)
			if got != tt.want {
				t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

// --- Private IP tests ---

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := isPrivateIP(ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// --- IP extraction tests ---

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"RemoteAddr with port", "8.8.8.8:12345", "", "", "8.8.8.8"},
		{"RemoteAddr without port", "8.8.8.8", "", "", "8.8.8.8"},
		{"X-Forwarded-For single", "10.0.0.1:1234", "8.8.8.8", "", "8.8.8.8"},
		{"X-Forwarded-For multiple", "10.0.0.1:1234", "8.8.8.8, 10.0.0.2", "", "8.8.8.8"},
		{"X-Real-Ip", "10.0.0.1:1234", "", "91.0.0.1", "91.0.0.1"},
		{"XFF over XRI", "10.0.0.1:1234", "1.2.3.4", "5.6.7.8", "1.2.3.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-Ip", tt.xri)
			}

			ip := extractIP(req)
			if ip == nil {
				t.Fatal("extractIP returned nil")
			}
			if ip.String() != tt.want {
				t.Errorf("extractIP = %s, want %s", ip, tt.want)
			}
		})
	}
}

// --- Country allow/block tests ---

func TestIsCountryAllowed(t *testing.T) {
	t.Run("allowlist mode", func(t *testing.T) {
		g := &GeoBlock{
			config:  &Config{DefaultAllow: false},
			allowed: map[string]struct{}{"DE": {}, "AT": {}, "CH": {}},
		}

		if !g.isCountryAllowed("DE") {
			t.Error("DE should be allowed")
		}
		if g.isCountryAllowed("US") {
			t.Error("US should not be allowed")
		}
		if g.isCountryAllowed("") {
			t.Error("empty should not be allowed (DefaultAllow=false)")
		}
	})

	t.Run("blocklist mode", func(t *testing.T) {
		g := &GeoBlock{
			config:  &Config{DefaultAllow: true},
			blocked: map[string]struct{}{"RU": {}, "CN": {}},
		}

		if g.isCountryAllowed("RU") {
			t.Error("RU should be blocked")
		}
		if g.isCountryAllowed("CN") {
			t.Error("CN should be blocked")
		}
		if !g.isCountryAllowed("DE") {
			t.Error("DE should be allowed")
		}
		if !g.isCountryAllowed("") {
			t.Error("empty should be allowed (DefaultAllow=true)")
		}
	})
}

// --- ServeHTTP integration tests ---

func TestServeHTTP_AllowlistMode(t *testing.T) {
	db := setupTestDB(t)
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next:    next,
		name:    "test",
		config:  &Config{AllowPrivate: true, DefaultAllow: false, HTTPStatusCode: http.StatusForbidden},
		db:      db,
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
	}{
		{"allowed country (DE)", "91.0.0.1:1234", http.StatusOK},
		{"blocked country (US)", "8.8.8.8:1234", http.StatusForbidden},
		{"private IP allowed", "192.168.1.1:1234", http.StatusOK},
		{"unknown IP default-block", "203.0.113.1:1234", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()

			g.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func TestServeHTTP_BlocklistMode(t *testing.T) {
	db := setupTestDB(t)
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next:    next,
		name:    "test",
		config:  &Config{AllowPrivate: true, DefaultAllow: true, HTTPStatusCode: http.StatusForbidden},
		db:      db,
		blocked: map[string]struct{}{"CN": {}},
		done:    make(chan struct{}),
	}

	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
	}{
		{"blocked country (CN)", "1.0.1.1:1234", http.StatusForbidden},
		{"allowed country (US)", "8.8.8.8:1234", http.StatusOK},
		{"allowed country (DE)", "91.0.0.1:1234", http.StatusOK},
		{"private IP", "10.0.0.1:1234", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()

			g.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func TestNew_Validation(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {})

	// Mock server so the updater goroutine doesn't hit the real IPInfo API.
	srv := serveMockDB(t, testCSV)
	defer srv.Close()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "no countries",
			config:  &Config{Token: "test"},
			wantErr: true,
		},
		{
			name:    "both allowed and blocked",
			config:  &Config{AllowedCountries: []string{"DE"}, BlockedCountries: []string{"CN"}, Token: "test"},
			wantErr: true,
		},
		{
			name:    "no token",
			config:  &Config{AllowedCountries: []string{"DE"}},
			wantErr: true,
		},
		{
			name: "valid allowlist",
			config: &Config{
				AllowedCountries: []string{"DE"},
				Token:            "test",
				DatabasePath:     "",
				DatabaseURL:      srv.URL,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := New(context.Background(), next, tt.config, "test")
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if handler == nil {
					t.Error("handler is nil")
				}
				// Stop updater goroutine.
				if g, ok := handler.(*GeoBlock); ok {
					close(g.done)
				}
			}
		})
	}
}

// --- Database update tests ---

// serveMockDB starts an HTTP server that serves a gzipped CSV database.
func serveMockDB(t *testing.T, csvData string) *httptest.Server {
	t.Helper()
	data := buildTestCSVGz(t, csvData)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(data)
	}))
}

func TestUpdateDatabase(t *testing.T) {
	// Start a mock server serving the test database.
	srv := serveMockDB(t, testCSV)
	defer srv.Close()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.csv.gz")

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next: next,
		name: "update-test",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test-token",
			DatabasePath:     dbPath,
			DatabaseURL:      srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	// Verify no database loaded yet.
	g.mu.RLock()
	if g.db != nil {
		t.Fatal("database should be nil before update")
	}
	g.mu.RUnlock()

	// Trigger update.
	g.updateDatabase()

	// Verify database is now loaded.
	g.mu.RLock()
	db := g.db
	g.mu.RUnlock()

	if db == nil {
		t.Fatal("database should be loaded after update")
	}
	csvDB, ok := db.(*ipDatabase)
	if !ok {
		t.Fatal("expected *ipDatabase after CSV update")
	}
	if len(csvDB.v4) == 0 {
		t.Error("expected IPv4 ranges after update")
	}
	if len(csvDB.v6) == 0 {
		t.Error("expected IPv6 ranges after update")
	}

	// Verify database was saved to disk.
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("database file should exist on disk: %v", err)
	}

	// Verify lookup works with updated database.
	ip := net.ParseIP("91.0.0.1")
	country := db.lookup(ip)
	if country != "DE" {
		t.Errorf("expected DE, got %q", country)
	}

	// Verify the middleware serves correctly after update.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "91.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("German IP should be allowed after update, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("US IP should be blocked after update, got %d", rec.Code)
	}
}

func TestUpdateDatabaseFromDisk(t *testing.T) {
	// Write a database to disk, then verify it loads on startup.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cached.csv.gz")

	data := buildTestCSVGz(t, testCSV)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	db, err := loadDatabaseFromDisk(dbPath)
	if err != nil {
		t.Fatalf("failed to load from disk: %v", err)
	}
	if len(db.v4) == 0 {
		t.Error("expected IPv4 ranges from disk cache")
	}

	// Verify lookup.
	country := db.lookup(net.ParseIP("8.8.8.8"))
	if country != "US" {
		t.Errorf("expected US from disk cache, got %q", country)
	}
}

func TestUpdateDatabaseReplacesOld(t *testing.T) {
	// Start with one database, update with a different one, verify the new data is used.
	oldCSV := `network,country,country_code,continent,continent_code,asn,as_name,as_domain
8.8.8.0/24,Germany,DE,Europe,EU,,,
`
	newCSV := `network,country,country_code,continent,continent_code,asn,as_name,as_domain
8.8.8.0/24,United States,US,North America,NA,,,
`

	// Load old database.
	oldData := buildTestCSVGz(t, oldCSV)
	oldDB, err := parseGzippedCSV(oldData)
	if err != nil {
		t.Fatal(err)
	}

	// Start mock server with new database.
	srv := serveMockDB(t, newCSV)
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next: next,
		name: "replace-test",
		config: &Config{
			AllowedCountries: []string{"US"},
			Token:            "test-token",
			DatabaseURL:      srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
		},
		allowed: map[string]struct{}{"US": {}},
		db:      oldDB,
		done:    make(chan struct{}),
	}

	// With old DB, 8.8.8.8 is DE -> should be blocked (only US allowed).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("before update: expected 403 (DE not in allowlist), got %d", rec.Code)
	}

	// Update database.
	g.updateDatabase()

	// With new DB, 8.8.8.8 is US -> should be allowed.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("after update: expected 200 (US in allowlist), got %d", rec.Code)
	}
}

func TestUpdateDatabaseFailureKeepsOld(t *testing.T) {
	// If download fails, the old database should remain active.
	oldData := buildTestCSVGz(t, testCSV)
	oldDB, err := parseGzippedCSV(oldData)
	if err != nil {
		t.Fatal(err)
	}

	// Server that returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	g := &GeoBlock{
		name: "fail-test",
		config: &Config{
			Token:       "test",
			DatabaseURL: srv.URL,
		},
		db:   oldDB,
		done: make(chan struct{}),
	}

	g.updateDatabase()

	g.mu.RLock()
	if g.db != oldDB {
		t.Error("database should not change on failed update")
	}
	g.mu.RUnlock()
}

func TestUpdaterGoroutine(t *testing.T) {
	// Verify the updater goroutine downloads the database when none is loaded.
	srv := serveMockDB(t, testCSV)
	defer srv.Close()

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), next, &Config{
		AllowedCountries: []string{"DE"},
		Token:            "test-token",
		DatabasePath:     t.TempDir() + "/test.csv.gz",
		DatabaseURL:      srv.URL,
		AllowPrivate:     true,
		DefaultAllow:     false,
		UpdateInterval:   24,
		HTTPStatusCode:   http.StatusForbidden,
	}, "goroutine-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	g := handler.(*GeoBlock)
	defer close(g.done)

	// Wait for the updater goroutine to load the database.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.RLock()
		loaded := g.db != nil
		g.mu.RUnlock()
		if loaded {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	g.mu.RLock()
	if g.db == nil {
		t.Fatal("updater goroutine should have loaded the database")
	}
	g.mu.RUnlock()
}

// --- Benchmark ---

func BenchmarkLookupV4(b *testing.B) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(testCSV))
	gz.Close()

	db, _ := parseGzippedCSV(buf.Bytes())
	ip := net.ParseIP("8.8.8.8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.lookup(ip)
	}
}

func BenchmarkLookupV6(b *testing.B) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(testCSV))
	gz.Close()

	db, _ := parseGzippedCSV(buf.Bytes())
	ip := net.ParseIP("2001:4860:4860::8888")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.lookup(ip)
	}
}
