package traefik_geoblock_plugin

// mmdb_test.go — Tests for the minimal MMDB reader.
//
// buildTestMMDB constructs a syntactically valid MMDB binary from a list of
// CIDR → country_code entries.  The database is IPv4-only with 24-bit records.
//
// MMDB binary layout:
//
//	[search tree — nodeCount×6 bytes]
//	[16 zero separator bytes]
//	[data section: serialised map records]
//	[metadata marker + metadata map]

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- MMDB binary builder ----

type testMMDBEntry struct{ cidr, cc string }

// buildTestMMDB constructs a minimal IPv4 MMDB binary for the given entries.
// It uses 24-bit record size.
func buildTestMMDB(t *testing.T, entries []testMMDBEntry) []byte {
	t.Helper()

	// 1. Build data section: one record per unique CC.
	ccOrder := make([]string, 0, len(entries))
	ccSet := make(map[string]bool)
	for _, e := range entries {
		cc := strings.ToUpper(e.cc)
		if !ccSet[cc] {
			ccSet[cc] = true
			ccOrder = append(ccOrder, cc)
		}
	}

	dataSec := []byte{}
	ccOffset := make(map[string]uint32, len(ccOrder))
	for _, cc := range ccOrder {
		ccOffset[cc] = uint32(len(dataSec))
		dataSec = append(dataSec, mmdbTestEncodeCountryRecord(cc)...)
	}

	// 2. Build the binary trie.
	// A node has a left and right child.  Values are:
	//   >= 0          → child node index
	//   -(1+dataIdx)  → leaf pointing to dataRecords[dataIdx]
	//   -1            → empty ("no data")
	const empty = -1
	type trieNode struct{ left, right int }
	nodes := []trieNode{{empty, empty}} // root = node 0

	for _, e := range entries {
		_, cidr, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", e.cidr, err)
		}
		ones, _ := cidr.Mask.Size()
		cc := strings.ToUpper(e.cc)
		offset := ccOffset[cc]

		ip := cidr.IP.To4()
		node := 0
		for i := 0; i < ones; i++ {
			bit := int((ip[i/8] >> uint(7-(i%8))) & 1)
			if i == ones-1 {
				// Leaf: encode data offset as -(offset+2) so that even offset=0
				// doesn't collide with empty (-1).
				leaf := -(int(offset) + 2)
				if bit == 0 {
					nodes[node].left = leaf
				} else {
					nodes[node].right = leaf
				}
			} else {
				child := nodes[node].left
				if bit == 1 {
					child = nodes[node].right
				}
				if child == empty || child < -1 {
					// Allocate a new node.
					nodes = append(nodes, trieNode{empty, empty})
					child = len(nodes) - 1
					if bit == 0 {
						nodes[node].left = child
					} else {
						nodes[node].right = child
					}
				}
				node = child
			}
		}
	}

	nodeCount := uint32(len(nodes))

	// Helper: convert a node reference to the MMDB uint32 value.
	resolveRef := func(ref int) uint32 {
		if ref == empty {
			return nodeCount // "no data" per MMDB spec
		}
		if ref < -1 {
			// Data pointer: ref = -(offset+2) → offset = -(ref+2)
			dataRecOffset := uint32(-(ref + 2))
			// In MMDB: data pointer value = nodeCount + 16 + dataRecOffset
			return nodeCount + 16 + dataRecOffset
		}
		return uint32(ref)
	}

	// 3. Serialise the search tree (nodeCount × 6 bytes, 24-bit records).
	treeSec := make([]byte, nodeCount*6)
	for i, n := range nodes {
		left := resolveRef(n.left)
		right := resolveRef(n.right)
		off := i * 6
		treeSec[off+0] = byte(left >> 16)
		treeSec[off+1] = byte(left >> 8)
		treeSec[off+2] = byte(left)
		treeSec[off+3] = byte(right >> 16)
		treeSec[off+4] = byte(right >> 8)
		treeSec[off+5] = byte(right)
	}

	// 4. Metadata section.
	metaSec := mmdbTestEncodeMetadata(nodeCount, 24, 4)

	var out []byte
	out = append(out, treeSec...)
	out = append(out, make([]byte, 16)...) // 16 zero separator bytes
	out = append(out, dataSec...)
	out = append(out, []byte("\xab\xcd\xefMaxMind.com")...) // metadata marker
	out = append(out, metaSec...)
	return out
}

func mmdbTestEncodeCountryRecord(cc string) []byte {
	// Encode: map{1 entry} → key "country_code" → value cc.
	// Map control: type=7 (map), size=1 → (7<<5)|1 = 0xe1
	var buf []byte
	buf = append(buf, 0xe1)
	buf = append(buf, mmdbTestEncodeString("country_code")...)
	buf = append(buf, mmdbTestEncodeString(cc)...)
	return buf
}

func mmdbTestEncodeString(s string) []byte {
	// type=2 (string), size=len(s) — only works for len<29.
	if len(s) >= 29 {
		panic("string too long")
	}
	return append([]byte{byte(2<<5) | byte(len(s))}, s...)
}

func mmdbTestEncodeUint32(v uint32) []byte {
	// type=6 (uint32), size=4 → ctrl byte = (6<<5)|4 = 0xc4, then 4 bytes big-endian.
	b := make([]byte, 5)
	b[0] = byte(6<<5) | 4
	binary.BigEndian.PutUint32(b[1:], v)
	return b
}

func mmdbTestEncodeMetadata(nodeCount, recordSize, ipVersion uint32) []byte {
	// Map with 3 entries: (7<<5)|3 = 0xe3.
	buf := []byte{0xe3}
	buf = append(buf, mmdbTestEncodeString("node_count")...)
	buf = append(buf, mmdbTestEncodeUint32(nodeCount)...)
	buf = append(buf, mmdbTestEncodeString("record_size")...)
	buf = append(buf, mmdbTestEncodeUint32(recordSize)...)
	buf = append(buf, mmdbTestEncodeString("ip_version")...)
	buf = append(buf, mmdbTestEncodeUint32(ipVersion)...)
	return buf
}

// ---- Tests ----

var mmdbTestEntries = []testMMDBEntry{
	{"1.0.0.0/24", "AU"},
	{"1.0.1.0/24", "CN"},
	{"8.8.8.0/24", "US"},
	{"91.0.0.0/24", "DE"},
}

func TestParseMMDB(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	if r.nodeCount == 0 {
		t.Error("nodeCount should not be 0")
	}
	if r.recordSize != 24 {
		t.Errorf("recordSize = %d, want 24", r.recordSize)
	}
	if r.ipVersion != 4 {
		t.Errorf("ipVersion = %d, want 4", r.ipVersion)
	}
}

func TestMMDBLookup(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}

	tests := []struct {
		ip   string
		want string
	}{
		{"1.0.0.1", "AU"},
		{"1.0.1.0", "CN"},
		{"8.8.8.8", "US"},
		{"91.0.0.128", "DE"},
		{"10.0.0.1", ""},
		{"203.0.113.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := r.lookup(ip)
			if got != tt.want {
				t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestMMDBFromDisk(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "test.mmdb")
	if err := os.WriteFile(mmdbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	r, err := openMMDB(mmdbPath)
	if err != nil {
		t.Fatalf("openMMDB: %v", err)
	}

	country := r.lookup(net.ParseIP("8.8.8.8"))
	if country != "US" {
		t.Errorf("lookup(8.8.8.8) = %q, want US", country)
	}
}

func TestMMDBServeHTTP(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)
	mmdbDB, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next:    next,
		name:    "mmdb-test",
		config:  &Config{AllowPrivate: true, DefaultAllow: false, HTTPStatusCode: http.StatusForbidden},
		db:      mmdbDB,
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	tests := []struct {
		name       string
		remoteAddr string
		wantCode   int
	}{
		{"allowed DE", "91.0.0.1:1234", http.StatusOK},
		{"blocked US", "8.8.8.8:1234", http.StatusForbidden},
		{"private IP", "192.168.1.1:1234", http.StatusOK},
		{"not in DB", "203.0.113.1:1234", http.StatusForbidden},
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

func TestMMDBUpdateFlow(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	mmdbPath := filepath.Join(tmpDir, "update.mmdb")

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	g := &GeoBlock{
		next: next,
		name: "mmdb-update-test",
		config: &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: mmdbPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
		},
		allowed: map[string]struct{}{"DE": {}},
		done:    make(chan struct{}),
	}

	g.mu.RLock()
	if g.db != nil {
		t.Fatal("db should be nil before update")
	}
	g.mu.RUnlock()

	g.updateMMDB()

	g.mu.RLock()
	db := g.db
	g.mu.RUnlock()

	if db == nil {
		t.Fatal("db should be set after updateMMDB")
	}

	// DE IP should be allowed.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "91.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("DE IP: expected 200, got %d", rec.Code)
	}

	// Verify file saved to disk.
	if _, err := os.Stat(mmdbPath); err != nil {
		t.Errorf("MMDB file not saved: %v", err)
	}
}

func TestNewValidation_MMDB(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {})

	data := buildTestMMDB(t, mmdbTestEntries)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	t.Run("both databasePath and databaseMMDBPath", func(t *testing.T) {
		cfg := &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabasePath:     "/tmp/a.csv.gz",
			DatabaseMMDBPath: "/tmp/a.mmdb",
		}
		_, err := New(context.Background(), next, cfg, "test")
		if err == nil {
			t.Error("expected error for both database paths set")
		}
	})

	t.Run("valid mmdb config", func(t *testing.T) {
		tmpDir := t.TempDir()
		mmdbPath := filepath.Join(tmpDir, "valid.mmdb")
		// Pre-write the MMDB file so the updater goroutine loads from disk
		// and never attempts a download (avoiding a race with srv.Close()).
		if err := os.WriteFile(mmdbPath, buildTestMMDB(t, mmdbTestEntries), 0600); err != nil {
			t.Fatal(err)
		}

		cfg := &Config{
			AllowedCountries: []string{"DE"},
			Token:            "test",
			DatabaseMMDBPath: mmdbPath,
			DatabaseMMDBURL:  srv.URL,
			AllowPrivate:     true,
			DefaultAllow:     false,
			HTTPStatusCode:   http.StatusForbidden,
		}
		handler, err := New(context.Background(), next, cfg, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if handler == nil {
			t.Fatal("handler is nil")
		}
		if g, ok := handler.(*GeoBlock); ok {
			close(g.done)
		}
	})
}
