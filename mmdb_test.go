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

	// 3. Serialise the search tree (nodeCount × 6 bytes, 24-bit records).
	treeSec := make([]byte, nodeCount*6)
	for i, n := range nodes {
		left := resolveMMDBRef(n.left, nodeCount)
		right := resolveMMDBRef(n.right, nodeCount)
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

// resolveMMDBRef converts a trie node reference to the MMDB uint32 record value.
// ref == -1 means "no data" (maps to nodeCount); ref < -1 is a data pointer.
func resolveMMDBRef(ref int, nodeCount uint32) uint32 {
	if ref == -1 {
		return nodeCount // "no data" per MMDB spec
	}
	if ref < -1 {
		// Data pointer: ref = -(offset+2) → offset = -(ref+2)
		return nodeCount + 16 + uint32(-(ref + 2))
	}
	return uint32(ref)
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

// ---- Additional helpers ----

// buildTestMMDBImpl is the generalised MMDB builder. recordSize must be 24 or 32.
// encodeRecord and encodeMeta plug in alternative encoders for coverage tests.
func buildTestMMDBImpl(
	t *testing.T,
	entries []testMMDBEntry,
	recordSize uint32,
	encodeRecord func(string) []byte,
	encodeMeta func(uint32, uint32, uint32) []byte,
) []byte {
	t.Helper()

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
		dataSec = append(dataSec, encodeRecord(cc)...)
	}

	const empty = -1
	type trieNode struct{ left, right int }
	nodes := []trieNode{{empty, empty}}

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
	resolveRef := func(ref int) uint32 {
		if ref == empty {
			return nodeCount
		}
		if ref < -1 {
			return nodeCount + 16 + uint32(-(ref + 2))
		}
		return uint32(ref)
	}

	var treeSec []byte
	switch recordSize {
	case 24:
		treeSec = make([]byte, nodeCount*6)
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
	case 32:
		treeSec = make([]byte, nodeCount*8)
		for i, n := range nodes {
			left := resolveRef(n.left)
			right := resolveRef(n.right)
			off := i * 8
			binary.BigEndian.PutUint32(treeSec[off:], left)
			binary.BigEndian.PutUint32(treeSec[off+4:], right)
		}
	default:
		t.Fatalf("unsupported record size: %d", recordSize)
	}

	metaSec := encodeMeta(nodeCount, recordSize, 4)
	var out []byte
	out = append(out, treeSec...)
	out = append(out, make([]byte, 16)...)
	out = append(out, dataSec...)
	out = append(out, []byte(mmdbMetadataMarker)...)
	out = append(out, metaSec...)
	return out
}

// mmdbTestEncodeCountryRecordWithExtra creates a 3-field map record.
// When findStringInMap iterates over the map, it skips "continent_code" (string)
// and "asn" (uint32) via skipValue before finding "country_code".
func mmdbTestEncodeCountryRecordWithExtra(cc string) []byte {
	var buf []byte
	buf = append(buf, (7<<5)|3) // map{3 entries}
	buf = append(buf, mmdbTestEncodeString("continent_code")...)
	buf = append(buf, mmdbTestEncodeString("EU")...)
	buf = append(buf, mmdbTestEncodeString("asn")...)
	buf = append(buf, mmdbTestEncodeUint32(15169)...)
	buf = append(buf, mmdbTestEncodeString("country_code")...)
	buf = append(buf, mmdbTestEncodeString(cc)...)
	return buf
}

// mmdbTestEncodePointer encodes an MMDB size-0 pointer to a given data-section offset.
// Supports offsets 0–2047 (packed into 11 bits).
func mmdbTestEncodePointer(dataOffset uint32) []byte {
	if dataOffset >= 2048 {
		panic("offset out of range for size-0 pointer")
	}
	// ctrl: type=1 (001xxxxx), size indicator bits 4-3 = 00 (size=0),
	// bits 2-0 = high 3 bits of value. Next byte = low 8 bits of value.
	return []byte{
		byte(1<<5) | byte((dataOffset>>8)&0x7),
		byte(dataOffset & 0xff),
	}
}

// mmdbTestEncodeMetadataWithExtra is like mmdbTestEncodeMetadata but adds a
// "database_type" string field, which causes decodeMMDBMetadata to call
// skipMetaValue for the string type (exercises the default case).
func mmdbTestEncodeMetadataWithExtra(nodeCount, recordSize, ipVersion uint32) []byte {
	buf := []byte{(7 << 5) | 4} // map{4 entries}
	buf = append(buf, mmdbTestEncodeString("node_count")...)
	buf = append(buf, mmdbTestEncodeUint32(nodeCount)...)
	buf = append(buf, mmdbTestEncodeString("record_size")...)
	buf = append(buf, mmdbTestEncodeUint32(recordSize)...)
	buf = append(buf, mmdbTestEncodeString("ip_version")...)
	buf = append(buf, mmdbTestEncodeUint32(ipVersion)...)
	buf = append(buf, mmdbTestEncodeString("database_type")...)
	buf = append(buf, mmdbTestEncodeString("test")...) // string type → skipMetaValue
	return buf
}

// buildTestMMDBWithPointer constructs an MMDB where the "country_code" value is
// encoded as an MMDB pointer that references a shared string earlier in the data
// section. This exercises resolvePointer and the pointer branch in decodeStringValue.
func buildTestMMDBWithPointer(t *testing.T) []byte {
	t.Helper()
	// Data section layout:
	//   offset 0: shared "DE" string encoded as MMDB UTF-8 string  [0x42,'D','E']
	//   offset 3: record: map{1}, key="country_code", value=pointer-to-offset-0
	sharedDE := mmdbTestEncodeString("DE") // 3 bytes at data offset 0
	ptrToDE := mmdbTestEncodePointer(0)    // 2 bytes – points to data offset 0

	var dataSec []byte
	dataSec = append(dataSec, sharedDE...) // shared string at offset 0
	recOffset := uint32(len(dataSec))      // = 3
	dataSec = append(dataSec, 0xe1)        // map{1 entry}
	dataSec = append(dataSec, mmdbTestEncodeString("country_code")...)
	dataSec = append(dataSec, ptrToDE...) // pointer value → "DE"

	// Build trie: 91.0.0.0/24 maps to the record at recOffset.
	const empty = -1
	type trieNode struct{ left, right int }
	nodes := []trieNode{{empty, empty}}
	ip := net.ParseIP("91.0.0.0").To4()
	leaf := -(int(recOffset) + 2)
	node := 0
	for i := 0; i < 24; i++ {
		bit := int((ip[i/8] >> uint(7-(i%8))) & 1)
		if i == 23 {
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

	nodeCount := uint32(len(nodes))
	resolveRef := func(ref int) uint32 {
		if ref == empty {
			return nodeCount
		}
		if ref < -1 {
			return nodeCount + 16 + uint32(-(ref + 2))
		}
		return uint32(ref)
	}
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

	metaSec := mmdbTestEncodeMetadata(nodeCount, 24, 4)
	var out []byte
	out = append(out, treeSec...)
	out = append(out, make([]byte, 16)...)
	out = append(out, dataSec...)
	out = append(out, []byte(mmdbMetadataMarker)...)
	out = append(out, metaSec...)
	return out
}

// ---- Additional tests ----

// TestMMDB32BitRecords verifies lookup with a 32-bit record MMDB (8 bytes/node).
func TestMMDB32BitRecords(t *testing.T) {
	data := buildTestMMDBImpl(t, mmdbTestEntries, 32, mmdbTestEncodeCountryRecord, mmdbTestEncodeMetadata)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	if r.recordSize != 32 {
		t.Errorf("recordSize = %d, want 32", r.recordSize)
	}
	tests := []struct{ ip, want string }{
		{"8.8.8.8", "US"},
		{"91.0.0.128", "DE"},
		{"1.0.0.1", "AU"},
		{"203.0.113.1", ""},
	}
	for _, tt := range tests {
		got := r.lookup(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// TestMMDBLookup_MultiFieldRecord looks up in a database where records contain
// extra fields before "country_code", exercising skipValue for string and uint32 types.
func TestMMDBLookup_MultiFieldRecord(t *testing.T) {
	data := buildTestMMDBImpl(t, mmdbTestEntries, 24, mmdbTestEncodeCountryRecordWithExtra, mmdbTestEncodeMetadata)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	tests := []struct{ ip, want string }{
		{"8.8.8.8", "US"},
		{"91.0.0.128", "DE"},
		{"1.0.0.1", "AU"},
		{"203.0.113.1", ""},
	}
	for _, tt := range tests {
		got := r.lookup(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// TestMMDBIPv6AddrOnIPv4DB verifies that an IPv6 address looked up in an IPv4-only
// database returns an empty string (the "IPv6 address queried against IPv4-only DB" guard).
func TestMMDBIPv6AddrOnIPv4DB(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	got := r.lookup(net.ParseIP("2001:4860:4860::8888"))
	if got != "" {
		t.Errorf("IPv6 lookup on IPv4 DB should return empty, got %q", got)
	}
}

// TestMMDBParseError_NoMarker verifies that parseMMDB returns an error when the MMDB
// metadata marker is absent.
func TestMMDBParseError_NoMarker(t *testing.T) {
	_, err := parseMMDB([]byte("not a valid mmdb file at all"))
	if err == nil {
		t.Error("expected an error for missing metadata marker, got nil")
	}
}

// TestMMDBClose verifies that close() is safe to call (it is a no-op).
func TestMMDBClose(t *testing.T) {
	data := buildTestMMDB(t, mmdbTestEntries)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	r.close() // must not panic
}

// TestMMDBMetadataWithStringField builds an MMDB whose metadata map contains an extra
// "database_type" string field. decodeMMDBMetadata hits the default branch and calls
// skipMetaValue to advance past the unknown string value.
func TestMMDBMetadataWithStringField(t *testing.T) {
	data := buildTestMMDBImpl(t, mmdbTestEntries, 24, mmdbTestEncodeCountryRecord, mmdbTestEncodeMetadataWithExtra)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB with extra metadata field: %v", err)
	}
	got := r.lookup(net.ParseIP("8.8.8.8"))
	if got != "US" {
		t.Errorf("lookup(8.8.8.8) = %q, want US", got)
	}
}

// TestMMDBWithPointer builds an MMDB where country_code values are MMDB pointers
// referencing a shared string in the data section. This exercises resolvePointer
// (size-0 case) and the pointer branch in decodeStringValue.
func TestMMDBWithPointer(t *testing.T) {
	data := buildTestMMDBWithPointer(t)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	// 91.0.0.0/24 should resolve to "DE" via the pointer.
	if got := r.lookup(net.ParseIP("91.0.0.1")); got != "DE" {
		t.Errorf("lookup(91.0.0.1) = %q, want DE", got)
	}
	// An IP outside the trie should return "".
	if got := r.lookup(net.ParseIP("8.8.8.8")); got != "" {
		t.Errorf("lookup(8.8.8.8) = %q, want empty", got)
	}
}

// ---- Helpers for extended skipValue / resolvePointer coverage ----

// mmdbTestEncodeDouble encodes a 64-bit floating-point 0.0 value (MMDB type 3).
// skipValue for type 3 always skips exactly 8 bytes.
func mmdbTestEncodeDouble() []byte {
	b := make([]byte, 9)
	b[0] = 0x60 // type=3 (double), sz=0
	// remaining 8 bytes = IEEE 754 representation of 0.0 (all zeros)
	return b
}

// mmdbTestEncodeArrayOfUint32 encodes an MMDB array (extended type 11) containing
// two uint32 values. Used to exercise the case 11 branch in skipValue.
func mmdbTestEncodeArrayOfUint32(a, b uint32) []byte {
	var buf []byte
	buf = append(buf, 0x02) // extended type (type=0), sz=2 elements
	buf = append(buf, 0x04) // next byte: type = 4 + 7 = 11 (array)
	buf = append(buf, mmdbTestEncodeUint32(a)...)
	buf = append(buf, mmdbTestEncodeUint32(b)...)
	return buf
}

// mmdbTestEncodeLongString encodes a UTF-8 string whose length is in [29, 283],
// triggering the sz==29 extended-size branch in extendSize.
func mmdbTestEncodeLongString(s string) []byte {
	if len(s) < 29 || len(s) > 283 {
		panic("string length must be in [29,283] for this helper")
	}
	// ctrl: type=2 (string), sz=29 → triggers extendSize case 29
	// actual length = 29 + next_byte
	return append([]byte{0x5d, byte(len(s) - 29)}, s...)
}

// mmdbTestEncodeAbsolutePointer encodes an MMDB size-3 (absolute, 4-byte) pointer.
// resolvePointer case 3: v = BigEndian.Uint32(data), return dataOffset + v.
func mmdbTestEncodeAbsolutePointer(dataOffset uint32) []byte {
	b := make([]byte, 5)
	b[0] = byte(1<<5) | byte(3<<3) // type=1 (pointer), size indicator = 3
	binary.BigEndian.PutUint32(b[1:], dataOffset)
	return b
}

// mmdbTestEncodeCountryRecordComplex encodes a richly-typed map record that exercises
// multiple branches of skipValue before reaching "country_code":
//   - "accuracy_radius"  → double 0.0              (skipValue case 3)
//   - "geonames_ids"     → array of two uint32s    (skipValue case 11, recursive)
//   - "as_domain"        → 30-char string           (extendSize case 29 in skipValue)
//   - "country_code"     → cc
func mmdbTestEncodeCountryRecordComplex(cc string) []byte {
	longStr := "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPS" // 32 chars; we use first 30
	var buf []byte
	buf = append(buf, (7<<5)|4) // map{4 entries}
	buf = append(buf, mmdbTestEncodeString("accuracy_radius")...)
	buf = append(buf, mmdbTestEncodeDouble()...)
	buf = append(buf, mmdbTestEncodeString("geonames_ids")...)
	buf = append(buf, mmdbTestEncodeArrayOfUint32(123, 456)...)
	buf = append(buf, mmdbTestEncodeString("as_domain")...)
	buf = append(buf, mmdbTestEncodeLongString(longStr[:30])...)
	buf = append(buf, mmdbTestEncodeString("country_code")...)
	buf = append(buf, mmdbTestEncodeString(cc)...)
	return buf
}

// buildTestMMDBWithAbsolutePointer is like buildTestMMDBWithPointer but uses
// a size-3 (absolute 4-byte) pointer, exercising resolvePointer case 3 (default).
func buildTestMMDBWithAbsolutePointer(t *testing.T) []byte {
	t.Helper()
	sharedDE := mmdbTestEncodeString("DE")
	ptrToDE := mmdbTestEncodeAbsolutePointer(0) // absolute pointer to data offset 0

	var dataSec []byte
	dataSec = append(dataSec, sharedDE...)
	recOffset := uint32(len(dataSec)) // = 3
	dataSec = append(dataSec, 0xe1)
	dataSec = append(dataSec, mmdbTestEncodeString("country_code")...)
	dataSec = append(dataSec, ptrToDE...)

	// Build trie for 8.8.8.0/24 → recOffset.
	const empty = -1
	type trieNode struct{ left, right int }
	nodes := []trieNode{{empty, empty}}
	ip := net.ParseIP("8.8.8.0").To4()
	leaf := -(int(recOffset) + 2)
	node := 0
	for i := 0; i < 24; i++ {
		bit := int((ip[i/8] >> uint(7-(i%8))) & 1)
		if i == 23 {
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

	nodeCount := uint32(len(nodes))
	resolveRef := func(ref int) uint32 {
		if ref == empty {
			return nodeCount
		}
		if ref < -1 {
			return nodeCount + 16 + uint32(-(ref + 2))
		}
		return uint32(ref)
	}
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

	metaSec := mmdbTestEncodeMetadata(nodeCount, 24, 4)
	var out []byte
	out = append(out, treeSec...)
	out = append(out, make([]byte, 16)...)
	out = append(out, dataSec...)
	out = append(out, []byte(mmdbMetadataMarker)...)
	out = append(out, metaSec...)
	return out
}

// TestMMDBSkipValue_MoreTypes exercises the double, array, and extended-size string
// branches of skipValue by looking up in a database with complex multi-typed records.
func TestMMDBSkipValue_MoreTypes(t *testing.T) {
	data := buildTestMMDBImpl(t, mmdbTestEntries, 24, mmdbTestEncodeCountryRecordComplex, mmdbTestEncodeMetadata)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	tests := []struct{ ip, want string }{
		{"8.8.8.8", "US"},
		{"91.0.0.128", "DE"},
		{"1.0.0.1", "AU"},
	}
	for _, tt := range tests {
		got := r.lookup(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// TestMMDBWithAbsolutePointer builds an MMDB that uses size-3 (absolute 4-byte)
// pointers for country_code values, exercising the default case in resolvePointer.
func TestMMDBWithAbsolutePointer(t *testing.T) {
	data := buildTestMMDBWithAbsolutePointer(t)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	// 8.8.8.0/24 → "DE" via absolute pointer.
	if got := r.lookup(net.ParseIP("8.8.8.1")); got != "DE" {
		t.Errorf("lookup(8.8.8.1) = %q, want DE", got)
	}
	// Outside the trie returns "".
	if got := r.lookup(net.ParseIP("1.0.0.1")); got != "" {
		t.Errorf("lookup(1.0.0.1) = %q, want empty", got)
	}
}

// ---- IPv6 MMDB (ipVersion=6) builder & tests ----

// buildTestMMDBIPv6 constructs an MMDB with ipVersion=6 that supports both
// IPv4 (as IPv4-mapped, ::x.x.x.x) and native IPv6 entries.
// The trie traverses 128 bits; IPv4 CIDRs are inserted with a 96-zero-bit prefix.
func buildTestMMDBIPv6(t *testing.T, ipv4Entries, ipv6Entries []testMMDBEntry) []byte {
	t.Helper()

	// Collect unique country codes and build the data section.
	ccOrder := make([]string, 0)
	ccSet := make(map[string]bool)
	addCC := func(cc string) {
		cc = strings.ToUpper(cc)
		if !ccSet[cc] {
			ccSet[cc] = true
			ccOrder = append(ccOrder, cc)
		}
	}
	for _, e := range ipv4Entries {
		addCC(e.cc)
	}
	for _, e := range ipv6Entries {
		addCC(e.cc)
	}
	dataSec := []byte{}
	ccOffset := make(map[string]uint32, len(ccOrder))
	for _, cc := range ccOrder {
		ccOffset[cc] = uint32(len(dataSec))
		dataSec = append(dataSec, mmdbTestEncodeCountryRecord(cc)...)
	}

	const empty = -1
	type trieNode struct{ left, right int }
	nodes := []trieNode{{empty, empty}}

	// insert adds a 128-bit prefix to the trie.
	insert := func(ip16 [16]byte, ones int, cc string) {
		offset := ccOffset[strings.ToUpper(cc)]
		node := 0
		for i := 0; i < ones; i++ {
			byteIdx := i / 8
			bitIdx := 7 - (i % 8)
			bit := int((ip16[byteIdx] >> uint(bitIdx)) & 1)
			if i == ones-1 {
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

	// IPv4 CIDRs: encoded as ::x.x.x.x → 96 zero bits then 32 IPv4 bits.
	for _, e := range ipv4Entries {
		_, cidr, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", e.cidr, err)
		}
		ones, _ := cidr.Mask.Size()
		ip4 := cidr.IP.To4()
		var ip16 [16]byte
		copy(ip16[12:], ip4) // bytes 0-11 remain zero
		insert(ip16, 96+ones, e.cc)
	}

	// Native IPv6 CIDRs.
	for _, e := range ipv6Entries {
		_, cidr, err := net.ParseCIDR(e.cidr)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", e.cidr, err)
		}
		ones, _ := cidr.Mask.Size()
		var ip16 [16]byte
		copy(ip16[:], cidr.IP.To16())
		insert(ip16, ones, e.cc)
	}

	nodeCount := uint32(len(nodes))
	resolveRef := func(ref int) uint32 {
		if ref == empty {
			return nodeCount
		}
		if ref < -1 {
			return nodeCount + 16 + uint32(-(ref + 2))
		}
		return uint32(ref)
	}

	// Serialise with 24-bit records (nodeCount well within 2^24 for test data).
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

	metaSec := mmdbTestEncodeMetadata(nodeCount, 24, 6) // ipVersion=6
	var out []byte
	out = append(out, treeSec...)
	out = append(out, make([]byte, 16)...)
	out = append(out, dataSec...)
	out = append(out, []byte(mmdbMetadataMarker)...)
	out = append(out, metaSec...)
	return out
}

// TestMMDBIPv6Database covers the two branches in mmdbReader.lookup that are only
// reachable with an ipVersion=6 database:
//   - IPv4 address → prepends 96 zero bits before traversal
//   - Native IPv6 address → uses ip.To16() directly
func TestMMDBIPv6Database(t *testing.T) {
	ipv4Entries := []testMMDBEntry{
		{"8.8.8.0/24", "US"},
		{"91.0.0.0/24", "DE"},
	}
	ipv6Entries := []testMMDBEntry{
		{"2001:4860:4860::/48", "US"},
		{"2a00:1450::/32", "DE"},
	}

	data := buildTestMMDBIPv6(t, ipv4Entries, ipv6Entries)
	r, err := parseMMDB(data)
	if err != nil {
		t.Fatalf("parseMMDB: %v", err)
	}
	if r.ipVersion != 6 {
		t.Errorf("ipVersion = %d, want 6", r.ipVersion)
	}

	tests := []struct {
		name string
		ip   string
		want string
	}{
		// IPv4 addresses in an ipVersion=6 database — exercises the 96-zero-bit prefix path.
		{"IPv4 US in IPv6 DB", "8.8.8.8", "US"},
		{"IPv4 DE in IPv6 DB", "91.0.0.128", "DE"},
		{"IPv4 not in DB", "1.0.0.1", ""},
		// Native IPv6 addresses — exercises raw = ip.To16() path.
		{"IPv6 US (Google DNS)", "2001:4860:4860::8888", "US"},
		{"IPv6 DE (Google EU)", "2a00:1450::1", "DE"},
		{"IPv6 not in DB", "2001:db8::1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.lookup(net.ParseIP(tt.ip))
			if got != tt.want {
				t.Errorf("lookup(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}
