package traefik_geoblock_plugin

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ipv4Range represents a contiguous IPv4 address range belonging to a country.
type ipv4Range struct {
	start   uint32
	end     uint32
	country [2]byte
}

// ipv6Range represents a contiguous IPv6 address range belonging to a country.
type ipv6Range struct {
	start   [16]byte
	end     [16]byte
	country [2]byte
}

// ipDatabase holds sorted IP ranges for fast binary-search lookup.
type ipDatabase struct {
	v4 []ipv4Range
	v6 []ipv6Range
}

// lookup returns the 2-letter country code for the given IP, or "" if not found.
func (db *ipDatabase) lookup(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return db.lookupV4(ipToUint32(v4))
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	var addr [16]byte
	copy(addr[:], v6)
	return db.lookupV6(addr)
}

// lookupV4 performs a binary search on sorted IPv4 ranges.
func (db *ipDatabase) lookupV4(ip uint32) string {
	n := len(db.v4)
	if n == 0 {
		return ""
	}

	// Find the first index where start > ip; the candidate is at idx-1.
	idx := sort.Search(n, func(i int) bool {
		return db.v4[i].start > ip
	})

	if idx == 0 {
		return ""
	}
	idx--

	if ip <= db.v4[idx].end {
		return string(db.v4[idx].country[:])
	}
	return ""
}

// lookupV6 performs a binary search on sorted IPv6 ranges.
func (db *ipDatabase) lookupV6(ip [16]byte) string {
	n := len(db.v6)
	if n == 0 {
		return ""
	}

	idx := sort.Search(n, func(i int) bool {
		return bytes.Compare(db.v6[i].start[:], ip[:]) > 0
	})

	if idx == 0 {
		return ""
	}
	idx--

	if bytes.Compare(ip[:], db.v6[idx].end[:]) <= 0 {
		return string(db.v6[idx].country[:])
	}
	return ""
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

// parseCSV parses the IPInfo Lite CSV into an ipDatabase.
// Format: network (CIDR), country, country_code, continent, continent_code, ...
func parseCSV(r io.Reader) (*ipDatabase, error) {
	reader := csv.NewReader(r)
	reader.ReuseRecord = true

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	networkIdx, countryCodeIdx := findCSVColumns(header)
	if networkIdx == -1 || countryCodeIdx == -1 {
		return nil, fmt.Errorf("missing required columns (need network, country_code); got: %s", strings.Join(header, ", "))
	}

	maxCol := networkIdx
	if countryCodeIdx > maxCol {
		maxCol = countryCodeIdx
	}

	db := &ipDatabase{
		v4: make([]ipv4Range, 0, 600000),
		v6: make([]ipv6Range, 0, 200000),
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading record: %w", err)
		}

		if len(record) <= maxCol {
			continue
		}

		country := strings.ToUpper(strings.TrimSpace(record[countryCodeIdx]))
		if len(country) != 2 {
			continue
		}

		network := strings.TrimSpace(record[networkIdx])
		_, cidr, parseErr := net.ParseCIDR(network)
		if parseErr != nil {
			continue
		}

		var cc [2]byte
		cc[0] = country[0]
		cc[1] = country[1]
		appendIPRange(db, cidr, cc)
	}

	sort.Slice(db.v4, func(i, j int) bool {
		return db.v4[i].start < db.v4[j].start
	})
	sort.Slice(db.v6, func(i, j int) bool {
		return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0
	})

	return db, nil
}

// findCSVColumns scans the CSV header row and returns the zero-based indices of
// the "network" and "country_code" columns. Returns -1 for any column not found.
func findCSVColumns(header []string) (networkIdx, countryCodeIdx int) {
	networkIdx, countryCodeIdx = -1, -1
	for i, col := range header {
		switch strings.TrimSpace(strings.ToLower(col)) {
		case "network":
			networkIdx = i
		case "country_code":
			countryCodeIdx = i
		}
	}
	return
}

// appendIPRange adds the CIDR range with the given country code to db.
func appendIPRange(db *ipDatabase, cidr *net.IPNet, cc [2]byte) {
	startIP := cidr.IP
	endIP := lastIP(cidr)
	if v4Start := startIP.To4(); v4Start != nil {
		v4End := endIP.To4()
		if v4End == nil {
			return
		}
		db.v4 = append(db.v4, ipv4Range{
			start:   ipToUint32(v4Start),
			end:     ipToUint32(v4End),
			country: cc,
		})
	} else {
		var s, e [16]byte
		copy(s[:], startIP.To16())
		copy(e[:], endIP.To16())
		db.v6 = append(db.v6, ipv6Range{
			start:   s,
			end:     e,
			country: cc,
		})
	}
}

// lastIP returns the last (broadcast) IP in a CIDR network.
func lastIP(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	for i := range n.IP {
		ip[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip
}

func parseGzippedCSV(data []byte) (*ipDatabase, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompressing database: %w", err)
	}
	defer gz.Close()

	return parseCSV(gz)
}

const defaultBaseURL = "https://ipinfo.io/data/ipinfo_lite.csv.gz"
const defaultMMDBBaseURL = "https://ipinfo.io/data/ipinfo_lite.mmdb"

func buildDownloadURL(overrideURL, token, baseURL string) string {
	if overrideURL != "" {
		// Test overrides are passed verbatim (they don't need the token appended
		// because the mock server ignores query parameters).
		v := url.Values{}
		v.Set("token", token)
		return overrideURL + "?" + v.Encode()
	}
	v := url.Values{}
	v.Set("token", token)
	return baseURL + "?" + v.Encode()
}

// downloadRaw downloads a raw file from the given URL (with token auth) and
// returns the raw bytes. baseURL is used if overrideURL is empty.
func downloadRaw(overrideURL, token, baseURL string) ([]byte, error) {
	downloadURL := buildDownloadURL(overrideURL, token, baseURL)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL) //nolint:gosec // URL is constructed internally
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// downloadAndParse downloads the IPInfo Lite CSV database and parses it.
// Returns the parsed database and the raw gzipped bytes (for caching to disk).
func downloadAndParse(overrideURL, token string) (*ipDatabase, []byte, error) {
	data, err := downloadRaw(overrideURL, token, defaultBaseURL)
	if err != nil {
		return nil, nil, err
	}

	db, err := parseGzippedCSV(data)
	if err != nil {
		return nil, nil, err
	}

	return db, data, nil
}

func loadDatabaseFromDisk(path string) (*ipDatabase, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Stream-parse directly from the file to avoid a ~10–20 MB buffer for the
	// compressed CSV bytes.
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("decompressing database: %w", err)
	}
	defer gz.Close()

	return parseCSV(gz)
}

// saveToDisk writes data atomically (write to tmp, then rename).
func saveToDisk(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(data)
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(tmp)
		return writeErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}

	return os.Rename(tmp, path)
}

// streamToFile copies r to path atomically via a temp file + rename,
// without buffering the full content in memory.
// A unique temp file name is used per call so that concurrent goroutines
// downloading the same destination path do not corrupt each other's writes.
func streamToFile(r io.Reader, path string) error {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	// os.CreateTemp gives a unique name, preventing concurrent goroutines from
	// writing to the same .tmp file and interleaving their bytes.
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()

	_, writeErr := io.Copy(f, r)
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(tmp)
		return writeErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}

	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, path)
}

// downloadToFile streams a file from url directly to destPath without
// buffering the full response body in memory. This avoids the ~50 MB
// allocation that downloadRaw would create when fetching the MMDB.
func downloadToFile(overrideURL, token, baseURL, destPath string) error {
	downloadURL := buildDownloadURL(overrideURL, token, baseURL)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL) //nolint:gosec // URL is constructed internally
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	return streamToFile(resp.Body, destPath)
}
