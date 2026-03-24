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

	networkIdx, countryCodeIdx := -1, -1
	for i, col := range header {
		switch strings.TrimSpace(strings.ToLower(col)) {
		case "network":
			networkIdx = i
		case "country_code":
			countryCodeIdx = i
		}
	}

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

		startIP := cidr.IP
		endIP := lastIP(cidr)

		if v4Start := startIP.To4(); v4Start != nil {
			v4End := endIP.To4()
			if v4End == nil {
				continue
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

	sort.Slice(db.v4, func(i, j int) bool {
		return db.v4[i].start < db.v4[j].start
	})
	sort.Slice(db.v6, func(i, j int) bool {
		return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0
	})

	return db, nil
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

func buildDownloadURL(baseURL, token string) string {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	v := url.Values{}
	v.Set("token", token)
	return baseURL + "?" + v.Encode()
}

// downloadAndParse downloads the IPInfo Lite database and parses it.
// Returns the parsed database and the raw gzipped bytes (for caching to disk).
func downloadAndParse(baseURL, token string) (*ipDatabase, []byte, error) {
	downloadURL := buildDownloadURL(baseURL, token)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response body: %w", err)
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

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return parseGzippedCSV(data)
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
