// Package traefik_geoblock_plugin is a Traefik middleware plugin that blocks or allows
// requests based on geographic location using the IPInfo Lite database.
package traefik_geoblock_plugin

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds the plugin configuration.
type Config struct {
	// AllowedCountries is a list of allowed country codes (allowlist mode).
	// Cannot be set together with BlockedCountries.
	AllowedCountries []string `json:"allowedCountries,omitempty"`

	// BlockedCountries is a list of blocked country codes (blocklist mode).
	// Cannot be set together with AllowedCountries.
	BlockedCountries []string `json:"blockedCountries,omitempty"`

	// Token is the IPInfo API token for downloading the database.
	Token string `json:"token,omitempty"`

	// DatabasePath is the filesystem path to cache the gzipped CSV database.
	// Mutually exclusive with DatabaseMMDBPath.
	DatabasePath string `json:"databasePath,omitempty"`

	// DatabaseURL overrides the default IPInfo CSV download URL (for testing).
	DatabaseURL string `json:"databaseURL,omitempty"`

	// DatabaseMMDBPath is the filesystem path to cache the MMDB database.
	// When set, the MMDB backend is used instead of the CSV backend.
	// The MMDB file (~50 MB) is loaded into memory from disk on startup and
	// after each automatic update, using significantly less memory than the
	// parsed CSV database (~150 MB).
	// Mutually exclusive with DatabasePath.
	DatabaseMMDBPath string `json:"databaseMMDBPath,omitempty"`

	// DatabaseMMDBURL overrides the default IPInfo MMDB download URL (for testing).
	DatabaseMMDBURL string `json:"databaseMMDBURL,omitempty"`

	// UpdateInterval is the number of hours between automatic database updates.
	// Default: 24.
	UpdateInterval int `json:"updateInterval,omitempty"`

	// AllowPrivate allows requests from private/reserved IP ranges.
	// Default: true.
	AllowPrivate bool `json:"allowPrivate,omitempty"`

	// DefaultAllow determines behavior when an IP is not found in the database
	// or when the database is not yet loaded. Default: true.
	DefaultAllow bool `json:"defaultAllow,omitempty"`

	// LogEnabled enables logging of allowed/blocked requests.
	LogEnabled bool `json:"logEnabled,omitempty"`

	// HTTPStatusCode is the HTTP status code returned for blocked requests.
	// Default: 403.
	HTTPStatusCode int `json:"httpStatusCode,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		UpdateInterval: 24,
		AllowPrivate:   true,
		DefaultAllow:   true,
		HTTPStatusCode: http.StatusForbidden,
	}
}

// ipLookup is the common interface for both the CSV and MMDB lookup backends.
type ipLookup interface {
	lookup(ip net.IP) string
}

// GeoBlock is a Traefik middleware plugin for geo-blocking.
type GeoBlock struct {
	next   http.Handler
	name   string
	config *Config

	mu sync.RWMutex
	db ipLookup // either *ipDatabase (CSV) or *mmdbReader (MMDB)

	allowed map[string]struct{}
	blocked map[string]struct{}

	done chan struct{}
}

// New creates a new GeoBlock middleware instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.AllowedCountries) > 0 && len(config.BlockedCountries) > 0 {
		return nil, fmt.Errorf("geoblock: cannot set both allowedCountries and blockedCountries")
	}
	if len(config.AllowedCountries) == 0 && len(config.BlockedCountries) == 0 {
		return nil, fmt.Errorf("geoblock: must set either allowedCountries or blockedCountries")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("geoblock: token is required")
	}

	if config.DatabasePath != "" && config.DatabaseMMDBPath != "" {
		return nil, fmt.Errorf("geoblock: cannot set both databasePath and databaseMMDBPath")
	}
	// Apply the CSV default only when MMDB is not configured.
	if config.DatabasePath == "" && config.DatabaseMMDBPath == "" {
		config.DatabasePath = "/tmp/ipinfo_lite.csv.gz"
	}

	if config.UpdateInterval <= 0 {
		config.UpdateInterval = 24
	}
	if config.HTTPStatusCode == 0 {
		config.HTTPStatusCode = http.StatusForbidden
	}

	g := &GeoBlock{
		next:   next,
		name:   name,
		config: config,
		done:   make(chan struct{}),
	}

	if len(config.AllowedCountries) > 0 {
		g.allowed = make(map[string]struct{}, len(config.AllowedCountries))
		for _, c := range config.AllowedCountries {
			g.allowed[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
		}
	}
	if len(config.BlockedCountries) > 0 {
		g.blocked = make(map[string]struct{}, len(config.BlockedCountries))
		for _, c := range config.BlockedCountries {
			g.blocked[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
		}
	}

	// Try loading cached database from disk.
	if config.DatabaseMMDBPath != "" {
		if mmdb, err := openMMDB(config.DatabaseMMDBPath); err == nil {
			g.db = mmdb
			g.logf("loaded MMDB database from disk")
		}
	} else if config.DatabasePath != "" {
		if db, err := loadDatabaseFromDisk(config.DatabasePath); err == nil {
			g.db = db
			g.logf("loaded CSV database from disk: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
		}
	}

	go g.updater()

	return g, nil
}

// ServeHTTP handles an incoming HTTP request.
func (g *GeoBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := extractIP(req)
	if ip == nil {
		g.handleDefault(rw, req, "", "unknown")
		return
	}

	if g.config.AllowPrivate && isPrivateIP(ip) {
		g.next.ServeHTTP(rw, req)
		return
	}

	g.mu.RLock()
	lookup := g.db
	g.mu.RUnlock()

	if lookup == nil {
		g.handleDefault(rw, req, ip.String(), "db-not-loaded")
		return
	}

	country := lookup.lookup(ip)
	if g.isCountryAllowed(country) {
		if g.config.LogEnabled {
			g.logf("allowed %s country=%s", ip, country)
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogEnabled {
			g.logf("blocked %s country=%s", ip, country)
		}
		rw.WriteHeader(g.config.HTTPStatusCode)
	}
}

func (g *GeoBlock) handleDefault(rw http.ResponseWriter, req *http.Request, ip, reason string) {
	if g.config.DefaultAllow {
		if g.config.LogEnabled {
			g.logf("default-allow %s reason=%s", ip, reason)
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogEnabled {
			g.logf("default-block %s reason=%s", ip, reason)
		}
		rw.WriteHeader(g.config.HTTPStatusCode)
	}
}

func (g *GeoBlock) isCountryAllowed(country string) bool {
	if country == "" {
		return g.config.DefaultAllow
	}

	if g.allowed != nil {
		_, ok := g.allowed[country]
		return ok
	}

	if g.blocked != nil {
		_, ok := g.blocked[country]
		return !ok
	}

	return g.config.DefaultAllow
}

func (g *GeoBlock) updater() {
	// If no database is loaded yet, download immediately.
	g.mu.RLock()
	needsDownload := g.db == nil
	g.mu.RUnlock()

	if needsDownload {
		if g.config.DatabaseMMDBPath != "" {
			g.updateMMDB()
		} else {
			g.updateDatabase()
		}
	}

	ticker := time.NewTicker(time.Duration(g.config.UpdateInterval) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if g.config.DatabaseMMDBPath != "" {
				g.updateMMDB()
			} else {
				g.updateDatabase()
			}
		case <-g.done:
			return
		}
	}
}

func (g *GeoBlock) updateDatabase() {
	db, data, err := downloadAndParse(g.config.DatabaseURL, g.config.Token)
	if err != nil {
		g.logf("database update failed: %v", err)
		return
	}

	if g.config.DatabasePath != "" {
		if err := saveToDisk(g.config.DatabasePath, data); err != nil {
			g.logf("failed to save database to disk: %v", err)
		}
	}

	g.mu.Lock()
	g.db = db
	g.mu.Unlock()

	g.logf("database updated: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
}

func (g *GeoBlock) updateMMDB() {
	data, err := downloadRaw(g.config.DatabaseMMDBURL, g.config.Token, defaultMMDBBaseURL)
	if err != nil {
		g.logf("MMDB database download failed: %v", err)
		return
	}

	if err := saveToDisk(g.config.DatabaseMMDBPath, data); err != nil {
		g.logf("failed to save MMDB database to disk: %v", err)
		return
	}

	mmdb, err := openMMDB(g.config.DatabaseMMDBPath)
	if err != nil {
		g.logf("failed to open MMDB database: %v", err)
		return
	}

	g.mu.Lock()
	if old, ok := g.db.(*mmdbReader); ok {
		old.close()
	}
	g.db = mmdb
	g.mu.Unlock()

	g.logf("MMDB database updated")
}

var logger = log.New(os.Stdout, "", log.LstdFlags)

func (g *GeoBlock) logf(format string, args ...interface{}) {
	logger.Printf("[geoblock:%s] %s", g.name, fmt.Sprintf(format, args...))
}

func extractIP(req *http.Request) net.IP {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
			return ip
		}
	}

	if xri := req.Header.Get("X-Real-Ip"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return net.ParseIP(req.RemoteAddr)
	}
	return net.ParseIP(host)
}

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
