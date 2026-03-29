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
	"runtime"
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

	// AddCountryHeader writes an X-Geoblock-Country response header containing
	// the resolved 2-letter country code (or "unknown" / "private") on every
	// request.  When enabled, configure Traefik's access log to capture it:
	//
	//   accessLog:
	//     fields:
	//       headers:
	//         names:
	//           X-Geoblock-Country: keep
	//
	// This makes 403 log lines show the country that triggered the block.
	// Default: false.
	AddCountryHeader bool `json:"addCountryHeader,omitempty"`
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

// geoBlockHandler is the http.Handler returned to Traefik. It wraps *GeoBlock
// with an inner context cancel func. A runtime finalizer on this wrapper calls
// innerCancel when Traefik drops the handler reference (e.g. on a config
// hot-reload). This stops the updater goroutine and allows the *GeoBlock (and
// its ~50 MiB MMDB / ~150 MiB CSV database) to be garbage-collected even when
// the outer lifecycle context passed to New() is never cancelled — which is the
// case with Traefik 2.x where the context is context.Background().
type geoBlockHandler struct {
	*GeoBlock
	innerCancel context.CancelFunc
}

// New creates a new GeoBlock middleware instance.
// ctx is the middleware's lifecycle context provided by Traefik. In Traefik 2.x
// this is typically context.Background() and is never cancelled on hot-reload.
// To guard against that, New() creates an inner context and stores its cancel
// func in a geoBlockHandler wrapper. A runtime finalizer on the wrapper calls
// innerCancel when Traefik drops the handler, stopping the updater goroutine
// and allowing the database to be garbage-collected.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logger.Printf("[geoblock:%s] initializing", name)
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	if config.UpdateInterval <= 0 {
		config.UpdateInterval = 24
	}
	if config.HTTPStatusCode == 0 {
		config.HTTPStatusCode = http.StatusForbidden
	}

	// innerCtx is cancelled either when the outer ctx is cancelled (Traefik
	// shutdown or a Traefik version that properly manages the lifecycle) OR
	// when the finalizer on geoBlockHandler fires (handler discarded on reload).
	innerCtx, innerCancel := context.WithCancel(ctx)

	g := &GeoBlock{
		next:    next,
		name:    name,
		config:  config,
		done:    make(chan struct{}),
		allowed: buildCountrySet(config.AllowedCountries),
		blocked: buildCountrySet(config.BlockedCountries),
	}

	g.loadCachedDB()

	go g.updater(innerCtx)

	// Wrap g in a handler whose finalizer cancels innerCtx. The goroutine holds
	// g (*GeoBlock) directly (not handler), so handler can become unreachable
	// when Traefik drops its reference, triggering the finalizer even while the
	// goroutine is still running. The goroutine then observes ctx.Done() and exits.
	handler := &geoBlockHandler{GeoBlock: g, innerCancel: innerCancel}
	runtime.SetFinalizer(handler, func(h *geoBlockHandler) { h.innerCancel() })

	return handler, nil
}

// validateConfig checks that the configuration is self-consistent and applies
// the default database path when neither backend is explicitly configured.
func validateConfig(config *Config) error {
	if len(config.AllowedCountries) > 0 && len(config.BlockedCountries) > 0 {
		return fmt.Errorf("geoblock: cannot set both allowedCountries and blockedCountries")
	}
	if len(config.AllowedCountries) == 0 && len(config.BlockedCountries) == 0 {
		return fmt.Errorf("geoblock: must set either allowedCountries or blockedCountries")
	}
	if config.Token == "" {
		return fmt.Errorf("geoblock: token is required")
	}
	if config.DatabasePath != "" && config.DatabaseMMDBPath != "" {
		return fmt.Errorf("geoblock: cannot set both databasePath and databaseMMDBPath")
	}
	// Apply the MMDB default only when neither backend is configured.
	if config.DatabasePath == "" && config.DatabaseMMDBPath == "" {
		config.DatabaseMMDBPath = "/tmp/ipinfo_lite.mmdb"
	}
	return nil
}

// buildCountrySet converts a slice of country codes into a lookup set.
// Returns nil for an empty slice.
func buildCountrySet(countries []string) map[string]struct{} {
	if len(countries) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(countries))
	for _, c := range countries {
		m[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	return m
}

// loadCachedDB tries to load a previously cached database file from disk.
func (g *GeoBlock) loadCachedDB() {
	if g.config.DatabaseMMDBPath != "" {
		mmdb, err := openMMDB(g.config.DatabaseMMDBPath)
		if err != nil {
			g.logf("could not load MMDB from disk (will download): %v", err)
			return
		}
		g.db = mmdb
		g.logf("loaded MMDB database from disk")
	} else if g.config.DatabasePath != "" {
		db, err := loadDatabaseFromDisk(g.config.DatabasePath)
		if err != nil {
			g.logf("could not load CSV from disk (will download): %v", err)
			return
		}
		g.db = db
		g.logf("loaded CSV database from disk: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
	}
}

// ServeHTTP handles an incoming HTTP request.
func (g *GeoBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := extractIP(req)
	if ip == nil {
		g.handleDefault(rw, req, "", "unknown")
		return
	}

	if g.config.AllowPrivate && isPrivateIP(ip) {
		if g.config.AddCountryHeader {
			rw.Header().Set("X-Geoblock-Country", "private")
		}
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
	if g.config.AddCountryHeader {
		cc := country
		if cc == "" {
			cc = "unknown"
		}
		rw.Header().Set("X-Geoblock-Country", cc)
	}
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
	if g.config.AddCountryHeader {
		rw.Header().Set("X-Geoblock-Country", reason)
	}
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

func (g *GeoBlock) updater(ctx context.Context) {
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
		case <-ctx.Done():
			return
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
	runtime.GC() // promptly reclaim old database memory

	g.logf("database updated: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
}

func (g *GeoBlock) updateMMDB() {
	// Stream the download directly to disk instead of buffering it in memory
	// first. This avoids a ~50 MB spike from holding both the raw download bytes
	// and the parsed mmdbReader.data simultaneously.
	if err := downloadToFile(g.config.DatabaseMMDBURL, g.config.Token, defaultMMDBBaseURL, g.config.DatabaseMMDBPath); err != nil {
		g.logf("MMDB database download failed: %v", err)
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
	runtime.GC() // promptly reclaim old database memory

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
