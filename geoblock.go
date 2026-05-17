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

// downloadGroup ensures that only one goroutine downloads a given database path
// at a time across all GeoBlock instances in the same process.  All other
// goroutines that need the same file wait for the download to complete and then
// load the result from disk — avoiding N parallel downloads when Traefik
// instantiates the plugin N times per pod.
var downloadGroup singleflightGroup

// mmdbSharedCache is a process-wide in-memory cache of loaded MMDB readers,
// keyed by file path. It ensures that concurrent New() calls for the same
// MMDB path (which Traefik issues rapidly on config reconciliation) share a
// single os.ReadFile allocation instead of each reading the ~50 MiB file
// independently and spiking RSS by N×50 MiB simultaneously.
var mmdbSharedCache struct {
	mu      sync.Mutex
	entries map[string]*mmdbReader
}

// acquireSharedMMDB returns the cached *mmdbReader for path, reading and
// caching the file if it is not already present. The cache mutex is held for
// the duration of the file read so that concurrent callers for the same cold
// path serialize: only the first caller reads the file; the rest wait and then
// return the already-cached reader without a second allocation.
func acquireSharedMMDB(path string) (*mmdbReader, error) {
	mmdbSharedCache.mu.Lock()
	defer mmdbSharedCache.mu.Unlock()

	if mmdbSharedCache.entries == nil {
		mmdbSharedCache.entries = make(map[string]*mmdbReader)
	}
	if r, ok := mmdbSharedCache.entries[path]; ok {
		return r, nil
	}
	r, err := openMMDB(path)
	if err != nil {
		return nil, err
	}
	mmdbSharedCache.entries[path] = r
	return r, nil
}

// replaceSharedMMDB reads path from disk and atomically stores the result in
// the cache, replacing any previous entry. It is intended to be called inside
// a downloadGroup.do callback (which already serializes callers for the same
// path), so that by the time the singleflight group releases its waiters the
// fresh reader is available in the cache and waiters can obtain it via
// acquireSharedMMDB without a second disk read.
func replaceSharedMMDB(path string) error {
	r, err := openMMDB(path)
	if err != nil {
		return err
	}
	mmdbSharedCache.mu.Lock()
	if mmdbSharedCache.entries == nil {
		mmdbSharedCache.entries = make(map[string]*mmdbReader)
	}
	mmdbSharedCache.entries[path] = r
	mmdbSharedCache.mu.Unlock()
	return nil
}

// sharedUpdaters maintains a single updater goroutine per database path so that
// N middleware instances sharing the same DB path don't each spawn their own
// goroutine. When Traefik reconciles config, it calls New() once per route —
// without deduplication, 30+ routes means 30+ goroutines (and on every
// hot-reload another 30+ that may linger until a finalizer fires). This caused
// goroutine and memory accumulation leading to OOM kills.
var sharedUpdaters struct {
	mu      sync.Mutex
	entries map[string]*sharedUpdater
}

// sharedUpdater is the single updater goroutine state for a database path.
type sharedUpdater struct {
	refCount int
	cancel   context.CancelFunc
}

// registerUpdater ensures a single updater goroutine is running for the given
// GeoBlock's database path and config. Returns an unregister func that the
// caller must invoke when the middleware instance is discarded.
func registerUpdater(g *GeoBlock) func() {
	key := g.dbKey()

	sharedUpdaters.mu.Lock()
	defer sharedUpdaters.mu.Unlock()

	if sharedUpdaters.entries == nil {
		sharedUpdaters.entries = make(map[string]*sharedUpdater)
	}

	if su, ok := sharedUpdaters.entries[key]; ok {
		su.refCount++
		return func() { unregisterUpdater(key) }
	}

	ctx, cancel := context.WithCancel(context.Background())
	su := &sharedUpdater{refCount: 1, cancel: cancel}
	sharedUpdaters.entries[key] = su

	go sharedUpdaterLoop(ctx, g)

	return func() { unregisterUpdater(key) }
}

// unregisterUpdater decrements the refcount and stops the updater goroutine
// when the last middleware instance for a path is discarded.
func unregisterUpdater(key string) {
	sharedUpdaters.mu.Lock()
	defer sharedUpdaters.mu.Unlock()

	su, ok := sharedUpdaters.entries[key]
	if !ok {
		return
	}
	su.refCount--
	if su.refCount <= 0 {
		su.cancel()
		delete(sharedUpdaters.entries, key)
	}
}

// sharedUpdaterLoop is the single goroutine that keeps the database up to date
// for all middleware instances sharing the same database path.
func sharedUpdaterLoop(ctx context.Context, g *GeoBlock) {
	// If no database is loaded yet, attempt to download immediately.
	mmdbSharedCache.mu.Lock()
	_, loaded := mmdbSharedCache.entries[g.config.DatabaseMMDBPath]
	mmdbSharedCache.mu.Unlock()

	if !loaded && g.config.DatabaseMMDBPath != "" {
		g.runUpdate()
	} else if g.config.DatabasePath != "" {
		g.mu.RLock()
		needsDownload := g.db == nil
		g.mu.RUnlock()
		if needsDownload {
			g.runUpdate()
		}
	}

	ticker := time.NewTicker(time.Duration(g.config.UpdateInterval) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			g.runUpdate()
		case <-ctx.Done():
			return
		}
	}
}

// singleflightGroup is a minimal singleflight implementation that suppresses
// duplicate calls for the same key.  Unlike golang.org/x/sync/singleflight it
// does not share the return value — callers that arrive while a download is
// in-flight simply wait and then load the file from disk themselves.
type singleflightGroup struct {
	mu sync.Mutex
	m  map[string]*sync.WaitGroup
}

// do calls fn exactly once for a given key.  Concurrent callers with the same
// key block until fn returns, then return (false, nil) so they can load the
// result from disk.  The caller that actually ran fn receives (true, err).
func (g *singleflightGroup) do(key string, fn func() error) (ran bool, err error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sync.WaitGroup)
	}
	if wg, ok := g.m[key]; ok {
		// Another goroutine is already downloading — wait for it, then return.
		g.mu.Unlock()
		wg.Wait()
		return false, nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	g.m[key] = wg
	g.mu.Unlock()

	err = fn()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	wg.Done()
	return true, err
}

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

// geoResult holds the geographic information resolved for an IP address.
type geoResult struct {
	Country string // 2-letter ISO country code, e.g. "DE"
	City    string // city name, e.g. "Berlin" — only populated by the MMDB backend
}

// ipLookup is the common interface for both the CSV and MMDB lookup backends.
type ipLookup interface {
	lookup(ip net.IP) geoResult
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
}

// dbKey returns the deduplication key for the database backend. It is used by
// the shared updater registry so that all middleware instances using the same
// database path share a single updater goroutine.
func (g *GeoBlock) dbKey() string {
	if g.config.DatabaseMMDBPath != "" {
		return "mmdb:" + g.config.DatabaseMMDBPath
	}
	if g.config.DatabasePath != "" {
		return "csv:" + g.config.DatabasePath
	}
	return "csv:default"
}

// geoBlockHandler is the http.Handler returned to Traefik. It wraps *GeoBlock
// with an unregister func. A runtime finalizer on this wrapper calls unregister
// when Traefik drops the handler reference (e.g. on a config hot-reload). This
// decrements the shared updater's refcount and, when it hits zero, stops the
// updater goroutine.
type geoBlockHandler struct {
	*GeoBlock
	unregister func()
}

// New creates a new GeoBlock middleware instance.
// A single updater goroutine is shared across all instances that use the same
// database path, preventing goroutine accumulation when Traefik creates many
// middleware instances (one per route) during config reconciliation.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
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

	g := &GeoBlock{
		next:    next,
		name:    name,
		config:  config,
		allowed: buildCountrySet(config.AllowedCountries),
		blocked: buildCountrySet(config.BlockedCountries),
	}

	g.loadCachedDB()

	// Register with the shared updater for this database path. The first
	// instance to register starts the goroutine; subsequent instances just
	// bump the refcount. The returned unregister func is called by the
	// finalizer when Traefik discards the handler.
	unregister := registerUpdater(g)

	handler := &geoBlockHandler{GeoBlock: g, unregister: unregister}
	runtime.SetFinalizer(handler, func(h *geoBlockHandler) { h.unregister() })

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
		mmdb, err := acquireSharedMMDB(g.config.DatabaseMMDBPath)
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

	start := time.Now()
	country := lookup.lookup(ip)
	elapsed := time.Since(start)
	if g.config.AddCountryHeader {
		cc := country.Country
		if cc == "" {
			cc = "unknown"
		}
		rw.Header().Set("X-Geoblock-Country", cc)
		if country.City != "" {
			rw.Header().Set("X-Geoblock-City", country.City)
		}
	}
	if g.isCountryAllowed(country.Country) {
		if g.config.LogEnabled {
			g.logf("allowed %s country=%s lookup=%s", ip, country.Country, elapsed)
		}
		g.next.ServeHTTP(rw, req)
	} else {
		if g.config.LogEnabled {
			g.logf("blocked %s country=%s lookup=%s", ip, country.Country, elapsed)
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

func (g *GeoBlock) runUpdate() {
	if g.config.DatabaseMMDBPath != "" {
		g.updateMMDB()
	} else {
		g.updateDatabase()
	}
}

func (g *GeoBlock) updateDatabase() {
	var db *ipDatabase
	dbKey := g.config.DatabasePath
	if dbKey == "" {
		dbKey = "csv:default"
	}
	ran, err := downloadGroup.do(dbKey, func() error {
		parsed, data, dlErr := downloadAndParse(g.config.DatabaseURL, g.config.Token)
		if dlErr != nil {
			return dlErr
		}
		db = parsed
		if g.config.DatabasePath != "" {
			if saveErr := saveToDisk(g.config.DatabasePath, data); saveErr != nil {
				g.logf("failed to save database to disk: %v", saveErr)
			}
		}
		return nil
	})
	if err != nil {
		g.logf("database update failed: %v", err)
		return
	}
	if !ran {
		// Another instance did the download; load from disk.
		if g.config.DatabasePath != "" {
			loaded, loadErr := loadDatabaseFromDisk(g.config.DatabasePath)
			if loadErr != nil {
				g.logf("failed to load CSV from disk after peer download: %v", loadErr)
				return
			}
			db = loaded
		} else {
			return // in-memory only, nothing to load
		}
	}
	if db == nil {
		return
	}

	g.mu.Lock()
	g.db = db
	g.mu.Unlock()
	runtime.GC() // promptly reclaim old database memory

	if ran {
		g.logf("database updated: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
	} else {
		g.logf("database loaded from disk: %d IPv4, %d IPv6 ranges", len(db.v4), len(db.v6))
	}
}

func (g *GeoBlock) updateMMDB() {
	// downloadGroup ensures only one goroutine per path downloads at a time.
	// All other concurrent instances wait, then load the result from disk.
	ran, err := downloadGroup.do(g.config.DatabaseMMDBPath, func() error {
		if dlErr := downloadToFile(g.config.DatabaseMMDBURL, g.config.Token, defaultMMDBBaseURL, g.config.DatabaseMMDBPath); dlErr != nil {
			return dlErr
		}
		// Replace the shared cache entry inside the singleflight callback.
		// By the time do() releases its waiters, the fresh reader is already
		// cached, so all waiting instances get it via acquireSharedMMDB below
		// without a second disk read.
		return replaceSharedMMDB(g.config.DatabaseMMDBPath)
	})
	if err != nil {
		g.logf("MMDB database download failed: %v", err)
		return
	}
	if !ran {
		g.logf("MMDB downloaded by peer instance, loading from shared cache")
	}

	mmdb, err := acquireSharedMMDB(g.config.DatabaseMMDBPath)
	if err != nil {
		g.logf("failed to load MMDB database: %v", err)
		return
	}

	g.mu.Lock()
	g.db = mmdb
	g.mu.Unlock()
	runtime.GC() // promptly reclaim old database memory

	if ran {
		g.logf("MMDB database updated")
	} else {
		g.logf("MMDB database loaded from shared cache")
	}
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
