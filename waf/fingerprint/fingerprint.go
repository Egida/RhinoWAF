package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fingerprint represents a unique browser/device signature
type Fingerprint struct {
	Hash         string // SHA-256 hash of all fingerprint components
	UserAgent    string
	AcceptLang   string
	AcceptEnc    string
	ScreenRes    string // From client-side JS
	Timezone     string // From client-side JS
	Canvas       string // Canvas fingerprint hash
	WebGL        string // WebGL fingerprint hash
	Fonts        string // Available fonts list
	Plugins      string // Browser plugins
	DoNotTrack   string
	Platform     string
	CPUCores     string
	DeviceMemory string
	CreatedAt    time.Time
	LastSeen     time.Time
	SeenCount    int
	IPs          []string // IPs that used this fingerprint
}

// FingerprintData contains client-side collected data
type FingerprintData struct {
	ScreenWidth    int      `json:"screen_width"`
	ScreenHeight   int      `json:"screen_height"`
	ColorDepth     int      `json:"color_depth"`
	TimezoneOffset int      `json:"timezone_offset"`
	Canvas         string   `json:"canvas"`
	WebGL          string   `json:"webgl"`
	Fonts          []string `json:"fonts"`
	Plugins        []string `json:"plugins"`
	Platform       string   `json:"platform"`
	CPUCores       int      `json:"cpu_cores"`
	DeviceMemory   float64  `json:"device_memory"`
	DoNotTrack     string   `json:"do_not_track"`
}

// Tracker manages fingerprint tracking and analysis
type Tracker struct {
	fingerprints map[string]*Fingerprint // hash -> fingerprint
	ipToHash     map[string][]string     // IP -> fingerprint hashes
	rateLimiter  *RateLimiter            // Rate limiter for fingerprint collection
	mu           sync.RWMutex
	config       Config
}

type Config struct {
	Enabled              bool
	MaxIPsPerFingerprint int           // Max IPs allowed per fingerprint (detect bot networks)
	MaxAgeForReuse       time.Duration // How long fingerprint can be reused
	SuspiciousThreshold  int           // Number of IPs to flag as suspicious
	BlockOnExceed        bool          // Block if exceeds max IPs
	RequireClientData    bool          // Require canvas/WebGL data
	CollectionRateLimit  int           // Max fingerprint collection requests per IP per minute
}

// RateLimiter tracks request rates per IP for fingerprint collection
type RateLimiter struct {
	requests map[string]*ipRequests
	mu       sync.RWMutex
}

type ipRequests struct {
	count     int
	resetTime time.Time
}

func newRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*ipRequests),
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, req := range rl.requests {
			if now.After(req.resetTime) {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow checks if the IP is allowed to make a request
// Returns true if allowed, false if rate limit exceeded
func (rl *RateLimiter) Allow(ip string, maxRequests int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	req, exists := rl.requests[ip]

	if !exists || now.After(req.resetTime) {
		rl.requests[ip] = &ipRequests{
			count:     1,
			resetTime: now.Add(window),
		}
		return true
	}

	if req.count >= maxRequests {
		return false
	}

	req.count++
	return true
}

// Statistics for monitoring
type Stats struct {
	TotalFingerprints      int
	SuspiciousFingerprints int
	BlockedFingerprints    int
	AverageIPsPerPrint     float64
	TopFingerprints        []FingerprintInfo
}

type FingerprintInfo struct {
	Hash       string
	IPCount    int
	LastSeen   time.Time
	Suspicious bool
}

func NewTracker(config Config) *Tracker {
	t := &Tracker{
		fingerprints: make(map[string]*Fingerprint),
		ipToHash:     make(map[string][]string),
		rateLimiter:  newRateLimiter(),
		config:       config,
	}

	// Set defaults
	if t.config.MaxIPsPerFingerprint == 0 {
		t.config.MaxIPsPerFingerprint = 5
	}
	if t.config.SuspiciousThreshold == 0 {
		t.config.SuspiciousThreshold = 3
	}
	if t.config.MaxAgeForReuse == 0 {
		t.config.MaxAgeForReuse = 24 * time.Hour
	}
	if t.config.CollectionRateLimit == 0 {
		t.config.CollectionRateLimit = 10 // 10 requests per minute per IP
	}

	go t.cleanupExpired()
	return t
}

// ExtractFromRequest extracts server-side fingerprint components
func (t *Tracker) ExtractFromRequest(r *http.Request) *Fingerprint {
	fp := &Fingerprint{
		UserAgent:  r.Header.Get("User-Agent"),
		AcceptLang: r.Header.Get("Accept-Language"),
		AcceptEnc:  r.Header.Get("Accept-Encoding"),
		DoNotTrack: r.Header.Get("DNT"),
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
		SeenCount:  1,
	}

	return fp
}

// MergeClientData merges client-side collected data into fingerprint
func (t *Tracker) MergeClientData(fp *Fingerprint, data *FingerprintData) {
	fp.ScreenRes = fmt.Sprintf("%dx%d@%d", data.ScreenWidth, data.ScreenHeight, data.ColorDepth)
	fp.Timezone = fmt.Sprintf("UTC%+d", data.TimezoneOffset/60)
	fp.Canvas = data.Canvas
	fp.WebGL = data.WebGL

	// Sort fonts for consistent hashing
	sort.Strings(data.Fonts)
	fp.Fonts = strings.Join(data.Fonts, ",")

	// Sort plugins for consistent hashing
	sort.Strings(data.Plugins)
	fp.Plugins = strings.Join(data.Plugins, ",")

	fp.Platform = data.Platform
	fp.CPUCores = fmt.Sprintf("%d", data.CPUCores)
	fp.DeviceMemory = fmt.Sprintf("%.0fGB", data.DeviceMemory)

	if data.DoNotTrack != "" {
		fp.DoNotTrack = data.DoNotTrack
	}

	// Generate hash from all components
	fp.Hash = t.generateHash(fp)
}

// generateHash creates a SHA-256 hash from all fingerprint components
func (t *Tracker) generateHash(fp *Fingerprint) string {
	components := []string{
		fp.UserAgent,
		fp.AcceptLang,
		fp.AcceptEnc,
		fp.ScreenRes,
		fp.Timezone,
		fp.Canvas,
		fp.WebGL,
		fp.Fonts,
		fp.Plugins,
		fp.DoNotTrack,
		fp.Platform,
		fp.CPUCores,
		fp.DeviceMemory,
	}

	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// Track registers a fingerprint for an IP
func (t *Tracker) Track(ip string, fp *Fingerprint) error {
	if !t.config.Enabled {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if fingerprint exists
	existing, exists := t.fingerprints[fp.Hash]
	if exists {
		// Update existing fingerprint
		existing.LastSeen = time.Now()
		existing.SeenCount++

		// Add IP if not already tracked
		if !contains(existing.IPs, ip) {
			existing.IPs = append(existing.IPs, ip)
		}

		// Check if exceeds max IPs
		if len(existing.IPs) > t.config.MaxIPsPerFingerprint {
			if t.config.BlockOnExceed {
				return fmt.Errorf("fingerprint %s exceeds max IPs (%d)", fp.Hash[:8], len(existing.IPs))
			}
		}
	} else {
		// New fingerprint
		fp.IPs = []string{ip}
		t.fingerprints[fp.Hash] = fp
	}

	// Track IP to fingerprint mapping
	t.ipToHash[ip] = append(t.ipToHash[ip], fp.Hash)

	return nil
}

// Check validates a fingerprint and returns if it should be blocked
func (t *Tracker) Check(ip string, fp *Fingerprint) (allowed bool, reason string) {
	if !t.config.Enabled {
		return true, ""
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	existing, exists := t.fingerprints[fp.Hash]
	if !exists {
		// New fingerprint - require client data if configured
		if t.config.RequireClientData {
			if fp.Canvas == "" || fp.WebGL == "" {
				return false, "missing required client fingerprint data"
			}
		}
		return true, ""
	}

	// Check if fingerprint is too old for reuse
	if time.Since(existing.CreatedAt) > t.config.MaxAgeForReuse {
		return false, "fingerprint expired (possible replay attack)"
	}

	// Check if fingerprint is used by too many IPs
	if len(existing.IPs) >= t.config.MaxIPsPerFingerprint {
		if !contains(existing.IPs, ip) {
			if t.config.BlockOnExceed {
				return false, fmt.Sprintf("fingerprint shared by %d IPs (bot network detected)", len(existing.IPs))
			}
		}
	}

	return true, ""
}

// GetFingerprint retrieves a fingerprint by hash
func (t *Tracker) GetFingerprint(hash string) (*Fingerprint, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fp, exists := t.fingerprints[hash]
	return fp, exists
}

// GetIPFingerprints returns all fingerprints used by an IP
func (t *Tracker) GetIPFingerprints(ip string) []*Fingerprint {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hashes, exists := t.ipToHash[ip]
	if !exists {
		return nil
	}

	result := make([]*Fingerprint, 0, len(hashes))
	for _, hash := range hashes {
		if fp, ok := t.fingerprints[hash]; ok {
			result = append(result, fp)
		}
	}

	return result
}

// IsSuspicious checks if a fingerprint is suspicious (used by many IPs)
func (t *Tracker) IsSuspicious(hash string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fp, exists := t.fingerprints[hash]
	if !exists {
		return false
	}

	return len(fp.IPs) >= t.config.SuspiciousThreshold
}

// GetStats returns fingerprint tracking statistics
func (t *Tracker) GetStats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := Stats{
		TotalFingerprints: len(t.fingerprints),
		TopFingerprints:   make([]FingerprintInfo, 0),
	}

	totalIPs := 0
	suspicious := 0
	blocked := 0

	// Collect info for all fingerprints
	allFingerprints := make([]FingerprintInfo, 0, len(t.fingerprints))
	for hash, fp := range t.fingerprints {
		ipCount := len(fp.IPs)
		totalIPs += ipCount

		isSuspicious := ipCount >= t.config.SuspiciousThreshold
		if isSuspicious {
			suspicious++
		}
		if ipCount >= t.config.MaxIPsPerFingerprint {
			blocked++
		}

		allFingerprints = append(allFingerprints, FingerprintInfo{
			Hash:       hash,
			IPCount:    ipCount,
			LastSeen:   fp.LastSeen,
			Suspicious: isSuspicious,
		})
	}

	stats.SuspiciousFingerprints = suspicious
	stats.BlockedFingerprints = blocked

	if len(t.fingerprints) > 0 {
		stats.AverageIPsPerPrint = float64(totalIPs) / float64(len(t.fingerprints))
	}

	// Sort by IP count (descending) and take top 10
	sort.Slice(allFingerprints, func(i, j int) bool {
		return allFingerprints[i].IPCount > allFingerprints[j].IPCount
	})

	topN := 10
	if len(allFingerprints) < topN {
		topN = len(allFingerprints)
	}
	stats.TopFingerprints = allFingerprints[:topN]

	return stats
}

// cleanupExpired removes old fingerprints
func (t *Tracker) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.Lock()

		now := time.Now()
		maxAge := t.config.MaxAgeForReuse * 2 // Keep for 2x the reuse period

		for hash, fp := range t.fingerprints {
			if now.Sub(fp.LastSeen) > maxAge {
				// Remove from fingerprints map
				delete(t.fingerprints, hash)

				// Remove from IP mappings
				for _, ip := range fp.IPs {
					if hashes, ok := t.ipToHash[ip]; ok {
						t.ipToHash[ip] = removeString(hashes, hash)
						if len(t.ipToHash[ip]) == 0 {
							delete(t.ipToHash, ip)
						}
					}
				}
			}
		}

		t.mu.Unlock()
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeString(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
