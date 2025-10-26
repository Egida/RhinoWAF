package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/auth"
	"rhinowaf/waf/challenge"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/fingerprint"
	"rhinowaf/waf/geo"
	"rhinowaf/waf/logging"
	"rhinowaf/waf/reload"
	"rhinowaf/waf/reputation"
	"rhinowaf/waf/webhook"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Initialize log rotation (v2.3.1)
	logWriter := logging.SetupRotation(logging.Config{
		Enabled:    true,
		Filename:   "./logs/rhinowaf.log",
		MaxSize:    100, // 100MB
		MaxBackups: 3,
		MaxAge:     28, // days
		Compress:   true,
	})

	// Initialize DDoS logger with log rotation
	ddos.InitLogger(&ddos.LoggerConfig{
		LogPath:              "./logs/ddos.log",
		Enabled:              true,
		LogToConsole:         true,
		MaxSizeMB:            100,
		MaxAgeDays:           30,
		CompressOld:          true,
		FlushInterval:        1 * time.Second,
		BatchSize:            100,
		HumanReadableEnabled: true,
		HumanReadablePath:    "./logs/ddos-readable.log",
	})
	
	// Also log general messages to rotated file
	log.SetOutput(logWriter)

	// Initialize webhook notifications (v2.3.1)
	webhook.Init(webhook.Config{
		Enabled:       false,                  // Enable when URLs configured
		URLs:          []string{},             // Add Slack/Discord/Teams URLs here
		MinSeverity:   "high",                 // Only high/critical/emergency alerts
		Timeout:       5,                      // 5 seconds
		MaxRetries:    2,
		SlackFormat:   false,                  // Enable for Slack URLs
		DiscordFormat: false,                  // Enable for Discord URLs
		TeamsFormat:   false,                  // Enable for Microsoft Teams URLs
	})

	// Initialize IP reputation checking (v2.3.1)
	reputation.Init(reputation.Config{
		Enabled:           false,              // Enable when API keys configured
		Provider:          "both",             // Use both AbuseIPDB and IPQualityScore
		AbuseIPDBKey:      os.Getenv("ABUSEIPDB_API_KEY"),
		IPQualityScoreKey: os.Getenv("IPQS_API_KEY"),
		CacheDuration:     60,                 // Cache for 60 minutes
		ScoreThreshold:    75,                 // Block if score >= 75
		AutoBlock:         false,              // Enable for automatic blocking
		AutoChallenge:     true,               // Challenge suspicious IPs
		Timeout:           5,                  // 5 seconds
	})

	// Initialize per-user rate limiting (v2.3.1)
	auth.Init(auth.Config{
		Enabled:            false,             // Enable when JWT configured
		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTHeader:          "Authorization",
		SessionCookie:      "session_id",
		RateLimitPerUser:   1000,              // 1000 requests per user
		RateLimitWindow:    60,                // Per 60 seconds
		WhitelistUsernames: []string{},        // Add admin usernames here
		TrackAnonymous:     false,
	})

	// Initialize IP manager with advanced rules
	if err := ddos.InitIPManager("./config/ip_rules.json", true); err != nil {
		log.Printf("Warning: Could not initialize IP manager - %v (WAF will run with limited protection)", err)
	}

	// Load GeoIP database
	if err := geo.LoadGeoDatabase("./config/geoip.json"); err != nil {
		log.Printf("Warning: Could not load GeoIP database - %v (geolocation blocking will be unavailable)", err)
	}

	// Initialize hot-reload manager
	reloadMgr, err := reload.NewManager(reload.Config{
		IPRulesPath:  "./config/ip_rules.json",
		GeoDBPath:    "./config/geoip.json",
		DebounceTime: 2 * time.Second,
		WatchEnabled: true,
	})
	if err != nil {
		log.Printf("Warning: Could not initialize hot-reload system - %v (configuration changes will require restart)", err)
	}
	defer func() {
		if reloadMgr != nil {
			reloadMgr.Stop()
		}
	}()

	// Setup SIGHUP handler for manual reload
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			log.Println("Received SIGHUP signal, reloading all configurations...")
			if reloadMgr != nil {
				if err := reloadMgr.ReloadAll(); err != nil {
					log.Printf("Configuration reload failed: %v", err)
				} else {
					log.Println("All configurations reloaded successfully")
				}
			}
		}
	}()

	// Initialize challenge manager
	challengeMgr := challenge.NewManager()

	// Configure CAPTCHA providers from environment variables
	if hcaptchaKey := os.Getenv("HCAPTCHA_SITE_KEY"); hcaptchaKey != "" {
		secret := os.Getenv("HCAPTCHA_SECRET")
		if secret == "" {
			log.Printf("Warning: hCaptcha site key provided but secret is missing - hCaptcha challenges will not work")
		} else {
			challengeMgr.SetHCaptcha(hcaptchaKey, secret)
			log.Printf("hCaptcha configured successfully")
		}
	}
	if turnstileKey := os.Getenv("TURNSTILE_SITE_KEY"); turnstileKey != "" {
		secret := os.Getenv("TURNSTILE_SECRET")
		if secret == "" {
			log.Printf("Warning: Cloudflare Turnstile site key provided but secret is missing - Turnstile challenges will not work")
		} else {
			challengeMgr.SetTurnstile(turnstileKey, secret)
			log.Printf("Cloudflare Turnstile configured successfully")
		}
	}

	// Initialize fingerprint tracker (CONFIGURABLE)
	// For production with strict bot blocking: Set BlockOnExceed=true, RequireClientData=true
	fingerprintConfig := fingerprint.Config{
		Enabled:              true, // Browser fingerprinting enabled
		MaxIPsPerFingerprint: 5,    // Max IPs allowed per fingerprint (detect bot networks)
		MaxAgeForReuse:       24 * time.Hour,
		SuspiciousThreshold:  3,     // Flag as suspicious when 3+ IPs share fingerprint
		BlockOnExceed:        false, // Set true for production: Block IPs exceeding limits
		RequireClientData:    false, // Set true for production: Require full browser fingerprinting
	}
	fingerprintTracker := fingerprint.NewTracker(fingerprintConfig)
	fingerprintMW := fingerprint.NewMiddleware(fingerprintTracker)

	// Configure challenge middleware
	challengeConfig := challenge.Config{
		Enabled:         true, // Challenge system enabled for high-risk traffic
		DefaultType:     challenge.TypeJavaScript,
		Difficulty:      5, // Moderate difficulty for proof-of-work challenges
		WhitelistPaths:  []string{"/challenge/"},
		RequireForPaths: []string{},
	}
	challengeMW := challenge.NewMiddleware(challengeMgr, challengeConfig)

	// Challenge verification endpoint
	http.HandleFunc("/challenge/verify", challengeMW.VerifyHandler)

	// Fingerprint endpoints
	http.HandleFunc("/fingerprint/collect", fingerprintMW.CollectHandler)
	http.HandleFunc("/fingerprint/stats", fingerprintMW.StatsHandler)

	// Wrap handlers with both WAF and challenge protection
	mux := http.NewServeMux()

	// Prometheus metrics endpoint (no WAF protection for monitoring)
	mux.Handle("/metrics", promhttp.Handler())

	// Reload endpoint - triggers manual configuration reload (no WAF protection)
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests are accepted for configuration reload", http.StatusMethodNotAllowed)
			return
		}

		if reloadMgr == nil {
			http.Error(w, "Hot-reload system is not available", http.StatusInternalServerError)
			return
		}

		log.Println("Configuration reload requested via /reload endpoint")
		if err := reloadMgr.ReloadAll(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}

		status := reloadMgr.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"config": status,
		})
	})

	// Proxy all requests to backend (except fingerprint/challenge endpoints)
	mux.HandleFunc("/", waf.AdaptiveProtect(handlers.Home))
	mux.HandleFunc("/api/", waf.AdaptiveProtect(handlers.APIHandler))
	mux.HandleFunc("/about", waf.AdaptiveProtect(handlers.AboutHandler))
	mux.HandleFunc("/contact", waf.AdaptiveProtect(handlers.ContactHandler))

	// Legacy endpoints
	mux.HandleFunc("/login", waf.AdaptiveProtect(handlers.Login))
	mux.HandleFunc("/echo", waf.AdaptiveProtect(handlers.Echo))
	mux.HandleFunc("/flood", waf.AdaptiveProtect(handlers.Flood))

	// Apply middleware layers: fingerprint -> challenge -> routes
	handler := fingerprintMW.Handler(challengeMW.Handler(mux))

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   RhinoWAF v2.3.1                          ║")
	fmt.Println("║              Production Web Application Firewall            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("")
	fmt.Println("  Active Security Features:")
	fmt.Println("   - DDoS Protection with Adaptive Rate Limiting")
	fmt.Println("   - Advanced IP Rules (60+ configurable fields)")
	fmt.Println("   - Challenge System (JavaScript and Proof-of-Work)")
	fmt.Println("   - Browser Fingerprinting for Bot Detection")
	fmt.Println("   - Geolocation-based Access Control")
	fmt.Println("   - Proxy, Tor, and VPN Detection")
	fmt.Println("   - Input Sanitization and XSS Protection")
	fmt.Println("   - Live Configuration Reloading")
	fmt.Println("")
	fmt.Println("  Quality of Life Features (v2.3.1):")
	fmt.Println("   - Custom Error Pages with Branding")
	fmt.Println("   - Webhook Notifications (Slack/Discord/Teams)")
	fmt.Println("   - IP Reputation Checking (AbuseIPDB/IPQualityScore)")
	fmt.Println("   - Connection Pooling for Backend Proxy")
	fmt.Println("   - Automatic Log Rotation and Compression")
	fmt.Println("   - JWT/Session-based Rate Limiting")
	fmt.Println("")
	fmt.Println("  Service Information:")
	fmt.Println("   WAF is listening on http://localhost:8080")
	fmt.Println("   Prometheus metrics available at /metrics")
	fmt.Println("   Configuration reload endpoint at /reload (POST)")
	fmt.Println("   Automatic file watching is active")
	fmt.Println("   Manual reload available with: kill -SIGHUP <pid>")
	fmt.Println("   Attack logs being written to ./logs/ddos.log")
	fmt.Println("   General logs being written to ./logs/rhinowaf.log")
	fmt.Println("   Backend proxy target: http://localhost:9000")
	fmt.Println("")
	fmt.Println("RhinoWAF is ready and protecting your application.")
	fmt.Println("")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
