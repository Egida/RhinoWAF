package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"rhinowaf/handlers"
	"rhinowaf/waf"
	"rhinowaf/waf/challenge"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/fingerprint"
	"rhinowaf/waf/geo"
	"time"
)

func main() {
	ddos.InitLogger(nil)

	// Initialize IP manager with advanced rules
	if err := ddos.InitIPManager("./config/ip_rules.json", true); err != nil {
		log.Printf("Warning: Failed to init IP manager: %v", err)
	}

	// Load GeoIP database
	if err := geo.LoadGeoDatabase("./config/geoip.json"); err != nil {
		log.Printf("Warning: Failed to load GeoIP database: %v", err)
	}

	// Initialize challenge manager
	challengeMgr := challenge.NewManager()

	// Configure CAPTCHA providers from environment variables
	if hcaptchaKey := os.Getenv("HCAPTCHA_SITE_KEY"); hcaptchaKey != "" {
		secret := os.Getenv("HCAPTCHA_SECRET")
		if secret == "" {
			log.Printf("Warning: HCAPTCHA_SITE_KEY set but HCAPTCHA_SECRET is empty")
		} else {
			challengeMgr.SetHCaptcha(hcaptchaKey, secret)
			log.Printf("✓ hCaptcha configured")
		}
	}
	if turnstileKey := os.Getenv("TURNSTILE_SITE_KEY"); turnstileKey != "" {
		secret := os.Getenv("TURNSTILE_SECRET")
		if secret == "" {
			log.Printf("Warning: TURNSTILE_SITE_KEY set but TURNSTILE_SECRET is empty")
		} else {
			challengeMgr.SetTurnstile(turnstileKey, secret)
			log.Printf("✓ Cloudflare Turnstile configured")
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
	fmt.Println("║                     RhinoWAF v2.2                          ║")
	fmt.Println("║              Production Web Application Firewall            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("")
	fmt.Println("  Security Features:")
	fmt.Println("   DDoS Protection with Rate Limiting")
	fmt.Println("   Advanced IP Rule Enforcement (60+ fields)")
	fmt.Println("   Challenge System (JavaScript PoW)")
	fmt.Println("   Browser Fingerprinting (ACTIVE)")
	fmt.Println("   Geolocation-based Blocking")
	fmt.Println("   Proxy/Tor/VPN Detection")
	fmt.Println("   Input Sanitization & XSS Protection")
	fmt.Println("")
	fmt.Println(" Status:")
	fmt.Println("  • WAF Listening: http://localhost:8080")
	fmt.Println("  • Attack Logs: ./logs/ddos.log")
	fmt.Println("  • Backend Proxy: http://localhost:9000")
	fmt.Println("")
	fmt.Println("Ready.")
	fmt.Println("")

	log.Fatal(http.ListenAndServe(":8080", handler))
}
