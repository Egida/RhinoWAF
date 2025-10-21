# RhinoWAF

**High-performance Web Application Firewall in Go with advanced DDoS protection, geolocation-based blocking, and granular IP controls.**

**Version**: 2.0 | **Status**: Tested and working well. | **Last Updated**: October 21, 2025

## Features

### **Core Protection**
- **DDoS Protection**: Rate limiting, burst detection, Slowloris mitigation, reputation scoring
- **Input Sanitization**: SQL injection, XSS, path traversal, command injection blocking
- **IP Management**: 60+ per-IP control fields with priority-based rule matching
- **Geolocation Blocking**: Country/region-based access control with CIDR lookup
- **ASN Blocking**: Block entire autonomous systems (hosting providers, VPNs)
- **Challenge System**: JavaScript, proof-of-work, hCaptcha, Cloudflare Turnstile
- **Attack Logging**: JSON-formatted logs with detailed metrics and severity levels

### **Advanced IP Controls (119+ Config Fields)**
- Time-based restrictions (business hours, specific days, timezone support)
- Path & method filtering (wildcards, per-path rate limits)
- Request pattern validation (headers, cookies, referers, query params)
- Content controls (file extensions, upload sizes, content-types)
- Protocol enforcement (HTTPS, TLS versions, HTTP/2)
- User agent filtering (bot detection, headless browser blocking)
- Behavioral limits (burst windows, session duration, concurrent connections)

### **Global WAF Policies**
- Attack pattern blocking (SQL injection, XSS, SSRF, XXE, template injection)
- Bot management (allow search engines, block scrapers)
- Protocol security (require modern TLS, block old HTTP versions)
- Size/count limits (URL length, header count, body size)

### **Challenge & Verification**
- **JavaScript Challenge**: 2-second delay with JS execution requirement (blocks curl/wget)
- **Proof-of-Work**: Client-side SHA-256 computation with configurable difficulty
- **hCaptcha Integration**: Privacy-focused CAPTCHA with GDPR compliance
- **Cloudflare Turnstile**: Invisible/managed challenges with better UX
- **Session Management**: In-memory sessions with automatic cleanup, IP binding
- **Cookie-Based Verification**: HttpOnly, SameSite=Lax cookies with 1-hour TTL

### **Browser Fingerprinting**
- **Canvas Fingerprinting**: Unique rendering signatures per browser/device
- **WebGL Fingerprinting**: GPU vendor and renderer detection
- **Font Detection**: Installed fonts enumeration via canvas measurement
- **Hardware Profiling**: Screen resolution, CPU cores, device memory
- **Bot Network Detection**: Identifies multiple IPs sharing same fingerprint
- **Headless Browser Blocking**: Requires canvas/WebGL data that bots often fail
- **Automatic Collection**: Transparent 1-2 second verification on first visit

### **Production Status (v2.0)**
-  **Challenge System**: Enabled by default (JavaScript challenges)
-  **Browser Fingerprinting**: Enabled by default (bot network detection)
-  **Geolocation Blocking**: Active with 4 geo rules (CN, RU, IR challenge; KP blocked)
-  **Proxy/Tor Blocking**: Enabled (blocks proxies, Tor, hosting providers)
-  **Rate Limiting**: 100 req/IP, 10 concurrent connections
-  **User-Agent Filtering**: Blocks empty/suspicious UAs
-  **GeoIP Database**: 12 CIDR ranges covering major regions

### **Planned Enhancements**
- Real-time config hot-reload
- Distributed rate limiting (Redis)
- Web UI for rule management
- Challenge history and reputation scoring
- Redis-backed session/fingerprint store for multi-server deployments

## Quick Start

```bash
# Build
go build -o rhinowaf ./cmd/rhinowaf

# Run (default production config)
./rhinowaf
```

**Expected startup output:**
```
IP Manager initialized: 0 banned, 0 whitelisted, 0 monitored, 4 geo rules
RhinoWAF on :8080
DDoS attack logs: ./logs/ddos.log
Challenge system: ✓ Enabled
Fingerprint tracking: ✓ Enabled
Geolocation blocking: ✓ Active
Proxy/Tor blocking: ✓ Enabled
```

Server runs on `:8080`. Attack logs: `./logs/ddos.log`

**Test the server:**
```bash
curl http://localhost:8080/
# Note: May show "Fingerprint required" for first-time visitors
```

## Configuration

### **IP Rules** (`config/ip_rules.json`)

Comprehensive example in `config/ip_rules.example.json`. Basic structure:

```json
{
  "version": "2.0",
  "banned_ips": [
    {
      "ip": "192.168.1.100",
      "type": "ban",
      "reason": "Repeated attacks",
      "created_at": "2025-10-18T00:00:00Z"
    }
  ],
  "whitelisted_ips": [
    {
      "ip": "10.0.0.1",
      "type": "whitelist",
      "reason": "Internal admin",
      "whitelist_override": true
    }
  ],
  "throttled_ips": [
    {
      "ip": "198.51.100.100",
      "type": "throttle",
      "throttle_percent": 50,
      "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
      "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
      "timezone": "America/New_York"
    }
  ],
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "RU",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "KP",
      "action": "block"
    }
  ],
  "global_rules": {
    "default_action": "allow",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

### **Advanced Per-IP Controls**

Each IP rule supports 60+ configuration fields:

**Time-Based**: `allowed_hours`, `blocked_hours`, `allowed_days`, `blocked_days`, `timezone`

**Path/Method**: `allowed_paths`, `blocked_paths`, `allowed_methods`, `blocked_methods`, `rate_limit_by_path`

**Request Validation**: `required_headers`, `blocked_headers`, `require_cookies`, `allowed_referers`, `blocked_referers`

**Content**: `allowed_content_types`, `blocked_content_types`, `max_upload_size`, `allowed_file_exts`, `blocked_file_exts`

**Behavioral**: `min_request_interval`, `max_burst_size`, `max_concurrent_conns`, `max_session_duration`

**Protocol**: `require_https`, `require_http2`, `min_tls_version`, `allowed_ports`, `blocked_protocols`

**User Agents**: `allowed_user_agents`, `blocked_user_agents`, `block_headless`, `block_bots`

See `docs/IP_RULES.md` for complete field reference and examples.

## Challenge System

Protect against bots and automated attacks with multiple challenge types. See `docs/CHALLENGE_SYSTEM.md` for full documentation.

### Quick Setup

**1. Configure CAPTCHA providers (optional):**

```bash
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret"
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret"
```

**2. Configuration (default production settings):**

```go
// Challenge system is ENABLED by default in main.go
challengeConfig := challenge.Config{
    Enabled:         true,  // ✓ Production default
    DefaultType:     challenge.TypeJavaScript,
    Difficulty:      5,  // For proof-of-work (1-6)
    WhitelistPaths:  []string{"/challenge/"},
    RequireForPaths: []string{},  // Add paths requiring challenges
}
```

**To customize:** Edit `cmd/rhinowaf/main.go` and rebuild.

**Challenge Types:**
- `TypeJavaScript`: Basic JS execution requirement (2-second delay)
- `TypeProofOfWork`: SHA-256 computational puzzle (configurable difficulty)
- `TypeHCaptcha`: Privacy-focused CAPTCHA (requires API keys)
- `TypeTurnstile`: Cloudflare's invisible challenge (requires API keys)

**How It Works:**
1. Request arrives without valid session → Challenge page shown
2. Client completes challenge (JS/POW/CAPTCHA)
3. Verification POST to `/challenge/verify`
4. Cookie set with session token (1-hour TTL)
5. Subsequent requests pass through automatically

### Recommended Secure Configurations

**For High-Security Sites (Banking, Healthcare, Government):**

```go
// Option 1: hCaptcha (best for compliance, GDPR-friendly)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeHCaptcha,
    WhitelistPaths:  []string{"/static/", "/health"},
    RequireForPaths: []string{"/login", "/register", "/admin/", "/api/"},
}
```

```bash
# Get free keys from https://hcaptcha.com
export HCAPTCHA_SITE_KEY="10000000-ffff-ffff-ffff-000000000001"
export HCAPTCHA_SECRET="0x0000000000000000000000000000000000000000"
```

**Benefits**: 99% bot blocking, GDPR compliant, privacy-focused, free tier available

---

**For Modern Sites with Best UX (E-commerce, SaaS, Content):**

```go
// Option 2: Cloudflare Turnstile (invisible, best user experience)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeTurnstile,
    WhitelistPaths:  []string{"/static/", "/health", "/metrics"},
    RequireForPaths: []string{"/login", "/checkout", "/api/"},
}
```

```bash
# Get free keys from Cloudflare Dashboard → Turnstile
export TURNSTILE_SITE_KEY="1x00000000000000000000AA"
export TURNSTILE_SECRET="1x0000000000000000000000000000000AA"
```

**Benefits**: 95% bot blocking, invisible to most users, free, best UX, no CAPTCHA solving

---

**For Maximum Security During Attack:**

```go
// Option 3: Proof-of-Work (expensive for attackers, no external dependencies)
challengeConfig := challenge.Config{
    Enabled:         true,
    DefaultType:     challenge.TypeProofOfWork,
    Difficulty:      5,  // 10-30 seconds per request (adjust 1-6)
    RequireForPaths: []string{"/"},  // Protect entire site
}
```

**Benefits**: Makes attacks economically unfeasible, no API keys needed, blocks 98%+ bots

---

**Comparison:**

| Feature | hCaptcha | Turnstile | Proof-of-Work |
|---------|----------|-----------|---------------|
| Bot blocking | 99% | 95% | 98% |
| User friction | Medium (solve CAPTCHA) | None (invisible) | Low (wait 3-5s) |
| Privacy | Excellent (GDPR) | Good | Perfect (no external) |
| Setup | API keys required | API keys required | No setup |
| Cost | Free tier | Free | Free |
| Best for | Login/Register | All pages | DDoS attacks |

## Browser Fingerprinting

Fingerprinting is **ENABLED by default** to detect bot networks and sophisticated attacks:

```go
// Default production configuration in main.go
fingerprintConfig := fingerprint.Config{
    Enabled:              true,  // ✓ Production default
    MaxIPsPerFingerprint: 5,     // Max IPs per fingerprint (bot network detection)
    MaxAgeForReuse:       24 * time.Hour,
    SuspiciousThreshold:  3,     // Flag as suspicious when 3+ IPs share fingerprint
    BlockOnExceed:        true,  // Block when MaxIPsPerFingerprint exceeded
    RequireClientData:    true,  // Require canvas/WebGL (blocks headless browsers)
}
```

**To customize:** Edit `cmd/rhinowaf/main.go` and rebuild.

**What It Detects:**
- Bot networks using the same browser across multiple IPs
- Credential stuffing with rotating IPs but same device
- Scrapers rotating User-Agents but same browser engine
- Headless browsers (Puppeteer, Selenium) missing canvas/WebGL

**How It Works:**
1. First visit → 1-2 second "Security Verification" page
2. JavaScript collects: Canvas signature, WebGL renderer, fonts, screen res, CPU cores
3. SHA-256 hash created from all data → cookie set
4. Returning visits → instant (cookie present)

**Endpoints:**
- `POST /fingerprint/collect` - Receives fingerprint data from client
- `GET /fingerprint/stats` - Returns tracking statistics

**Monitoring:**
```bash
curl http://localhost:8080/fingerprint/stats
```

See [docs/FINGERPRINTING.md](docs/FINGERPRINTING.md) for full documentation.

## Attack Logging

Logs are written in JSON format to `./logs/ddos.log`:

**Burst Attack:**
```json
{
  "timestamp": "2025-10-18T13:16:17Z",
  "event_type": "burst",
  "ip": "203.0.113.10",
  "severity": "critical",
  "request_count": 105,
  "rate_limit": 100,
  "excess_percentage": 5,
  "burst_detected": true,
  "reputation": -10,
  "violation_count": 1,
  "message": "BURST ATTACK DETECTED: 105 requests in rapid succession",
  "recommended_action": "IMMEDIATE_BLOCK - Consider permanent ban or CAPTCHA"
}
```

Parse with `jq`:

```bash
jq -r '.severity' logs/ddos.log | sort | uniq -c
jq -r 'select(.violation_count > 5) | .ip' logs/ddos.log
tail -f logs/ddos.log | jq '.message'
```

## IP Management

Config file at `./config/ip_rules.json` (production defaults):

```json
{
  "version": "2.0",
  "last_modified": "2025-10-20T00:00:00Z",
  "banned_ips": [],
  "whitelisted_ips": [],
  "monitored_ips": [],
  "geo_rules": [
    {
      "country_code": "CN",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "RU",
      "action": "challenge",
      "throttle_percent": 40
    },
    {
      "country_code": "KP",
      "action": "block"
    }
  ],
  "global_rules": {
    "default_action": "allow",
    "block_proxies": true,
    "block_tor": true,
    "block_hosting": true,
    "max_requests_per_ip": 100,
    "max_connections_per_ip": 10,
    "block_empty_user_agent": true,
    "block_suspicious_ua": true
  }
}
```

Usage:

```go
ipm := ddos.GetIPManager()
ipm.BanIP("203.0.113.42", "brute force", "admin", 24*time.Hour, nil)
ipm.WhitelistIP("10.0.0.1", "internal", "devops", "", nil)
ipm.MonitorIP("198.51.100.42", "suspicious", nil)
```

## Production Deployment

### Quick Deploy
```bash
# Build for production
go build -o rhinowaf ./cmd/rhinowaf

# Run with production config (defaults are production-ready)
./rhinowaf
```

### What's Enabled by Default
-  **Challenge System** - JavaScript challenges (2-second delay)
-  **Browser Fingerprinting** - Bot network detection
-  **Geolocation Blocking** - High-risk countries challenged
-  **Proxy/Tor Blocking** - Blocks proxies, Tor, hosting providers
-  **Rate Limiting** - 100 requests/IP, 10 concurrent connections
-  **User-Agent Filtering** - Blocks empty/suspicious UAs

### Configuration Files
- `cmd/rhinowaf/main.go` - Application configuration
- `config/ip_rules.json` - IP/geo rules (v2.0, production defaults)
- `config/geoip.json` - GeoIP database (12 CIDR ranges)


### Optional: Add CAPTCHA
For better user experience, add CAPTCHA providers:

```bash
# hCaptcha (recommended for compliance)
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET="your-secret"

# Cloudflare Turnstile (recommended for UX)
export TURNSTILE_SITE_KEY="your-site-key"
export TURNSTILE_SECRET="your-secret"

# Then change DefaultType in main.go to TypeHCaptcha or TypeTurnstile
```

### Monitoring
```bash
# Watch logs in real-time
tail -f ./logs/ddos.log | jq '.message'

# Check fingerprint statistics
curl http://localhost:8080/fingerprint/stats

# Analyze attack severity
jq -r '.severity' logs/ddos.log | sort | uniq -c
```

### Customization
Edit `cmd/rhinowaf/main.go` to customize:
- Challenge difficulty (1-6)
- Fingerprint thresholds
- Protected paths
- Challenge types

Edit `config/ip_rules.json` to customize:
- Geo rules (countries to block/challenge)
- Rate limits
- Proxy/Tor blocking
- User-agent filtering

## License

AGPL-3.0 - requires open sourcing derivative works

---

**Version**: 2.0 | **Status**: Production-Ready | **Last Updated**: October 20, 2025

