# RhinoWAF

**High-performance Web Application Firewall in Go with advanced DDoS protection, geolocation-based blocking, and granular IP controls.**

**Version**: 2.4.0 | **Status**: Production-ready with HTTP request smuggling detection | **Last Updated**: October 28, 2025

## Note
It may seem im doing this very fast, keep in mind im working as a team with 5-6 friends so we work very fast together to deliver the best performance we can

## Features

### **Core Protection**

- **DDoS Protection**: Rate limiting, burst detection, Slowloris mitigation, reputation scoring
- **Input Sanitization**: SQL injection, XSS, path traversal, command injection blocking
- **HTTP Request Smuggling Detection**: CL.TE, TE.CL, TE.TE, header obfuscation, protocol violations
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

### **Production Status (v2.4)**

- **Challenge System**: Enabled by default (JavaScript challenges)
- **Browser Fingerprinting**: Enabled by default (bot network detection)
- **HTTP Request Smuggling Detection**: Active with strict mode, blocks severity 4+ violations
- **Geolocation Blocking**: Active with 4 geo rules (CN, RU, IR challenge; KP blocked)
- **Proxy/Tor Blocking**: Enabled (blocks proxies, Tor, hosting providers)
- **Rate Limiting**: 100 req/IP, 10 concurrent connections
- **User-Agent Filtering**: Blocks empty/suspicious UAs
- **GeoIP Database**: 12 CIDR ranges covering major regions
- **Prometheus Metrics**: Real-time observability at `/metrics` endpoint
- **Hot-Reload**: Live configuration updates without restart

### **Planned Enhancements (v2.5+)**
- Advanced rate limiting algorithms (token bucket, sliding window)
- GraphQL query depth limiting
- WebSocket security and payload inspection
- Response header security (CSP, HSTS auto-injection)
- **v3.0+**: Distributed rate limiting (Redis), Web UI dashboard, Multi-server synchronization

## Quick Start

```bash
# Build
go build -o rhinowaf ./cmd/rhinowaf

# Run (default production config)
./rhinowaf
```

**Expected startup output:**

```text
╔════════════════════════════════════════════════════════════╗
║                     RhinoWAF v2.4                          ║
║              Production Web Application Firewall            ║
╚════════════════════════════════════════════════════════════╝

  Security Features:
   HTTP Request Smuggling Detection (ACTIVE)
   DDoS Protection with Rate Limiting
   Advanced IP Rule Enforcement (60+ fields)
   Challenge System (JavaScript PoW)
   Browser Fingerprinting (ACTIVE)
   Geolocation-based Blocking
   Proxy/Tor/VPN Detection
   Input Sanitization & XSS Protection
   Hot-Reload Configuration (Auto & Manual)

 Status:
  • WAF Listening: http://localhost:8080
  • Metrics Endpoint: http://localhost:8080/metrics
  • Reload Endpoint: POST http://localhost:8080/reload
  • Auto-Reload: Watching config files
  • Manual Reload: kill -SIGHUP <pid>
  • Attack Logs: ./logs/ddos.log
  • Backend Proxy: http://localhost:9000

Ready.
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

## HTTP Request Smuggling Protection (v2.4 NEW)

Detects and blocks HTTP request smuggling attacks with severity-based blocking. See `docs/SMUGGLING_DETECTION.md` for full technical documentation.

### What It Detects

**17 Violation Types:**
- **CL.TE / TE.CL Conflicts** - Mismatched Content-Length and Transfer-Encoding headers (severity 5)
- **Multiple Headers** - Duplicate Content-Length or Transfer-Encoding headers (severity 5)
- **Header Obfuscation** - Whitespace, hex encoding, control characters in headers (severity 4)
- **Invalid Values** - Negative, malformed, or conflicting header values (severity 4)
- **Protocol Violations** - HTTP/0.9 with headers, invalid protocols (severity 3-5)

### Configuration Modes

**Strict Mode (Default Production):**
```go
// Enabled in waf/adaptive.go
smugglingDetector := smuggling.NewDetector(
    true,  // strict_mode: comprehensive validation
    true,  // log_violations: all detections logged
    4,     // block_threshold: blocks severity 4+
)
```

**Moderate Mode (Balanced):**
```go
smugglingDetector := smuggling.NewDetector(false, true, 5)
// Blocks only critical attacks (severity 5)
```

**Permissive Mode (Development):**
```go
smugglingDetector := smuggling.NewDetector(false, true, 6)
// Logs all violations but never blocks
```

### How It Works

1. **First Line of Defense** - Runs before all other WAF checks
2. **Request Inspection** - Analyzes Content-Length, Transfer-Encoding, HTTP protocol
3. **Violation Scoring** - Each violation has severity 1-5
4. **Threshold Blocking** - Requests meeting/exceeding threshold are blocked
5. **Metrics Recorded** - All violations tracked in Prometheus

### Prometheus Metrics

```bash
# Total smuggling attempts blocked (by violation type)
rhinowaf_smuggling_attempts_blocked_total{violation_type="CL_TE_CONFLICT"}

# All violations detected (including non-blocking)
rhinowaf_smuggling_violations_detected_total{violation_type="OBFUSCATED_CL",severity="4"}
```

### Example Attack Blocked

```bash
# CL.TE attack attempt
curl -X POST http://localhost:8080/ \
  -H "Content-Length: 44" \
  -H "Transfer-Encoding: chunked" \
  -d "GET /admin HTTP/1.1..."

# Response: 403 Forbidden
# Metrics: rhinowaf_smuggling_attempts_blocked_total{violation_type="CL_TE_CONFLICT"} = 1
```

See [docs/SMUGGLING_DETECTION.md](docs/SMUGGLING_DETECTION.md) for detailed technical documentation, attack examples, and testing procedures.

## Prometheus Metrics (v2.4)

RhinoWAF exposes comprehensive metrics for monitoring and alerting:

```bash
# View all metrics
curl http://localhost:8080/metrics
```

### Available Metrics

**Request Metrics:**
- `rhinowaf_requests_total{status}` - Total requests (counter with allowed/blocked labels)
- `rhinowaf_requests_blocked{reason}` - Blocked requests by reason (rate_limit, ip_rule, malicious_input, etc.)
- `rhinowaf_requests_allowed` - Allowed requests (counter)
- `rhinowaf_request_duration_seconds` - Request processing time (histogram)

**Challenge Metrics:**
- `rhinowaf_challenges_issued` - Total challenges issued (counter)
- `rhinowaf_challenges_passed` - Successfully completed challenges (counter)
- `rhinowaf_challenges_failed` - Failed challenge attempts (counter)
- `rhinowaf_challenge_sessions` - Active challenge sessions (gauge)

**Fingerprint Metrics:**
- `rhinowaf_fingerprints_collected` - Total fingerprints collected (counter)
- `rhinowaf_fingerprints_blocked{reason}` - Blocked fingerprints by reason (counter)
- `rhinowaf_fingerprint_rate_limited` - Rate limited fingerprint requests (counter)
- `rhinowaf_active_fingerprints` - Currently tracked fingerprints (gauge)
- `rhinowaf_suspicious_fingerprints` - Fingerprints flagged as suspicious (gauge)

**Configuration Metrics:**
- `rhinowaf_config_reloads{config_type}` - Configuration reload count (ip_rules, geoip)

### Grafana Dashboard Example

```promql
# Request rate
rate(rhinowaf_requests_total[5m])

# Block rate by reason
rate(rhinowaf_requests_blocked[5m]) by (reason)

# 95th percentile latency
histogram_quantile(0.95, rate(rhinowaf_request_duration_seconds_bucket[5m]))

# Challenge pass rate
rate(rhinowaf_challenges_passed[5m]) / rate(rhinowaf_challenges_issued[5m])
```

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for full metrics documentation and Grafana dashboard examples.

## Hot-Reload Configuration (v2.4)

Update IP rules and GeoIP database without restarting RhinoWAF:

### Automatic File Watching

By default, RhinoWAF watches configuration files for changes:

```bash
# Edit config files - changes detected automatically
vim config/ip_rules.json
# Reload happens automatically after 2-second debounce
```

Logs will show:
```
✓ Detected change in config file: config/ip_rules.json
✓ Successfully reloaded IP rules
```

### Manual Reload via HTTP Endpoint

```bash
# Trigger immediate reload
curl -X POST http://localhost:8080/reload

# Response:
{
  "status": "success",
  "config": {
    "ip_rules_path": "./config/ip_rules.json",
    "geodb_path": "./config/geoip.json",
    "debounce_time": "2s",
    "last_reloads": {
      "ip_rules": "2025-10-24T20:06:32Z",
      "geoip": "2025-10-24T20:06:32Z"
    }
  }
}
```

### Manual Reload via Signal

```bash
# Get RhinoWAF process ID
ps aux | grep rhinowaf

# Send SIGHUP signal
kill -SIGHUP <pid>
```

Logs will show:
```
Received SIGHUP, reloading configurations...
✓ Successfully reloaded IP rules
✓ Successfully reloaded GeoIP database
✓ All configurations reloaded successfully
```

### Configuration Validation

Hot-reload includes JSON validation to prevent invalid configs:

```bash
# Invalid JSON in config file
curl -X POST http://localhost:8080/reload

# Response on error:
{
  "status": "error",
  "error": "Invalid JSON in config/ip_rules.json: unexpected end of JSON input"
}
```

**Safe Reload**: If validation fails, the previous configuration remains active.

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed hot-reload documentation.

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
# Check health status
curl http://localhost:8080/health

# Sample response:
{
  "status": "healthy",
  "version": "v2.4.0",
  "uptime": "2 hours 15 minutes",
  "uptime_seconds": 8100,
  "timestamp": "2025-10-26T21:40:38Z",
  "system": {
    "go_version": "go1.24.5",
    "goroutines": 18,
    "memory_mb": 12,
    "num_cpu": 2
  }
}

# Watch logs in real-time
tail -f ./logs/ddos.log | jq '.message'

# Check Prometheus metrics
curl http://localhost:8080/metrics

# Check fingerprint statistics
curl http://localhost:8080/fingerprint/stats

# Reload configuration
curl -X POST http://localhost:8080/reload

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

## Changelog & Roadmap

### Released Versions

#### **v2.4** — October 28, 2025
*HTTP Request Smuggling Protection*

- **Smuggling Detection Engine** — 17 violation types detecting CL.TE, TE.CL, TE.TE attacks
- **Severity-based Blocking** — Configurable thresholds (1-5 severity scale), blocks 4+ by default
- **Header Obfuscation Detection** — Catches whitespace, hex encoding, control characters in headers
- **Protocol Violation Checks** — Detects invalid Content-Length/Transfer-Encoding combinations
- **Prometheus Metrics** — `rhinowaf_smuggling_attempts_blocked_total` and `rhinowaf_smuggling_violations_detected_total`
- **Strict Mode** — Production-ready configuration with comprehensive request validation

See [docs/SMUGGLING_DETECTION.md](docs/SMUGGLING_DETECTION.md) for technical documentation and [docs/CHANGELOGS/V2.4_FEATURES.md](docs/CHANGELOGS/V2.4_FEATURES.md) for detailed feature information.

#### **v2.3** — October 24, 2025
*Performance & Observability Release*

-  **Prometheus Metrics Endpoint** — 20+ metrics at `/metrics` for monitoring (requests, blocks, challenges, fingerprints, latency)
-  **Hot-Reload Configuration** — Update IP rules/GeoIP without restart (auto file-watch + manual triggers)
-  **HTTP Reload API** — `POST /reload` endpoint for programmatic configuration updates
-  **SIGHUP Signal Handler** — Manual reload via `kill -SIGHUP` for DevOps workflows
-  **Configuration Validation** — JSON validation with safe rollback on reload errors
-  **Debounced File Watching** — 2-second debounce prevents reload storms during batch edits

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed feature documentation.

#### **v2.2** — October 24, 2025
*Maintenance & Security Release*

-  **Constant-time token comparison** — Prevents timing attacks on token validation
-  **Rate limiting on `/fingerprint/collect`** — Prevents fingerprint collection DoS
-  **Improved CAPTCHA error messages** — Better user experience on failed challenges
-  **Better malformed header handling** — Prevents header injection attacks

#### **v2.1** — October 22, 2025
*Security Hardening*

-  **Secure cookie handling with auto-detect HTTPS** — Defends against MITM attacks
-  **CAPTCHA secret validation warnings** — Prevents silent misconfigurations
-  **IP spoofing protection via trusted proxy validation** — Blocks X-Forwarded-For bypass
-  **New `waf/security` package** — X-Forwarded-For validation against trusted proxy list

---

### Recent Releases

#### **v2.3.2** — October 26, 2025
*Health Monitoring*

- **Health Check Endpoint** — `/health` endpoint with status, uptime, memory, and system info (improves observability)

#### **v2.3.1** — October 26, 2025
*Quality of Life Improvements*

- **Custom Error Pages** — Branded HTML templates with minimal CSS for better UX (defends against information leakage)
- **Webhook Notifications** — Attack alerts to Slack/Discord/Teams with severity filtering (improves incident response)
- **IP Reputation APIs** — AbuseIPDB and IPQualityScore integration with caching (defends against known bad actors)
- **Connection Pooling** — HTTP transport optimization for backend proxy (improves performance)
- **Log Rotation** — Automatic log rotation with compression and retention policies (prevents disk space issues)
- **JWT/Session Rate Limiting** — Per-user rate limits separate from IP-based limits (defends against distributed attacks)

#### **v2.3** — October 24, 2025
*Performance & Observability Release*

- **Prometheus Metrics Endpoint** — 20+ metrics at `/metrics` for monitoring (requests, blocks, challenges, fingerprints, latency)
- **Hot-Reload Configuration** — Update IP rules/GeoIP without restart (auto file-watch + manual triggers)
- **HTTP Reload API** — `POST /reload` endpoint for programmatic configuration updates
- **SIGHUP Signal Handler** — Manual reload via `kill -SIGHUP` for DevOps workflows
- **Configuration Validation** — JSON validation with safe rollback on reload errors
- **Debounced File Watching** — 2-second debounce prevents reload storms during batch edits

See [docs/CHANGELOGS/V2.3_FEATURES.md](docs/CHANGELOGS/V2.3_FEATURES.md) for detailed feature documentation.

#### **v2.2** — October 24, 2025
*Maintenance & Security Release*

- **Constant-time token comparison** — Prevents timing attacks on token validation
- **Rate limiting on `/fingerprint/collect`** — Prevents fingerprint collection DoS
- **Improved CAPTCHA error messages** — Better user experience on failed challenges
- **Better malformed header handling** — Prevents header injection attacks

#### **v2.1** — October 22, 2025
*Security Hardening*

- **Secure cookie handling with auto-detect HTTPS** — Defends against MITM attacks
- **CAPTCHA secret validation warnings** — Prevents silent misconfigurations
- **IP spoofing protection via trusted proxy validation** — Blocks X-Forwarded-For bypass
- **New `waf/security` package** — X-Forwarded-For validation against trusted proxy list

---

### Upcoming Releases

#### **v2.5** — Advanced Rate Limiting & Analytics

Target: November 2025

**Planned Features:**

- **Advanced rate limiting algorithms** — Token bucket and sliding window implementations
- **GraphQL query depth limiting** — Prevents DoS via deeply nested queries
- **WebSocket security** — Rate limiting and payload inspection for WS connections
- **Response header security** — Auto-inject CSP, HSTS, X-Frame-Options headers
- **API schema validation** — OpenAPI/Swagger schema enforcement
- **Session fingerprint binding** — Bind sessions to browser fingerprint
- **Geo-velocity checking** — Flag impossible travel between requests

#### **v3.0** — Enterprise Features

Target: Q1 2026

- **Distributed rate limiting** — Redis backend for multi-server deployments
- **Web UI dashboard** — Rule management and live monitoring interface
- **Challenge history & reputation scoring** — Track and block repeat offenders
- **Multi-server session synchronization** — Shared fingerprint/session store
- **Machine learning anomaly detection** — Behavioral analysis for 0-day threats
- **Custom Lua scripting** — Advanced rule customization engine

---

## License

AGPL-3.0 - requires open sourcing derivative works

---

**Version**: 2.4.0 | **Status**: Production-ready with HTTP request smuggling detection | **Last Updated**: October 28, 2025
