# RhinoWAF

Web Application Firewall in Go with DDoS protection, input sanitization, and attack logging.

## Features

- DDoS protection with rate limiting, burst detection, and IP reputation
- Slowloris detection and mitigation
- Input sanitization for SQL injection, XSS, and malicious payloads
- JSON attack logging with detailed metrics
- IP management (ban/whitelist/monitor)
- Adaptive throttling under attack

## Quick Start

```bash
go run cmd/rhinowaf/main.go
```

Server starts on `:8080`. Logs written to `./logs/ddos.log`.

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
- ✅ **Challenge System** - JavaScript challenges (2-second delay)
- ✅ **Browser Fingerprinting** - Bot network detection
- ✅ **Geolocation Blocking** - High-risk countries challenged
- ✅ **Proxy/Tor Blocking** - Blocks proxies, Tor, hosting providers
- ✅ **Rate Limiting** - 100 requests/IP, 10 concurrent connections
- ✅ **User-Agent Filtering** - Blocks empty/suspicious UAs

### Configuration Files
- `cmd/rhinowaf/main.go` - Application configuration
- `config/ip_rules.json` - IP/geo rules (v2.0, production defaults)
- `config/geoip.json` - GeoIP database (12 CIDR ranges)

### Documentation
- **`PRODUCTION_CONFIG.md`** - Complete production configuration guide
- **`DEPLOYMENT_CHECKLIST.md`** - Step-by-step deployment checklist
- **`docs/CHALLENGE_SYSTEM.md`** - Challenge system documentation
- **`docs/FINGERPRINTING.md`** - Browser fingerprinting guide
- **`docs/IP_RULES.md`** - Complete IP rules reference
- **`docs/CHALLENGE_EXAMPLES.md`** - Challenge configuration examples
- **`docs/FINGERPRINTING_EXAMPLES.md`** - Fingerprinting examples

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

