# RhinoWAF

High-performance Web Application Firewall in Go with advanced DDoS protection, geolocation-based blocking, and granular IP controls.

## Features

### **Core Protection**
- **DDoS Protection**: Rate limiting, burst detection, Slowloris mitigation, reputation scoring
- **Input Sanitization**: SQL injection, XSS, path traversal, command injection blocking
- **IP Management**: 60+ per-IP control fields with priority-based rule matching
- **Geolocation Blocking**: Country/region-based access control with CIDR lookup
- **ASN Blocking**: Block entire autonomous systems (hosting providers, VPNs)
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

### **Planned (Not Yet Implemented)**
- CAPTCHA/Challenge system (fields exist, not wired up)
- JavaScript challenge verification
- Proof-of-work challenges
- Browser fingerprinting
- Real-time config hot-reload
- Distributed rate limiting (Redis)
- Web UI for rule management

## Quick Start

```bash
go build -o bin/rhinowaf ./cmd/rhinowaf
./bin/rhinowaf
```

Server runs on `:8080`. Attack logs: `./logs/ddos.log`

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
      "action": "block",
      "priority": 10
    }
  ],
  "global_rules": {
    "default_action": "allow",
    "blocked_countries": ["KP", "IR"],
    "block_tor": true,
    "block_sql_injection": true,
    "block_xss": true,
    "max_requests_per_ip": 1000
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

Config file at `./config/ip_rules.json`:

```json
{
  "version": "1.0",
  "last_modified": "2025-01-18T00:00:00Z",
  "banned_ips": [
    { "ip": "192.0.2.10", "type": "ban", "reason": "brute force", "expires_at": null }
  ],
  "whitelisted_ips": [
    { "ip": "10.0.0.1", "type": "whitelist", "reason": "internal monitoring" }
  ],
  "monitored_ips": [
    { "ip": "198.51.100.42", "type": "monitor", "reason": "suspicious traffic" }
  ]
}
```

Usage:

```go
ipm := ddos.GetIPManager()
ipm.BanIP("203.0.113.42", "brute force", "admin", 24*time.Hour, nil)
ipm.WhitelistIP("10.0.0.1", "internal", "devops", "", nil)
ipm.MonitorIP("198.51.100.42", "suspicious", nil)
```

## License

AGPL-3.0 - requires open sourcing derivative works

