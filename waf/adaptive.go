package waf

import (
	"net/http"
	"rhinowaf/waf/ddos"
	"rhinowaf/waf/sanitize"
	"time"
)

func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ddos.GetIP(r)

		// Validate headers for malformed or malicious content (prevents header injection)
		if valid, reason := sanitize.ValidateHeaders(r); !valid {
			http.Error(w, "RhinoWAF: Malformed headers - "+reason, http.StatusBadRequest)
			return
		}

		// Check advanced IP rules first (most specific)
		ipMgr := ddos.GetIPManager()
		if ipMgr != nil {
			ctx := &ddos.RequestContext{
				IP:            ip,
				Path:          r.URL.Path,
				FullURL:       r.URL.String(),
				Method:        r.Method,
				UserAgent:     r.UserAgent(),
				Referer:       r.Referer(),
				ContentType:   r.Header.Get("Content-Type"),
				ContentLength: r.ContentLength,
				Protocol:      r.Proto,
				IsHTTPS:       r.TLS != nil,
				Timestamp:     time.Now(),
				Headers:       make(map[string]string),
				Cookies:       make(map[string]string),
				QueryParams:   make(map[string]string),
			}

			// Copy headers
			for key, values := range r.Header {
				if len(values) > 0 {
					ctx.Headers[key] = values[0]
				}
			}

			// Copy cookies
			for _, cookie := range r.Cookies() {
				ctx.Cookies[cookie.Name] = cookie.Value
			}

			// Copy query params
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					ctx.QueryParams[key] = values[0]
				}
			}

			allowed, reason := ipMgr.ValidateRequest(ctx)
			if !allowed {
				http.Error(w, "RhinoWAF: Access denied - "+reason, http.StatusForbidden)
				return
			}
		}

		// Check rate limits (L7/L4)
		if !ddos.AllowL7(ip) || !ddos.AllowL4(ip) {
			http.Error(w, "RhinoWAF: Attack Diffused/Mitigated", http.StatusTooManyRequests)
			return
		}

		// Check for malicious input FIRST (before sanitization removes patterns)
		if sanitize.IsMalicious(r) {
			http.Error(w, "RhinoWAF: Malicious input blocked", http.StatusForbidden)
			return
		}

		// Then sanitize all input before passing to backend
		sanitize.All(r)

		next(w, r)
	}
}
