package waf

import (
	"net/http"
	"webdefender/waf/ddos"
	"webdefender/waf/sanitize"
)

func AdaptiveProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ddos.GetIP(r)
		if !ddos.AllowL7(ip) || !ddos.AllowL4(ip) {
			http.Error(w, "WebDefender: Attack Diffused/Mitigated", http.StatusTooManyRequests)
			return
		}
		sanitize.All(r)
		if sanitize.IsMalicious(r) {
			http.Error(w, "WebDefender: Malicious input blocked", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
