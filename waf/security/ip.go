package security

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxyConfig defines which proxies we trust for X-Forwarded-For
type TrustedProxyConfig struct {
	TrustedCIDRs []*net.IPNet
	TrustAll     bool
}

var defaultConfig = &TrustedProxyConfig{
	TrustedCIDRs: []*net.IPNet{
		mustParseCIDR("127.0.0.0/8"),
		mustParseCIDR("::1/128"),
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
		mustParseCIDR("fc00::/7"),
	},
	TrustAll: false,
}

var currentConfig = defaultConfig

func SetTrustedProxies(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		nets = append(nets, ipnet)
	}
	currentConfig = &TrustedProxyConfig{
		TrustedCIDRs: nets,
		TrustAll:     false,
	}
	return nil
}

func GetRealIP(r *http.Request) string {
	remoteIP := getRemoteIP(r)
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return remoteIP
	}

	if !currentConfig.TrustAll && !isTrustedProxy(ip) {
		return remoteIP
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(parts[0])
		if parsed := net.ParseIP(clientIP); parsed != nil {
			return clientIP
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsed := net.ParseIP(xri); parsed != nil {
			return xri
		}
	}

	return remoteIP
}

func getRemoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isTrustedProxy(ip net.IP) bool {
	for _, cidr := range currentConfig.TrustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func NormalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}

	if parsed.To4() != nil {
		return parsed.To4().String()
	}

	return parsed.To16().String()
}

func IsIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

func IsIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
