package middleware

import (
	"net"
	"net/http"
	"strings"
)

// TrustedRealIP rewrites RemoteAddr from forwarding headers only for private peers.
func TrustedRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peerIsTrusted(r.RemoteAddr) {
			if ip := forwardedClientIP(r); ip != "" {
				r.RemoteAddr = net.JoinHostPort(ip, "0")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func peerIsTrusted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || isSharedAddressSpace(ip)
}

func isSharedAddressSpace(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

func forwardedClientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" && net.ParseIP(v) != nil {
		return v
	}
	fwd := r.Header.Get("X-Forwarded-For")
	if fwd == "" {
		return ""
	}
	parts := strings.Split(fwd, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if ip := net.ParseIP(candidate); ip != nil && !peerIsTrusted(candidate) {
			return candidate
		}
	}
	first := strings.TrimSpace(parts[0])
	if net.ParseIP(first) != nil {
		return first
	}
	return ""
}
