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

// cloudflareRanges is the list at https://www.cloudflare.com/ips/. Only these addresses may vouch for CF-Connecting-IP.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

func isCloudflare(ip net.IP) bool {
	for _, cidr := range cloudflareRanges {
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func forwardedClientIP(r *http.Request) string {
	fwd := r.Header.Get("X-Forwarded-For")
	if fwd == "" {
		return ""
	}
	parts := strings.Split(fwd, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if ip := net.ParseIP(candidate); ip != nil && !peerIsTrusted(candidate) {
			if client := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); isCloudflare(ip) && net.ParseIP(client) != nil {
				return client
			}
			return candidate
		}
	}
	first := strings.TrimSpace(parts[0])
	if net.ParseIP(first) != nil {
		return first
	}
	return ""
}
