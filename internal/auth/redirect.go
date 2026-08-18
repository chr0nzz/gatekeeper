package auth

import (
	"net/url"
	"strings"
)

// RedirectPolicy decides whether a post-login redirect target is trusted.
type RedirectPolicy struct {
	hosts        map[string]bool
	suffixes     []string
	cookieDomain string
	extraHosts   func() []string
}

// SetExtraHosts installs a loader for operator-managed allowed hosts.
func (p *RedirectPolicy) SetExtraHosts(fn func() []string) {
	p.extraHosts = fn
}

// ParseHostList splits a comma or newline separated list of hosts into entries.
func ParseHostList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// NewRedirectPolicy builds a policy from the deployment URLs and an allowlist.
func NewRedirectPolicy(baseURL, adminURL, cookieDomain string, allowed []string) *RedirectPolicy {
	p := &RedirectPolicy{hosts: map[string]bool{}}
	for _, raw := range []string{baseURL, adminURL} {
		if h := hostOf(raw); h != "" {
			p.hosts[h] = true
		}
	}
	if cookieDomain != "" {
		p.cookieDomain = strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	}
	for _, entry := range allowed {
		if s := normalizeEntry(entry); s != "" {
			p.suffixes = append(p.suffixes, s)
		}
	}
	return p
}

func normalizeEntry(entry string) string {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return ""
	}
	if strings.Contains(entry, "://") {
		entry = hostOf(entry)
	}
	entry = strings.TrimPrefix(entry, "*")
	return strings.TrimPrefix(entry, ".")
}

// Allowed reports whether target is a permitted redirect destination.
func (p *RedirectPolicy) Allowed(target string) bool {
	if target == "" {
		return false
	}
	if isRelativePath(target) {
		return true
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return p.hostAllowed(u.Hostname())
}

// Sanitize returns target when it is allowed, and "/" otherwise.
func (p *RedirectPolicy) Sanitize(target string) string {
	if p.Allowed(target) {
		return target
	}
	return "/"
}

func (p *RedirectPolicy) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	if host == "" {
		return false
	}
	if p.hosts[host] {
		return true
	}
	if p.cookieDomain != "" && matchesSuffix(host, p.cookieDomain) {
		return true
	}
	for _, s := range p.suffixes {
		if matchesSuffix(host, s) {
			return true
		}
	}
	if p.extraHosts != nil {
		for _, entry := range p.extraHosts() {
			if matchesEntry(host, entry) {
				return true
			}
		}
	}
	return false
}

func matchesEntry(host, entry string) bool {
	s := normalizeEntry(entry)
	return s != "" && matchesSuffix(host, s)
}

func matchesSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func isRelativePath(target string) bool {
	if !strings.HasPrefix(target, "/") {
		return false
	}
	if strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return false
	}
	return true
}

func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
