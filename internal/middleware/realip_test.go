package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIP(t *testing.T) {
	tests := []struct {
		name   string
		peer   string
		header map[string]string
		want   string
	}{
		{
			name:   "client X-Real-IP is ignored",
			peer:   "172.18.0.2:4000",
			header: map[string]string{"X-Real-IP": "203.0.113.10", "X-Forwarded-For": "198.51.100.9"},
			want:   "198.51.100.9:0",
		},
		{
			name:   "X-Real-IP alone does not change the address",
			peer:   "172.18.0.2:4000",
			header: map[string]string{"X-Real-IP": "203.0.113.10"},
			want:   "172.18.0.2:4000",
		},
		{
			name:   "rightmost public forwarded address wins",
			peer:   "172.18.0.2:4000",
			header: map[string]string{"X-Forwarded-For": "203.0.113.10, 198.51.100.9, 172.18.0.1"},
			want:   "198.51.100.9:0",
		},
		{
			name:   "public peer cannot set forwarding headers",
			peer:   "198.51.100.9:4000",
			header: map[string]string{"X-Real-IP": "203.0.113.10", "X-Forwarded-For": "203.0.113.10"},
			want:   "198.51.100.9:4000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			handler := TrustedRealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.peer
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tt.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, tt.want)
			}
		})
	}
}
