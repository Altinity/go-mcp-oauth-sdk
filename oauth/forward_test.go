package oauth

import "testing"

// TestBuildClickHouseHeaders pins the Bearer-header wire format across modes.
// Regression guard: broker:true must emit the Authorization header so the
// CH-auth auto-detect's Bearer probe carries the token (otherwise CH falls back
// to the `default` user and the probe can never succeed — silently forcing
// every broker deployment onto the Basic path).
func TestBuildClickHouseHeaders(t *testing.T) {
	const tok = "tok123"
	cases := []struct {
		name     string
		cfg      OAuthConfig
		wantBear bool
	}{
		{"forward mode", OAuthConfig{Mode: "forward"}, true},
		{"broker:true", OAuthConfig{Broker: true}, true},
		{"broker:true + gating mode", OAuthConfig{Mode: "gating", Broker: true}, true},
		{"pure gating (no broker)", OAuthConfig{Mode: "gating"}, false},
		{"unset mode, no broker", OAuthConfig{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := BuildClickHouseHeaders(tc.cfg, tok)
			got, ok := h["Authorization"]
			if tc.wantBear {
				if !ok || got != "Bearer "+tok {
					t.Fatalf("want Authorization=Bearer %s, got %q (present=%v)", tok, got, ok)
				}
			} else if ok {
				t.Fatalf("expected no Authorization header, got %q", got)
			}
		})
	}
}
