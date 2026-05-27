package oauth

import "testing"

// TestBuildClickHouseHeaders pins the Bearer-header wire format. The SDK
// returns the header whenever the caller asks for Bearer auth; host services
// decide whether to use Bearer or another ClickHouse auth method.
func TestBuildClickHouseHeaders(t *testing.T) {
	const tok = "tok123"
	cases := []struct {
		name     string
		cfg      OAuthConfig
		wantBear bool
	}{
		{"default config", OAuthConfig{}, true},
		{"broker true", OAuthConfig{Broker: true}, true},
		{"empty token", OAuthConfig{Broker: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := tok
			if tc.name == "empty token" {
				token = " "
			}
			h := BuildClickHouseHeaders(tc.cfg, token)
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
