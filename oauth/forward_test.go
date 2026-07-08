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

// TestUsernameFromExtra pins the strict, top-level, string-only lookup used to
// derive the ClickHouse Basic-auth username from a configured claim. Every
// non-string / missing / blank case must fail closed (ok == false) so the host
// can reject rather than fall back to another identity.
func TestUsernameFromExtra(t *testing.T) {
	raw := map[string]interface{}{
		"username":                     "alice",
		"padded":                       "  bob  ",
		"blank":                        "   ",
		"num":                          12345,
		"arr":                          []interface{}{"a", "b"},
		"obj":                          map[string]interface{}{"x": 1},
		"https://example.com/username": "namespaced",
	}
	cases := []struct {
		name    string
		claim   string
		wantVal string
		wantOK  bool
	}{
		{"found string", "username", "alice", true},
		{"whitespace trimmed", "padded", "bob", true},
		{"blank value fails closed", "blank", "", false},
		{"missing claim fails closed", "sub", "", false},
		{"non-string number fails closed", "num", "", false},
		{"non-string array fails closed", "arr", "", false},
		{"non-string object fails closed", "obj", "", false},
		{"empty claim name fails closed", "", "", false},
		{"whitespace claim name fails closed", "   ", "", false},
		{"exact key only, no suffix match", "username2", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UsernameFromExtra(raw, tc.claim)
			if ok != tc.wantOK || got != tc.wantVal {
				t.Fatalf("UsernameFromExtra(raw, %q) = (%q, %v), want (%q, %v)",
					tc.claim, got, ok, tc.wantVal, tc.wantOK)
			}
		})
	}

	t.Run("nil map fails closed", func(t *testing.T) {
		if got, ok := UsernameFromExtra(nil, "username"); ok || got != "" {
			t.Fatalf("nil map: got (%q, %v), want (\"\", false)", got, ok)
		}
	})
}
