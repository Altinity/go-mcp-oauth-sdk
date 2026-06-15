package oauth

import (
	"reflect"
	"regexp"
	"testing"
)

// TestRolesFromClaim pins the per-request role-filtering contract: only roles
// from the named claim that match the filter are returned, the claim is read
// from Extra (so namespaced keys work), and every "no roles" condition yields
// an empty slice so the host can fail closed.
func TestRolesFromClaim(t *testing.T) {
	const claim = "https://clickhouse/roles"
	mcpOnly := regexp.MustCompile(`_mcp$`)
	matchAll := regexp.MustCompile(``)

	withClaim := func(v interface{}) *Claims {
		return &Claims{Extra: map[string]interface{}{claim: v}}
	}

	cases := []struct {
		name      string
		claims    *Claims
		claimName string
		re        *regexp.Regexp
		want      []string
	}{
		{
			name:      "filters to matching subset, preserves order",
			claims:    withClaim([]interface{}{"analyst", "sandbox_mcp", "admin", "readonly_mcp"}),
			claimName: claim,
			re:        mcpOnly,
			want:      []string{"sandbox_mcp", "readonly_mcp"},
		},
		{
			name:      "no match yields empty (fail-closed signal)",
			claims:    withClaim([]interface{}{"analyst", "admin"}),
			claimName: claim,
			re:        mcpOnly,
			want:      nil,
		},
		{
			name:      "match-all regex returns every string role",
			claims:    withClaim([]interface{}{"a", "b"}),
			claimName: claim,
			re:        matchAll,
			want:      []string{"a", "b"},
		},
		{
			name:      "trims blanks and dedupes",
			claims:    withClaim([]interface{}{" x_mcp ", "x_mcp", "  ", "y_mcp"}),
			claimName: claim,
			re:        mcpOnly,
			want:      []string{"x_mcp", "y_mcp"},
		},
		{
			name:      "ignores non-string array elements",
			claims:    withClaim([]interface{}{"keep_mcp", 42, true, nil}),
			claimName: claim,
			re:        mcpOnly,
			want:      []string{"keep_mcp"},
		},
		{
			name:      "missing claim",
			claims:    &Claims{Extra: map[string]interface{}{"other": []interface{}{"x_mcp"}}},
			claimName: claim,
			re:        mcpOnly,
			want:      nil,
		},
		{
			name:      "non-array claim type",
			claims:    withClaim("x_mcp,y_mcp"),
			claimName: claim,
			re:        mcpOnly,
			want:      nil,
		},
		{name: "nil claims", claims: nil, claimName: claim, re: mcpOnly, want: nil},
		{name: "empty claim name", claims: withClaim([]interface{}{"x_mcp"}), claimName: "", re: mcpOnly, want: nil},
		{name: "nil regex", claims: withClaim([]interface{}{"x_mcp"}), claimName: claim, re: nil, want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RolesFromClaim(tc.claims, tc.claimName, tc.re)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("RolesFromClaim = %#v, want %#v", got, tc.want)
			}
		})
	}
}
