package oauth

import (
	"regexp"
	"strings"
)

// RolesFromClaim returns the role names found under claimName in the validated
// token's non-standard claims (Claims.Extra) that match re, preserving claim
// order and de-duplicating.
//
// The claim value is expected to be a JSON array of strings — the shape an IdP
// action emits for a roles claim. A nil claims, empty claimName, nil re, a
// missing claim, a wrong-typed claim, or no matches all yield an empty slice;
// the caller decides whether an empty set is fatal (fail-closed). Because the
// claim is read from Extra, namespaced keys (e.g. "https://clickhouse/roles")
// work without any special handling.
func RolesFromClaim(claims *Claims, claimName string, re *regexp.Regexp) []string {
	if claims == nil || claimName == "" || re == nil {
		return nil
	}
	raw, ok := claims.Extra[claimName]
	if !ok {
		return nil
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	seen := make(map[string]struct{}, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" || !re.MatchString(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
