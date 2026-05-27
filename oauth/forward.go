package oauth

import "strings"

// BuildClickHouseHeaders returns the headers MCP forwards to ClickHouse for the
// Bearer wire format: just the bearer wrapped as `Authorization: Bearer <token>`.
//
// Both forward mode and broker mode use this. Under broker:true the CH auth
// method (Bearer vs Basic) is auto-detected by probing Bearer first; if this
// helper returned nil for broker mode, that probe would carry NO Authorization
// header, ClickHouse would fall back to the `default` user (REQUIRED_PASSWORD /
// AUTHENTICATION_FAILED), and the Bearer probe could never succeed against a
// token_processor backend — silently forcing every broker deployment onto the
// Basic path. Pure gating (no broker) does not flow through this helper; its CH
// credentials are conveyed via the Basic header assembled by clickhouse-go from
// Auth.Username/Auth.Password.
func BuildClickHouseHeaders(cfg OAuthConfig, token string) map[string]string {
	if !cfg.IsForwardMode() && !cfg.Broker {
		return nil
	}
	return map[string]string{
		"Authorization": "Bearer " + token,
	}
}

// EmailFromNamespacedExtra returns the first string-valued claim whose key
// ends with `/email` from the JWT's non-standard claim map. Auth0 third-party
// (DCR) tokens in enhanced security mode silently drop non-namespaced custom
// claims, forcing operators to set email under a URL-prefixed key (e.g.
// `https://mcp.altinity.cloud/email`). Looking up by suffix lets MCP accept
// any namespace the operator chose.
func EmailFromNamespacedExtra(extra map[string]interface{}) string {
	for k, v := range extra {
		if !strings.HasSuffix(k, "/email") {
			continue
		}
		if s, ok := v.(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				return t
			}
		}
	}
	return ""
}
