package caddyanubis

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("anubis", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("anubis", httpcaddyfile.After, "templates")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m AnubisMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	anubis {
//	    policy_file          <path>
//	    difficulty           <int>
//	    cookie_domain        <domain>
//	    cookie_expiration    <duration>
//	    cookie_partitioned
//	    cookie_secure        <bool>
//	    cookie_same_site     <none|lax|strict|default>
//	    cookie_dynamic_domain
//	    cookie_prefix        <prefix>
//	    serve_robots_txt
//	    og_passthrough
//	    og_expiry_time       <duration>
//	    og_cache_consider_host
//	    base_prefix          <prefix>
//	    strip_base_prefix
//	    webmaster_email      <email>
//	    redirect_domains     <domain1> [<domain2> ...]
//	    ed25519_private_key_hex <hex>
//	    hs512_secret         <secret>
//	    public_url           <url>
//	    jwt_restriction_header <header>
//	    difficulty_in_jwt
//	    use_simplified_explanation
//	    forced_language      <lang>
//	    target               <url>
//	    target_host          <host>
//	    target_sni           <sni>
//	    target_insecure_skip_verify
//	    log_level            <level>
//	}
func (m *AnubisMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	for d.NextBlock(0) {
		switch d.Val() {
		case "policy_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PolicyFile = d.Val()

		case "difficulty":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid difficulty value: %v", err)
			}
			m.Difficulty = val

		case "cookie_domain":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookieDomain = d.Val()

		case "cookie_expiration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid cookie_expiration: %v", err)
			}
			m.CookieExpiration = caddy.Duration(dur)

		case "cookie_partitioned":
			m.CookiePartitioned = true

		case "cookie_secure":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.ParseBool(d.Val())
			if err != nil {
				return d.Errf("invalid cookie_secure value: %v", err)
			}
			m.CookieSecure = &val

		case "cookie_same_site":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := strings.ToLower(d.Val())
			switch val {
			case "none", "lax", "strict", "default":
				m.CookieSameSite = val
			default:
				return d.Errf("invalid cookie_same_site %q, valid values are none, lax, strict, default", d.Val())
			}

		case "cookie_dynamic_domain":
			m.CookieDynamicDomain = true

		case "cookie_prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookiePrefix = d.Val()

		case "serve_robots_txt":
			m.ServeRobotsTXT = true

		case "og_passthrough":
			m.OGPassthrough = true

		case "og_expiry_time":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid og_expiry_time: %v", err)
			}
			m.OGExpiryTime = caddy.Duration(dur)

		case "og_cache_consider_host":
			m.OGCacheConsiderHost = true

		case "base_prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.BasePrefix = d.Val()

		case "strip_base_prefix":
			m.StripBasePrefix = true

		case "webmaster_email":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.WebmasterEmail = d.Val()

		case "redirect_domains":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.RedirectDomains = append(m.RedirectDomains, args...)

		case "ed25519_private_key_hex":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ED25519PrivateKeyHex = d.Val()

		case "hs512_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.HS512Secret = d.Val()

		case "public_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PublicURL = d.Val()

		case "jwt_restriction_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.JWTRestrictionHeader = d.Val()

		case "difficulty_in_jwt":
			m.DifficultyInJWT = true

		case "use_simplified_explanation":
			m.UseSimplifiedExplanation = true

		case "forced_language":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ForcedLanguage = d.Val()

		case "target":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Target = d.Val()

		case "target_host":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.TargetHost = d.Val()

		case "target_sni":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.TargetSNI = d.Val()

		case "target_insecure_skip_verify":
			m.TargetInsecureSkipVerify = true

		case "log_level":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.LogLevel = d.Val()

		default:
			return d.Errf("unknown anubis option: %s", d.Val())
		}
	}

	return nil
}

var _ caddyfile.Unmarshaler = (*AnubisMiddleware)(nil)
