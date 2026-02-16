package caddyanubis

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/TecharoHQ/anubis"
	libanubis "github.com/TecharoHQ/anubis/lib"
	"github.com/TecharoHQ/anubis/lib/config"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

func init() {
	caddy.RegisterModule(AnubisMiddleware{})
}

// nextHandlerKey is a context key used to pass the Caddy next handler
// through the request context to the Anubis server's Next handler closure.
type nextHandlerKey struct{}

// AnubisMiddleware implements an HTTP handler that wraps the Anubis
// proof-of-work bot protection system as Caddy middleware.
type AnubisMiddleware struct {
	// PolicyFile is the path to the Anubis bot policy configuration file.
	// If empty, the built-in default policy is used.
	PolicyFile string `json:"policy_file,omitempty"`

	// Difficulty is the number of leading zero bits required in the
	// proof-of-work challenge. Defaults to 4.
	Difficulty int `json:"difficulty,omitempty"`

	// CookieDomain sets the Domain attribute on Anubis cookies.
	// If empty, cookies are scoped to the request domain.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// CookieExpiration controls how long the authorization cookie is valid.
	// Defaults to 7 days.
	CookieExpiration caddy.Duration `json:"cookie_expiration,omitempty"`

	// CookiePartitioned enables the Partitioned cookie attribute (CHIPS support).
	CookiePartitioned bool `json:"cookie_partitioned,omitempty"`

	// CookieSecure sets the Secure flag on cookies. Defaults to true.
	CookieSecure *bool `json:"cookie_secure,omitempty"`

	// CookieSameSite sets the SameSite attribute. Valid values: none, lax, strict, default.
	CookieSameSite string `json:"cookie_same_site,omitempty"`

	// CookieDynamicDomain automatically sets cookie Domain based on request domain.
	CookieDynamicDomain bool `json:"cookie_dynamic_domain,omitempty"`

	// CookiePrefix sets the prefix for cookie names.
	// The auth cookie becomes "<prefix>-auth" and test cookie becomes "<prefix>-cookie-verification".
	CookiePrefix string `json:"cookie_prefix,omitempty"`

	// ServeRobotsTXT serves a robots.txt that disallows all robots.
	ServeRobotsTXT bool `json:"serve_robots_txt,omitempty"`

	// OGPassthrough enables Open Graph tag passthrough for link previews.
	OGPassthrough bool `json:"og_passthrough,omitempty"`

	// OGExpiryTime sets the Open Graph tag cache expiration. Defaults to 24h.
	OGExpiryTime caddy.Duration `json:"og_expiry_time,omitempty"`

	// OGCacheConsiderHost includes the host in OG tag cache keys.
	OGCacheConsiderHost bool `json:"og_cache_consider_host,omitempty"`

	// BasePrefix sets a URL prefix under which Anubis is served (e.g. "/myapp").
	BasePrefix string `json:"base_prefix,omitempty"`

	// StripBasePrefix strips the base prefix from requests forwarded to the upstream.
	StripBasePrefix bool `json:"strip_base_prefix,omitempty"`

	// WebmasterEmail displays the webmaster's email on the reject page.
	WebmasterEmail string `json:"webmaster_email,omitempty"`

	// RedirectDomains is a list of domains Anubis is allowed to redirect to.
	// If empty, only same-domain redirects are allowed.
	RedirectDomains []string `json:"redirect_domains,omitempty"`

	// ED25519PrivateKeyHex is a hex-encoded ed25519 seed for signing JWTs.
	// If neither this nor HS512Secret is set, a random key is generated.
	ED25519PrivateKeyHex string `json:"ed25519_private_key_hex,omitempty"`

	// HS512Secret is the secret used to sign JWTs with HS512.
	// Mutually exclusive with ED25519PrivateKeyHex.
	HS512Secret string `json:"hs512_secret,omitempty"`

	// PublicURL is the externally accessible URL for this Anubis instance.
	PublicURL string `json:"public_url,omitempty"`

	// JWTRestrictionHeader binds JWTs to a specific header value.
	// Defaults to "X-Real-IP".
	JWTRestrictionHeader string `json:"jwt_restriction_header,omitempty"`

	// DifficultyInJWT adds the difficulty field to JWT claims.
	DifficultyInJWT bool `json:"difficulty_in_jwt,omitempty"`

	// UseSimplifiedExplanation replaces the challenge explanation text with
	// a simplified version for non-technical audiences.
	UseSimplifiedExplanation bool `json:"use_simplified_explanation,omitempty"`

	// ForcedLanguage overrides the Accept-Language header with this language.
	ForcedLanguage string `json:"forced_language,omitempty"`

	// Target is the upstream URL to reverse proxy to. This is only used
	// when Anubis is running in standalone mode; in Caddy middleware mode,
	// the next handler in the chain acts as the upstream.
	Target string `json:"target,omitempty"`

	// LogLevel sets the Anubis internal log level. Defaults to "INFO".
	LogLevel string `json:"log_level,omitempty"`

	// anubisServer is the provisioned Anubis server instance.
	anubisServer http.Handler
}

// CaddyModule returns the Caddy module information.
func (AnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.anubis",
		New: func() caddy.Module { return new(AnubisMiddleware) },
	}
}

// Provision sets up the Anubis middleware.
func (m *AnubisMiddleware) Provision(ctx caddy.Context) error {
	logger := ctx.Logger()

	anubis.ForcedLanguage = m.ForcedLanguage
	anubis.UseSimplifiedExplanation = m.UseSimplifiedExplanation

	if m.CookiePrefix != "" {
		anubis.CookieName = m.CookiePrefix + "-auth"
		anubis.TestCookieName = m.CookiePrefix + "-cookie-verification"
	}

	if m.Difficulty == 0 {
		m.Difficulty = anubis.DefaultDifficulty
	}
	if m.LogLevel == "" {
		m.LogLevel = "INFO"
	}

	policy, err := libanubis.LoadPoliciesOrDefault(ctx, m.PolicyFile, m.Difficulty, m.LogLevel)
	if err != nil {
		return fmt.Errorf("anubis: failed to load policy: %v", err)
	}

	var ed25519Priv ed25519.PrivateKey
	if m.ED25519PrivateKeyHex != "" && m.HS512Secret != "" {
		return fmt.Errorf("anubis: cannot specify both ed25519_private_key_hex and hs512_secret")
	}
	if m.ED25519PrivateKeyHex != "" {
		keyBytes, err := hex.DecodeString(m.ED25519PrivateKeyHex)
		if err != nil {
			return fmt.Errorf("anubis: ed25519_private_key_hex is not valid hex: %v", err)
		}
		if len(keyBytes) != ed25519.SeedSize {
			return fmt.Errorf("anubis: ed25519_private_key_hex must be %d bytes, got %d", ed25519.SeedSize, len(keyBytes))
		}
		ed25519Priv = ed25519.NewKeyFromSeed(keyBytes)
	}

	cookieSecure := true
	if m.CookieSecure != nil {
		cookieSecure = *m.CookieSecure
	}

	sameSite := http.SameSiteNoneMode
	if m.CookieSameSite != "" {
		sameSite = parseSameSite(m.CookieSameSite)
		if sameSite == 0 {
			return fmt.Errorf("anubis: invalid cookie_same_site value %q, valid values are none, lax, strict, default", m.CookieSameSite)
		}
	}

	cookieExpiration := anubis.CookieDefaultExpirationTime
	if m.CookieExpiration > 0 {
		cookieExpiration = time.Duration(m.CookieExpiration)
	}

	og := config.OpenGraph{
		Enabled:      m.OGPassthrough,
		ConsiderHost: m.OGCacheConsiderHost,
		Override:     map[string]string{},
	}
	if m.OGExpiryTime > 0 {
		og.TimeToLive = time.Duration(m.OGExpiryTime)
	} else if m.OGPassthrough {
		og.TimeToLive = 24 * time.Hour
	}

	if policy.OpenGraph.Enabled {
		og = policy.OpenGraph
	}

	var redirectDomains []string
	if len(m.RedirectDomains) > 0 {
		redirectDomains = m.RedirectDomains
	}

	opts := libanubis.Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next, ok := r.Context().Value(nextHandlerKey{}).(caddyhttp.Handler)
			if !ok {
				logger.Error("anubis: next handler not found in request context")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if err := next.ServeHTTP(w, r); err != nil {
				logger.Error("anubis: next handler error", zap.Error(err))
			}
		}),
		Policy:              policy,
		Target:              m.Target,
		CookieDynamicDomain: m.CookieDynamicDomain,
		CookieDomain:        m.CookieDomain,
		CookieExpiration:    cookieExpiration,
		CookiePartitioned:   m.CookiePartitioned,
		CookieSecure:        cookieSecure,
		CookieSameSite:      sameSite,
		BasePrefix:          m.BasePrefix,
		StripBasePrefix:     m.StripBasePrefix,
		WebmasterEmail:      m.WebmasterEmail,
		RedirectDomains:     redirectDomains,
		ED25519PrivateKey:   ed25519Priv,
		HS512Secret:         hs512Secret(m.HS512Secret),
		ServeRobotsTXT:      m.ServeRobotsTXT,
		OpenGraph:           og,
		PublicUrl:            m.PublicURL,
		JWTRestrictionHeader: m.JWTRestrictionHeader,
		DifficultyInJWT:     m.DifficultyInJWT,
		Logger:              slog.New(zapslog.NewHandler(logger.Core())),
		LogLevel:            m.LogLevel,
	}

	s, err := libanubis.New(opts)
	if err != nil {
		return fmt.Errorf("anubis: failed to create server: %v", err)
	}

	m.anubisServer = s
	logger.Info("anubis middleware provisioned",
		zap.Int("difficulty", m.Difficulty),
		zap.Bool("serve_robots_txt", m.ServeRobotsTXT),
		zap.Bool("og_passthrough", m.OGPassthrough),
		zap.String("base_prefix", m.BasePrefix),
	)

	return nil
}

// Validate ensures the middleware configuration is valid.
func (m *AnubisMiddleware) Validate() error {
	if m.CookieDomain != "" && m.CookieDynamicDomain {
		return fmt.Errorf("anubis: cannot set both cookie_domain and cookie_dynamic_domain")
	}
	if m.StripBasePrefix && m.BasePrefix == "" {
		return fmt.Errorf("anubis: strip_base_prefix requires base_prefix to be set")
	}
	if m.BasePrefix != "" && !strings.HasPrefix(m.BasePrefix, "/") {
		return fmt.Errorf("anubis: base_prefix must start with a slash, e.g. /%s", m.BasePrefix)
	}
	if m.BasePrefix != "" && strings.HasSuffix(m.BasePrefix, "/") {
		return fmt.Errorf("anubis: base_prefix must not end with a slash")
	}
	if m.ED25519PrivateKeyHex != "" && m.HS512Secret != "" {
		return fmt.Errorf("anubis: cannot specify both ed25519_private_key_hex and hs512_secret")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *AnubisMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := context.WithValue(r.Context(), nextHandlerKey{}, next)
	m.anubisServer.ServeHTTP(w, r.WithContext(ctx))
	return nil
}

// hs512Secret returns nil when s is empty (so Anubis auto-generates an
// ed25519 key) and []byte(s) otherwise. []byte("") is a non-nil empty
// slice, which would bypass Anubis's nil-check and leave the signing
// key uninitialized.
func hs512Secret(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// parseSameSite converts a string to an http.SameSite value.
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "default":
		return http.SameSiteDefaultMode
	default:
		return 0
	}
}

// Interface guards.
var (
	_ caddy.Module                = (*AnubisMiddleware)(nil)
	_ caddy.Provisioner           = (*AnubisMiddleware)(nil)
	_ caddy.Validator             = (*AnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AnubisMiddleware)(nil)
)
