package caddyanubis

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
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

// maxDifficulty is the upper bound for proof-of-work difficulty.
// SHA-256 produces 256 bits; requiring more than 32 leading hex zeros
// (128 bits) is computationally infeasible and would DoS legitimate users.
const maxDifficulty = 32

// globalStateMu protects writes to anubis package-level globals.
// These globals (CookieName, ForcedLanguage, etc.) are shared across all
// instances in a Caddy process. We refcount successful provisions so
// Cleanup() from an old generation cannot clear state that a new
// generation already relies on.
var (
	globalStateMu       sync.Mutex
	globalStateRefCount int

	// Snapshot upstream defaults so we can restore them when the last
	// instance is removed (refcount reaches zero).
	defaultCookieName     = anubis.CookieName
	defaultTestCookieName = anubis.TestCookieName
	defaultForcedLang     = anubis.ForcedLanguage
	defaultSimplified     = anubis.UseSimplifiedExplanation
	defaultBasePrefix     = anubis.BasePrefix
	defaultPublicURL      = anubis.PublicUrl

	globalStateOwner   string
	globalCookiePrefix string
	globalForcedLang   string
	globalSimplified   bool
	globalBasePrefix   string
	globalPublicURL    string
	globalStateSet     bool
)

// nextHandlerKey is a context key used to pass the Caddy next handler
// through the request context to the Anubis server's Next handler closure.
type nextHandlerKey struct{}

// AnubisMiddleware implements an HTTP handler that wraps the Anubis
// proof-of-work bot protection system as Caddy middleware.
type AnubisMiddleware struct {
	// PolicyFile is the path to the Anubis bot policy configuration file.
	// If empty, the built-in default policy is used.
	PolicyFile string `json:"policy_file,omitempty"`

	// Difficulty is the number of leading hex zeros required in the
	// proof-of-work challenge. Must be between 1 and 32. Defaults to 4.
	Difficulty int `json:"difficulty,omitempty"`

	// CookieDomain sets the Domain attribute on Anubis cookies.
	// If empty, cookies are scoped to the request domain.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// CookieExpiration controls how long the authorization cookie is valid.
	// Defaults to 7 days.
	CookieExpiration caddy.Duration `json:"cookie_expiration,omitempty"`

	// CookiePartitioned enables the Partitioned cookie attribute (CHIPS support).
	// Requires cookie_secure=true and cookie_same_site=none.
	CookiePartitioned bool `json:"cookie_partitioned,omitempty"`

	// CookieSecure sets the Secure flag on cookies. Defaults to true.
	CookieSecure *bool `json:"cookie_secure,omitempty"`

	// CookieSameSite sets the SameSite attribute. Valid values: none, lax, strict, default.
	// Defaults to "lax".
	CookieSameSite string `json:"cookie_same_site,omitempty"`

	// CookieDynamicDomain automatically sets cookie Domain based on request domain.
	CookieDynamicDomain bool `json:"cookie_dynamic_domain,omitempty"`

	// CookiePrefix sets the prefix for cookie names.
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
	// WARNING: visible via Caddy admin API; use {env.VAR} placeholders for secrets.
	ED25519PrivateKeyHex string `json:"ed25519_private_key_hex,omitempty"`

	// HS512Secret is the secret used to sign JWTs with HS512.
	// Mutually exclusive with ED25519PrivateKeyHex.
	// WARNING: visible via Caddy admin API; use {env.VAR} placeholders for secrets.
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

	// TargetHost overrides the Host header when forwarding requests to the target.
	TargetHost string `json:"target_host,omitempty"`

	// TargetSNI sets the TLS Server Name Indication when connecting to the target.
	TargetSNI string `json:"target_sni,omitempty"`

	// TargetInsecureSkipVerify skips TLS certificate verification for the target.
	TargetInsecureSkipVerify bool `json:"target_insecure_skip_verify,omitempty"`

	// LogLevel sets the Anubis internal log level. Defaults to "INFO".
	LogLevel string `json:"log_level,omitempty"`

	anubisServer       http.Handler
	claimedGlobalState bool
}

// CaddyModule returns the Caddy module information.
func (AnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.anubis",
		New: func() caddy.Module { return new(AnubisMiddleware) },
	}
}

// MarshalJSON redacts secret fields so they are not exposed via the
// Caddy admin API (GET /config/). Users should prefer {env.VAR}
// placeholders for secrets, but defense-in-depth is prudent.
func (m AnubisMiddleware) MarshalJSON() ([]byte, error) {
	// Type alias breaks the method set so json.Marshal won't recurse.
	type redacted AnubisMiddleware
	r := redacted(m)
	if r.ED25519PrivateKeyHex != "" {
		r.ED25519PrivateKeyHex = "[REDACTED]"
	}
	if r.HS512Secret != "" {
		r.HS512Secret = "[REDACTED]"
	}
	return json.Marshal(r)
}

// Provision sets up the Anubis middleware.
//
// NOTE: Caddy calls Provision() BEFORE Validate(). We call m.Validate()
// explicitly at the top so that no side effects (global state mutation,
// key derivation) occur with an invalid configuration.
func (m *AnubisMiddleware) Provision(ctx caddy.Context) error {
	logger := ctx.Logger()

	if err := m.Validate(); err != nil {
		return err
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
	edConfigured := m.ED25519PrivateKeyHex != ""
	if edConfigured {
		keyBytes, err := hex.DecodeString(m.ED25519PrivateKeyHex)
		if err != nil {
			return fmt.Errorf("anubis: ed25519_private_key_hex is not valid hex: %v", err)
		}
		if len(keyBytes) != ed25519.SeedSize {
			return fmt.Errorf("anubis: ed25519_private_key_hex must be %d bytes, got %d", ed25519.SeedSize, len(keyBytes))
		}
		ed25519Priv = ed25519.NewKeyFromSeed(keyBytes)

		// Zero seed material after key derivation.
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}

	cookieSecure := true
	if m.CookieSecure != nil {
		cookieSecure = *m.CookieSecure
	}

	sameSite := http.SameSiteLaxMode
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
		if m.OGPassthrough || m.OGExpiryTime > 0 || m.OGCacheConsiderHost {
			logger.Warn("anubis: policy file OpenGraph settings override Caddyfile og_passthrough/og_expiry_time/og_cache_consider_host")
		}
		og = policy.OpenGraph
	}

	var redirectDomains []string
	if len(m.RedirectDomains) > 0 {
		redirectDomains = m.RedirectDomains
	}

	hsConfigured := m.HS512Secret != ""

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
		Policy:                   policy,
		Target:                   m.Target,
		TargetHost:               m.TargetHost,
		TargetSNI:                m.TargetSNI,
		TargetInsecureSkipVerify: m.TargetInsecureSkipVerify,
		CookieDynamicDomain:      m.CookieDynamicDomain,
		CookieDomain:             m.CookieDomain,
		CookieExpiration:         cookieExpiration,
		CookiePartitioned:        m.CookiePartitioned,
		CookieSecure:             cookieSecure,
		CookieSameSite:           sameSite,
		BasePrefix:               m.BasePrefix,
		StripBasePrefix:          m.StripBasePrefix,
		WebmasterEmail:           m.WebmasterEmail,
		RedirectDomains:          redirectDomains,
		ED25519PrivateKey:        ed25519Priv,
		HS512Secret:              hs512Secret(m.HS512Secret),
		ServeRobotsTXT:           m.ServeRobotsTXT,
		OpenGraph:                og,
		PublicUrl:                m.PublicURL,
		JWTRestrictionHeader:     m.JWTRestrictionHeader,
		DifficultyInJWT:          m.DifficultyInJWT,
		Logger:                   slog.New(zapslog.NewHandler(logger.Core())),
		LogLevel:                 m.LogLevel,
	}

	// Global state check + libanubis.New() run under one lock so that
	// upstream global writes are serialized and rolled back on failure.
	s, err := m.setGlobalState(logger, opts)
	if err != nil {
		return fmt.Errorf("anubis: %v", err)
	}
	m.anubisServer = s

	// Secrets consumed by libanubis.New(); replace with sentinel so
	// MarshalJSON / admin API shows a secret was configured.
	if hsConfigured {
		m.HS512Secret = "[REDACTED]"
	}
	if edConfigured {
		m.ED25519PrivateKeyHex = "[REDACTED]"
	}

	logger.Info("anubis middleware provisioned",
		zap.Int("difficulty", m.Difficulty),
		zap.Bool("serve_robots_txt", m.ServeRobotsTXT),
		zap.Bool("og_passthrough", m.OGPassthrough),
		zap.String("base_prefix", m.BasePrefix),
	)

	return nil
}

func (m *AnubisMiddleware) Validate() error {
	if m.Difficulty < 0 {
		return fmt.Errorf("anubis: difficulty must be non-negative (0 = use default of %d), got %d", anubis.DefaultDifficulty, m.Difficulty)
	}
	if m.Difficulty > maxDifficulty {
		return fmt.Errorf("anubis: difficulty must be <= %d, got %d", maxDifficulty, m.Difficulty)
	}
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
	if m.CookieSameSite != "" && parseSameSite(m.CookieSameSite) == 0 {
		return fmt.Errorf("anubis: invalid cookie_same_site value %q, valid values are none, lax, strict, default", m.CookieSameSite)
	}

	cookieSecure := m.CookieSecure == nil || *m.CookieSecure
	sameSite := parseSameSite(m.CookieSameSite)
	if sameSite == http.SameSiteNoneMode && !cookieSecure {
		return fmt.Errorf("anubis: cookie_same_site=none requires cookie_secure=true")
	}
	if m.CookiePartitioned && !cookieSecure {
		return fmt.Errorf("anubis: cookie_partitioned requires cookie_secure=true")
	}
	if m.CookiePartitioned && sameSite != http.SameSiteNoneMode {
		return fmt.Errorf("anubis: cookie_partitioned requires cookie_same_site=none")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
//
// Anubis's http.Handler interface does not return errors, so errors from
// the next handler in the chain are logged but cannot be propagated to
// Caddy's error handling middleware.
func (m *AnubisMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := context.WithValue(r.Context(), nextHandlerKey{}, next)
	m.anubisServer.ServeHTTP(w, r.WithContext(ctx))
	return nil
}

// Cleanup decrements the global-state refcount. Only when the last
// claimed instance is cleaned up do we reset tracking and restore
// upstream defaults.
func (m *AnubisMiddleware) Cleanup() error {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()

	if !m.claimedGlobalState {
		return nil
	}
	m.claimedGlobalState = false

	if globalStateRefCount > 0 {
		globalStateRefCount--
	}
	if globalStateRefCount != 0 {
		return nil
	}

	resetGlobalStateLocked()
	return nil
}

func resetGlobalStateLocked() {
	globalStateSet = false
	globalStateOwner = ""
	globalCookiePrefix = ""
	globalForcedLang = ""
	globalSimplified = false
	globalBasePrefix = ""
	globalPublicURL = ""

	anubis.CookieName = defaultCookieName
	anubis.TestCookieName = defaultTestCookieName
	anubis.ForcedLanguage = defaultForcedLang
	anubis.UseSimplifiedExplanation = defaultSimplified
	anubis.BasePrefix = defaultBasePrefix
	anubis.PublicUrl = defaultPublicURL
}

func applyUpstreamGlobalsLocked(cookiePrefix, forcedLang string, simplified bool) {
	anubis.ForcedLanguage = forcedLang
	anubis.UseSimplifiedExplanation = simplified

	if cookiePrefix != "" {
		anubis.CookieName = cookiePrefix + "-auth"
		anubis.TestCookieName = cookiePrefix + "-cookie-verification"
		return
	}
	anubis.CookieName = defaultCookieName
	anubis.TestCookieName = defaultTestCookieName
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

// setGlobalState checks compatibility with the process-wide global settings,
// then calls libanubis.New(opts) under the same mutex (because upstream New()
// mutates anubis.BasePrefix/PublicUrl without synchronization).
//
// On success it commits the remaining upstream globals, updates tracking,
// and increments the refcount for Cleanup().
func (m *AnubisMiddleware) setGlobalState(logger *zap.Logger, opts libanubis.Options) (http.Handler, error) {
	globalStateMu.Lock()
	defer globalStateMu.Unlock()

	desc := describeInstance(m)

	if globalStateSet {
		var conflicts []string
		if m.CookiePrefix != globalCookiePrefix {
			conflicts = append(conflicts, fmt.Sprintf("cookie_prefix: existing=%q new=%q", globalCookiePrefix, m.CookiePrefix))
		}
		if m.ForcedLanguage != globalForcedLang {
			conflicts = append(conflicts, fmt.Sprintf("forced_language: existing=%q new=%q", globalForcedLang, m.ForcedLanguage))
		}
		if m.UseSimplifiedExplanation != globalSimplified {
			conflicts = append(conflicts, fmt.Sprintf("use_simplified_explanation: existing=%v new=%v", globalSimplified, m.UseSimplifiedExplanation))
		}
		if m.BasePrefix != globalBasePrefix {
			conflicts = append(conflicts, fmt.Sprintf("base_prefix: existing=%q new=%q", globalBasePrefix, m.BasePrefix))
		}
		if m.PublicURL != globalPublicURL {
			conflicts = append(conflicts, fmt.Sprintf("public_url: existing=%q new=%q", globalPublicURL, m.PublicURL))
		}
		if len(conflicts) > 0 {
			return nil, fmt.Errorf("anubis: global state conflict between [%s] and [%s]: %s",
				globalStateOwner, desc, strings.Join(conflicts, "; "))
		}
	}

	// Snapshot for rollback — upstream New() writes these globals.
	prevBasePrefix := anubis.BasePrefix
	prevPublicURL := anubis.PublicUrl

	s, err := libanubis.New(opts)
	if err != nil {
		anubis.BasePrefix = prevBasePrefix
		anubis.PublicUrl = prevPublicURL
		return nil, err
	}

	applyUpstreamGlobalsLocked(m.CookiePrefix, m.ForcedLanguage, m.UseSimplifiedExplanation)

	if !globalStateSet {
		globalStateOwner = desc
		globalCookiePrefix = m.CookiePrefix
		globalForcedLang = m.ForcedLanguage
		globalSimplified = m.UseSimplifiedExplanation
		globalBasePrefix = m.BasePrefix
		globalPublicURL = m.PublicURL
		globalStateSet = true
	} else if desc != globalStateOwner {
		logger.Warn("anubis: multiple instances share global state; settings from first instance apply",
			zap.String("owner", globalStateOwner),
			zap.String("current", desc),
		)
	}

	if !m.claimedGlobalState {
		globalStateRefCount++
		m.claimedGlobalState = true
	}

	return s, nil
}

func describeInstance(m *AnubisMiddleware) string {
	parts := []string{"anubis"}
	if m.BasePrefix != "" {
		parts = append(parts, "prefix="+m.BasePrefix)
	}
	if m.CookieDomain != "" {
		parts = append(parts, "domain="+m.CookieDomain)
	}
	if m.Target != "" {
		parts = append(parts, "target="+m.Target)
	}
	return strings.Join(parts, ",")
}

// Interface guards.
var (
	_ caddy.Module                = (*AnubisMiddleware)(nil)
	_ caddy.Provisioner           = (*AnubisMiddleware)(nil)
	_ caddy.Validator             = (*AnubisMiddleware)(nil)
	_ caddy.CleanerUpper          = (*AnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AnubisMiddleware)(nil)
)
