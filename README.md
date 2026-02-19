# caddy-anubis

> **Warning: Not Production Ready**
>
> This module has no unit or integration tests. Use at your own risk. Contributions and testing are welcome.

A [Caddy](https://caddyserver.com) module that integrates [Anubis](https://github.com/TecharoHQ/anubis) proof-of-work bot protection as middleware.

Anubis presents visitors with a lightweight SHA-256 proof-of-work challenge before granting access to your upstream service. Once solved, a JWT cookie is issued and subsequent requests pass through without interruption.

## Building

Requires [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build \
  --with github.com/hui1601/caddy-anubis \
  --replace 'github.com/TecharoHQ/anubis=github.com/hui1601/anubis@v1.25.0-embed'
```

> The `--replace` flag is required because the upstream Anubis module does not ship its embedded static assets in the Go module distribution. The fork at `github.com/hui1601/anubis` includes these assets.

## Caddyfile Usage

```caddy
{
    order anubis before reverse_proxy
}

:443 {
    request_header X-Real-Ip {remote_host}

    anubis {
        difficulty 4
    }

    reverse_proxy localhost:8080
}
```

### Minimal (all defaults)

```caddy
anubis
```

### All Options

```caddy
anubis {
    # PoW difficulty (number of leading hex zeros required). Default: 4
    difficulty 4

    # Path to a custom bot policy YAML file
    policy_file /etc/anubis/policy.yaml

    # Cookie settings
    cookie_domain example.com
    cookie_expiration 168h
    cookie_partitioned true
    cookie_secure true
    cookie_same_site lax
    cookie_dynamic_domain true
    cookie_prefix myapp

    # JWT signing (mutually exclusive, omit both to auto-generate ed25519 key)
    ed25519_private_key_hex <64-char-hex-seed>
    hs512_secret <secret-string>

    # JWT restriction header (bind JWT to a header value, default: X-Real-IP)
    jwt_restriction_header X-Real-IP
    # Set to "" to disable restriction
    jwt_restriction_header ""

    # Include difficulty in JWT claims
    difficulty_in_jwt true

    # Open Graph tag passthrough for link previews
    og_passthrough true
    og_expiry_time 24h
    og_cache_consider_host true

    # Serve a robots.txt that disallows all bots
    serve_robots_txt true

    # URL prefix for Anubis (for sub-path deployments)
    base_prefix /myapp
    strip_base_prefix true

    # Webmaster email shown on reject pages
    webmaster_email admin@example.com

    # Allowed redirect domains after challenge completion
    redirect_domains example.com cdn.example.com

    # Public URL override
    public_url https://example.com

    # Use simplified explanation text
    use_simplified_explanation true

    # Force a specific language
    forced_language en

    # Log level for Anubis internals
    log_level INFO
}
```

## Important Notes

### X-Real-Ip Header

Anubis requires the `X-Real-Ip` header. Add this before the `anubis` directive:

```caddy
request_header X-Real-Ip {remote_host}
```

### Cookie Security over HTTP

When testing over plain HTTP (no TLS), disable secure cookies:

```caddy
anubis {
    cookie_secure false
    cookie_same_site lax
}
```

Browsers reject `Secure` cookies over HTTP, which will cause the challenge flow to fail.

### Directive Order

Register the `anubis` handler before your proxy/file server:

```caddy
{
    order anubis before reverse_proxy
}
```

## JSON Config

The module is registered as `http.handlers.anubis`. All Caddyfile options map to JSON fields:

```json
{
    "handler": "anubis",
    "difficulty": 4,
    "cookie_secure": true,
    "cookie_same_site": "lax",
    "serve_robots_txt": true
}
```

## License

ISC
