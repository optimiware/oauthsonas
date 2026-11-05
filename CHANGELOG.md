# Changelog

## Unreleased

### Fixed

- Background cleanup raced with in-flight requests on fosite's in-memory store
  (a fatal concurrent map access under load). All store access now goes through
  one lock; cleanup also prunes the request-ID maps and keeps rotated refresh
  tokens until their own expiry.
- `id_token_hint` was never verified (the private key was passed to the
  verifier), so logout could not identify the client. It is now verified with
  the public key and constrains the allowed `post_logout_redirect_uri`.
- `Server.Close()` stops the cleanup goroutine.
- The README quick start used an `OIDC_AUDIENCE` that the example config rejects.

### Changed

- `prompt=none` returns `login_required` immediately instead of rendering the
  picker; unknown `prompt` values return `invalid_request`.
- `/logout` accepts `POST` as well as `GET`.
- `/userinfo` error responses include CORS headers for registered origins and
  expose `WWW-Authenticate`.
- The token endpoint reads parameters from the POST body only (matching fosite)
  and request bodies are limited to 64 KiB.
- The interaction cookie is `Secure` when the issuer is `https`, like the gate
  cookie.
- The access-code gate logs successful and rejected attempts.
- Config: `token_ttl`, `authorization_code_ttl`, and `refresh_token_ttl` must be
  Go duration strings; validation reports every problem at once;
  `OAUTHSONAS_ACCESS_CODE` is applied inside `config.Load`.
- Unknown `--log-format` / `--log-level` values are rejected instead of ignored.
- Replaced `gopkg.in/yaml.v3` with the maintained `go.yaml.in/yaml/v3`.

### Added

- `--healthcheck` flag and a container `HEALTHCHECK` (the image has no shell or `curl`).
- [docs/e2e-stack.md](docs/e2e-stack.md): Compose and Playwright guide.
- CI gates for `gofmt`, `go mod tidy`, and `staticcheck`; the Go version is
  read from `go.mod`.

### Internal

- `internal/server` is split by concern (authorize, gate, token, userinfo,
  logout, session, store, http helpers); HTML templates are embedded files;
  routes use method-aware patterns.
- The multi-arch image is cross-compiled instead of built under QEMU.
- `test/e2e/smoke.sh` performs a full login against the image.
