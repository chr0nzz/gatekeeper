# Contributing

Thanks for your interest in contributing to GateKeeper.

## Before you start

For anything beyond a small bug fix, open an issue first to discuss the change. This avoids wasted effort if the direction does not fit the project.

Found a security vulnerability? Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Go 1.26 or newer. No CGO.

```bash
git clone https://github.com/chr0nzz/gatekeeper
cd gatekeeper
go build -o gatekeeper ./cmd/gatekeeper
```

Run it:

```bash
BASE_URL=http://localhost:8282 \
ADMIN_URL=http://localhost:8283 \
SECRET_KEY=$(openssl rand -hex 32) \
DB_PATH=./dev.db \
./gatekeeper
```

GateKeeper listens on two ports. The public side (login, OIDC, ForwardAuth) is on `8282`, and the admin panel is on `8283`, served at the root rather than under `/admin`. Open `http://localhost:8283` to create the first admin account.

## Tests

```bash
go test ./...
```

Every pull request runs build, `go vet`, `gofmt`, and the test suite with race detection. Run these locally before pushing:

```bash
go vet ./...
gofmt -l .          # must print nothing
go test -race ./...
```

Tests that touch the database use a real SQLite file in a temporary directory, created through `db.Open` so migrations run exactly as they do in production. There is no mocking layer. Follow the existing helpers rather than introducing one.

Bugs found by tests are worth more than tests written after the fact. If you are fixing a bug, add the test that fails without your change.

## Making changes

- Keep changes focused. One logical change per pull request.
- Match the existing code style: short, clear, and no comments unless the reason behind the code is non-obvious. Comments explain why, not what.
- No em dashes in code, comments, docs, or UI text. Use a comma or a period.
- No new dependencies without prior discussion.
- If a change affects how users configure or understand GateKeeper, update `/docs` in the same pull request.

## Templates and static assets

HTML templates live in `web/templates/`, static files in `web/static/`. Both are embedded into the binary at build time via `assets.go`, so rebuild after editing them.

Three conventions are enforced by tests in `internal/templates`, because breaking them produces a page that fails only in a browser:

- **Inline scripts need a nonce.** Write `<script nonce="__CSP_NONCE__">`, never a bare `<script>`. The Content-Security-Policy has no `unsafe-inline`, and the placeholder is replaced per response.
- **No inline event handlers.** `onclick`, `onchange`, and friends are blocked by that same policy. Use a `data-` attribute and attach a listener in `web/static/js/`.
- **Use `$` for page values inside a range.** Write `{{$.CSRFToken}}`, not `{{.CSRFToken}}`, inside `{{range}}`. A plain dot resolves against the loop item and breaks every row.

## Database migrations

Schema changes go in `internal/db/migrations/` as sequentially numbered SQL files, continuing from the highest existing number. They run automatically on startup and are recorded, so each file is applied once and must never be edited after release.

Write migrations so they can run against an existing database with real data in it.

## Handling secrets and tokens

GateKeeper follows a few rules consistently. New code should too:

- Credentials stored in the database are hashed if they only need verifying (sessions, invites, reset tokens) or encrypted with `auth.EncryptSecret` if they need to be read back (TOTP secrets, SMTP passwords).
- Nothing secret goes in a URL or a log line.
- Compare secrets with `subtle.ConstantTimeCompare` or `hmac.Equal`.
- The database is limited to a single connection. Never write to it while a query cursor is still open, or the request will deadlock.

## Pull requests

- Target the `main` branch.
- Include a clear description of what changed and why.
- If the change fixes a bug, reference the issue number.
- Keep the diff small and reviewable.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
