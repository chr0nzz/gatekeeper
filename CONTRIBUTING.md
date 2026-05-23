# Contributing

Thanks for your interest in contributing to GateKeeper.

## Before you start

For anything beyond a small bug fix, open an issue first to discuss the change. This avoids wasted effort if the direction does not fit the project.

## Development setup

Requirements: Go 1.26+, no CGO required.

```bash
git clone https://github.com/chr0nzz/gatekeeper
cd gatekeeper
go build -o gatekeeper ./cmd/gatekeeper
```

Run with:

```bash
BASE_URL=http://localhost:8080 SECRET_KEY=$(openssl rand -hex 32) ./gatekeeper
```

The admin UI is at `http://localhost:8080/admin`.

## Making changes

- Keep changes focused. One logical change per pull request.
- Match the existing code style - short, clear, no comments unless the reason is non-obvious.
- No new dependencies without prior discussion.
- If you add a new feature that users need to configure or understand, update the docs in `/docs`.

## Templates and static assets

HTML templates live in `web/templates/`. Static files (CSS, JS) live in `web/static/`. Both are embedded into the binary at build time via `assets.go`.

After editing templates or static files, rebuild to pick up the changes:

```bash
go build -o gatekeeper ./cmd/gatekeeper
```

## Database migrations

New tables or schema changes go in `internal/db/migrations/` as sequentially numbered SQL files (`009_*.sql`, etc.). Migrations run automatically on startup.

## Pull requests

- Target the `main` branch.
- Include a clear description of what changed and why.
- If the change fixes a bug, reference the issue number.
- Keep the diff small and reviewable.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
