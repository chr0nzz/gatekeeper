# Security Policy

## Supported versions

Only the latest release receives security fixes. Older versions are not backported.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub: go to the Security tab of this repository and open a private advisory, or email the maintainer directly if you cannot find the contact.

Include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The version of GateKeeper you tested against
- Any suggested mitigation or fix

You will receive an acknowledgement within 48 hours. If the report is confirmed, a fix will be prepared and released as soon as possible - typically within 7 days for critical issues, 30 days for others. You will be credited in the release notes unless you prefer to remain anonymous.

## Scope

Issues in scope:

- Authentication and session handling
- OIDC provider implementation
- ForwardAuth middleware
- Admin UI access controls
- Cryptographic operations (password hashing, TOTP, passkeys, signing keys)
- SQL injection, XSS, CSRF

Out of scope:

- Vulnerabilities in dependencies not yet fixed upstream
- Attacks requiring physical access to the server
- Denial-of-service via resource exhaustion
- Issues in the documentation site

## Security hardening notes

When deploying GateKeeper:

- Use a strong, randomly generated `SECRET_KEY` (at minimum 32 bytes, generated with `openssl rand -hex 32`)
- Place GateKeeper behind HTTPS - session cookies are marked `Secure` and will not work over plain HTTP
- Restrict access to the SQLite database file - it contains hashed credentials and encrypted TOTP secrets
- Set `ALLOWED_EMAIL_DOMAINS` if you want to limit which email addresses can register
- Review the audit log regularly for unexpected activity
