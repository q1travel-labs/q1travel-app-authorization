# Changelog

## 0.1.0

- Publish the neutral `@q1travel/app-authorization` package.
- Add authorization-code login with PKCE, session verification, revocation, and authorized fetch.
- Add the token-free extension facade and optional headless React gate.
- Allow empty and root API path prefixes for unprefixed deployments.
- Gate restored-session reads on startup verification with observable failure and timeout behavior.
- Support Node.js 22 and later for package installation and build tooling.
- Split the extension API into background-only and token-free UI entry points.
- Explicitly restrict session storage to Chrome trusted contexts and document that extension-owned pages share that trust domain.
