# Changelog

## 0.1.0 — 2026-09-27

Published to npm at 14:51 UTC from source commit `bdd06eb` using a maintainer's local `npm publish q1travel-app-authorization-0.1.0.tgz --access public --provenance=false`. This release has no npm provenance attestation because npm trusted publishing was not configured and local publishing could not generate provenance.
The tarball had npm shasum `29502bae252c587ebda8fa8d0ef20e75762ce3b6`, with 35 files (15.0 kB packed, 64.2 kB unpacked). `npm view` returned 404 during registry propagation; a later registry readback confirmed the version and shasum.
For subsequent releases, use `.github/workflows/release-provenance.yml`; the repository is public, and an npm trusted publisher must first be configured.

- Publish the neutral `@q1travel/app-authorization` package.
- Add authorization-code login with PKCE, session verification, revocation, and authorized fetch.
- Add the token-free extension facade and optional headless React gate.
- Allow empty and root API path prefixes for unprefixed deployments.
- Gate restored-session reads on startup verification with observable failure and timeout behavior.
- Support Node.js 22 and later for package installation and build tooling.
- Split the extension API into background-only and token-free UI entry points.
- Explicitly restrict session storage to Chrome trusted contexts and document that extension-owned pages share that trust domain.
