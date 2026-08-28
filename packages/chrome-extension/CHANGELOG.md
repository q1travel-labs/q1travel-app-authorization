# Changelog

## 0.1.0 — Unpublished candidate

- Added the exact eight-method runtime composition and six-method UI facade.
- Added a static operation catalog with caller policy and exact input/output
  decoders for `authorizedFetch`.
- Added the sole package compiler for opaque catalogs and literal-context
  filtering of callable operation IDs.
- Added a V2 background dispatcher with extension sender, top-frame and exact
  entry-path checks.
- Bound runtime composition to the concrete Task 3 runtime and installed its
  internal, external, tab and alarm listeners alongside the V2 listener.
- Moved Task 3 repository, tab and authorization coordinator construction
  inside the public runtime factory; consumers now provide only explicitly
  service-worker-only storage, Chrome, crypto, state, profile and exchange
  resources.
- Removed the public coordinator/callback-ingress dependency surface and kept
  background secret-processing ports outside the UI facade/catalog graph.
- Made the V2 listener synchronously decline non-V2 traffic so Task 3 bootstrap
  messages retain their existing keepalive/response semantics.
- Added closed, bounded V2 UI request and result parsing with fresh data-only
  copies and fail-closed errors.
- Added a testing-only consumer public-surface conformance entry.
- Added a declaration-emitting build with a safe public declaration graph,
  compiled `/testing` entry and no source maps.
- Added isolated build-and-pack verification of the exact candidate manifest,
  all retained ESM imports, extracted public composition, blocked deep imports
  and forbidden contents.

No registry artifact has been published, and no consumer adoption is claimed.
# 0.1.1

- Export the dependency-free `prepareAuthorization` PKCE helper and its profile types for consumers.
