# @q1travel/app-authorization

Unified OAuth authorization-code runtime for Chrome extensions. Tokens never reach content scripts, web pages, or SDK UI messages. Extension-owned pages and the service worker share Chrome's trusted-context storage boundary.

## Install

```sh
pnpm add @q1travel/app-authorization
```

Install React only when using the optional headless gate:

```sh
pnpm add react @q1travel/app-authorization
```

## Background

```ts
import { createAuthRuntime } from '@q1travel/app-authorization/extension/background'

export const auth = createAuthRuntime({
  clientId: 'registered-extension-client',
  redirectUri: chrome.identity.getRedirectURL('authorization-callback'),
  scopes: ['orders:read'],
  apiOrigin: 'https://api.example.com',
  pathPrefix: '/api',
})

try {
  await auth.ready()
} catch {
  // The local session can still be used; show that remote verification is unavailable.
}
```

`createAuthRuntime(config)` installs the background runtime and its strict UI message listener, then verifies any restored session once for that service-worker instance. `ready()` observes that first verification: it rejects with a retryable error on network failure or after 10 seconds. `getSession()`, `authorizedFetch()`, and facade session reads automatically wait for the first verification to settle, so callers cannot accidentally bypass it. After a network failure or timeout, a locally unexpired session remains available; use the `ready()` error to show that remote verification is temporarily unavailable.

## Popup or extension page

```ts
import { createAuthFacade } from '@q1travel/app-authorization/extension/ui'

const auth = createAuthFacade()
let session
try {
  session = await auth.verifySession()
} catch {
  session = await auth.getSession()
  // Keep a locally unexpired session and show that remote verification is unavailable.
}

if (session.status === 'signed-out') {
  await auth.login()
}

const unsubscribe = auth.onSessionChange((next) => {
  document.body.dataset.authenticated = String(next.status === 'authenticated')
})

window.addEventListener('unload', unsubscribe, { once: true })
```

The facade exposes `login`, `logout`, `getSession`, `verifySession`, and `onSessionChange`. An immediate `verifySession()` shares the startup verification and exposes its retryable failure; `getSession()` waits for that attempt to settle, then falls back to locally unexpired state. The facade does not expose `authorizedFetch` or any credential-bearing type.

## React gate

```tsx
import { AuthGate } from '@q1travel/app-authorization/react'
import { createAuthFacade } from '@q1travel/app-authorization/extension/ui'

const auth = createAuthFacade()

export function Root() {
  return (
    <AuthGate client={auth} loading={<>Loading</>} signedOut={<Login />}>
      <Application />
    </AuthGate>
  )
}
```

`AuthGate` and `useAuthSession` are headless. They verify the server session when mounted; the consumer owns copy, styling, and the login action.

## Configuration

| Field | Required | Meaning |
| --- | --- | --- |
| `clientId` | yes | Registered public client identifier. |
| `redirectUri` | yes | Exact `https://<extension-id>.chromiumapp.org/<path>` callback. |
| `scopes` | yes | Non-empty unique scope identifiers. |
| `apiOrigin` | yes | Exact API origin allowed by `authorizedFetch`. |
| `pathPrefix` | no | API route prefix; defaults to `/api`. Use `''` or `'/'` for no prefix. |
| `allowInsecureLoopback` | no | Allows explicit HTTP loopback origins for local tests only. |

The fixed authorization endpoints are `<apiOrigin><pathPrefix>/app-authorizations/v1/{authorize,token,revoke,session}`. Empty and root prefixes both normalize to `<apiOrigin>/app-authorizations/v1/*`; other prefixes must start with `/`, cannot contain `..`, a query, or a fragment, and cannot end in `/`. Invalid or incomplete configuration fails closed.

## Background API

- `login()` launches `chrome.identity.launchWebAuthFlow`, validates the exact callback and exchanges one authorization code with PKCE S256.
- `ready()` waits for the one-time restored-session verification and exposes retryable startup failures.
- `logout()` attempts remote revocation and always clears local state. It throws `revocation_unconfirmed` when the remote result is unknown.
- `getSession()` returns only status, expiry, and scopes.
- `verifySession()` checks the server session and clears revoked credentials.
- `onSessionChange(callback)` subscribes to token-free session metadata.
- `authorizedFetch(input, init)` allows only `apiOrigin`, rejects caller authorization headers, forces `credentials: 'omit'`, and clears matching credentials after `401` or `invalid_token`.

## Error codes

Errors are `AppAuthorizationError` instances with a stable `code`, fixed `message`, and `retryable` flag:

`configuration_invalid`, `interaction_cancelled`, `interaction_failed`, `authorization_denied`, `invalid_callback`, `state_mismatch`, `network_unavailable`, `oauth_invalid_request`, `oauth_invalid_grant`, `invalid_token`, `server_unavailable`, `response_invalid`, `storage_unavailable`, `session_expired`, `session_revoked`, `forbidden`, `revocation_unconfirmed`, `request_not_allowed`, and `runtime_unavailable`.

Errors never retain callback URLs, authorization codes, PKCE verifiers, or access tokens.

## Security boundary

- Access tokens exist in background memory and `chrome.storage.session`; runtime initialization explicitly sets `TRUSTED_CONTEXTS`.
- Chrome exposes no service-worker-only session-storage access level. `TRUSTED_CONTEXTS` blocks content scripts and web pages, but extension-owned pages and the service worker remain one trust domain and can read session storage.
- SDK UI messages contain only session metadata and stable errors; tokens never reach content scripts, web pages, or those messages.
- Sessions expire locally after the server-issued fixed eight-hour lifetime; there is no refresh token or replay.
- Authorization callback origin and path must exactly match `redirectUri`; `state` must match the active transaction.
- `authorizedFetch` never accepts a cross-origin target or a caller-supplied `Authorization` header.
- Applications keep business API message allowlists and authorization-dependent cleanup in their own background code.

The SDK deliberately keeps the simple session-storage design. Wrapping the stored token with an in-memory one-time key would lose that key whenever Chrome restarts the service worker, forcing verification or login again while adding little protection inside the extension's existing trusted-page boundary.

## Upgrade from the former extension-specific package

Replace the old package dependency and imports with `@q1travel/app-authorization/extension/background` in the service worker and `@q1travel/app-authorization/extension/ui` in extension pages. Remove tab-based authorization, external callback bridges, caller-supplied token exchange, UI fetch relays, and operation catalogs. Initialize one background runtime, use the facade in extension pages, and move business messages to the application's own typed background protocol.
