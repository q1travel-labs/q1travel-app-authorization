# @q1travel/app-authorization

Unified OAuth authorization-code runtime for Chrome extensions. Tokens stay in the background service worker and are never returned through the UI facade.

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
import { createAuthRuntime } from '@q1travel/app-authorization/extension'

export const auth = createAuthRuntime({
  clientId: 'registered-extension-client',
  redirectUri: chrome.identity.getRedirectURL('authorization-callback'),
  scopes: ['orders:read'],
  apiOrigin: 'https://api.example.com',
  pathPrefix: '/api',
})

```

`createAuthRuntime(config)` installs the background runtime and its strict UI message listener, then verifies any restored session once for that service-worker instance.

## Popup or extension page

```ts
import { createAuthFacade } from '@q1travel/app-authorization/extension'

const auth = createAuthFacade()
const session = await auth.verifySession()

if (session.status === 'signed-out') {
  await auth.login()
}

const unsubscribe = auth.onSessionChange((next) => {
  document.body.dataset.authenticated = String(next.status === 'authenticated')
})

window.addEventListener('unload', unsubscribe, { once: true })
```

The facade exposes `login`, `logout`, `getSession`, `verifySession`, and `onSessionChange`. It does not expose `authorizedFetch` or any credential-bearing type.

## React gate

```tsx
import { AuthGate } from '@q1travel/app-authorization/react'
import { createAuthFacade } from '@q1travel/app-authorization/extension'

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
| `pathPrefix` | no | API route prefix; defaults to `/api`. |
| `allowInsecureLoopback` | no | Allows explicit HTTP loopback origins for local tests only. |

The fixed authorization endpoints are `<apiOrigin><pathPrefix>/app-authorizations/v1/{authorize,token,revoke,session}`. Invalid or incomplete configuration fails closed.

## Background API

- `login()` launches `chrome.identity.launchWebAuthFlow`, validates the exact callback and exchanges one authorization code with PKCE S256.
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

- Access tokens exist only in background memory and `chrome.storage.session` configured for trusted contexts.
- UI and content-script messages contain only session metadata and stable errors.
- Sessions expire locally after the server-issued fixed eight-hour lifetime; there is no refresh token or replay.
- Authorization callback origin and path must exactly match `redirectUri`; `state` must match the active transaction.
- `authorizedFetch` never accepts a cross-origin target or a caller-supplied `Authorization` header.
- Applications keep business API message allowlists and authorization-dependent cleanup in their own background code.

## Upgrade from the former extension-specific package

Replace the old package dependency and imports with `@q1travel/app-authorization/extension`. Remove tab-based authorization, external callback bridges, caller-supplied token exchange, UI fetch relays, and operation catalogs. Initialize one background runtime, use the facade in extension pages, and move business messages to the application's own typed background protocol.
