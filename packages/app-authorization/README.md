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

## Adjacent-tab authorization (0.2.0)

The background entry also exports `createAdjacentTabAuthRuntime` and
`TAB_AUTH_CALLBACK`. Construct one runtime synchronously at service-worker top
level so Chrome can register its wake-up listeners:

```ts
const runtime = createAdjacentTabAuthRuntime(config, {
  chrome,
  getSourceTab: async () => {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
    if (!tab) throw new Error('No source tab')
    return tab
  },
})
await runtime.ready()
```

Use the normal UI facade. An explicit login opens a blank tab in the source
window at `source.index + 1`, records ownership and PKCE state in
`chrome.storage.session`, then navigates to the authorization endpoint. Declare
`alarms` and an `externally_connectable.matches` entry restricted to the trusted
callback origin/path. The callback must be an exact registered HTTPS URL without
query or fragment. HTTP localhost/127.0.0.1 callbacks require
`allowInsecureLoopback: true`; this is for local development only.

The callback page preserves its initial callback URL in memory, removes its
query from browser history, and sends the following closed envelope to its
registered extension ID:

```ts
{ type: 'q1travel.appAuthorization.callback.v1', callbackUrl }
```

Only a top-frame Web sender whose origin and cleaned URL exactly match the
configured callback and whose tab ID matches the persisted owned tab is
accepted. State and callback shape are checked before SDK token exchange. The
response is `{ ok: true }` or `{ ok: false, error: { code, message, retryable } }`;
it carries no token or session. Web owns no PKCE verifier or token exchange.

Transactions survive worker restart while authorization is pending. A callback
claims its transaction durably before exchange; a restarted worker cancels an
already claimed exchange instead of replaying the code. Manual tab closure,
logout or the ten-minute maximum alarm expires the flow. Concurrent login calls
share one pending operation; after restart a new login action focuses the
existing owned tab. Completion closes only the recorded tab with a matching
Chrome opener relation and restores the source only if the auth tab remains
active in the focused source window. The default `createAuthRuntime` identity
flow remains available.

Real-browser acceptance must separately verify external callback delivery,
worker suspension/restart, exact adjacent placement and focused-window behavior.
Unit tests and packing alone do not establish that acceptance.

## Optional background authorization context (unreleased)

Both background runtimes accept `authorizationContextPort?: AuthorizationContextPort`.
Import this type and `AuthorizationSourceMetadata` from the background subpath.
The consumer implements:

```ts
interface AuthorizationContextPort {
  prepare(input: {
    clientId: string; redirectUri: string; state: string; codeChallenge: string;
    sourceTabId?: number;
  }): Promise<{ token: string }>;
  assertCurrent(input: {
    token: string; phase: 'beforeExchange' | 'beforeSessionCommit';
  }): Promise<void>;
}
```

`prepare` must return exactly one own field, `token`, containing a canonical
43-character base64url encoding of 32 bytes. The SDK adds it only to the
`authorization_context` authorize query and v2 pending transaction. The port
never receives access tokens or the PKCE verifier. Context failures use fixed
SDK errors; acquired tokens are revoked on failed commit, with
`revocation_unconfirmed` if remote revocation cannot be confirmed. A failed
strict flow clears its own local session without clearing a newer login.

Adjacent-tab `getSourceTab(source?)` receives only trusted Chrome metadata:
`{ tabId?: number, frameId?: number, documentId?: string }`. Resolve an embedded
extension frame from `source.tabId`; verify the consumer's original top document
and identity observation, and never substitute the active tab. The SDK rejects
a returned tab ID that differs from this original ID. For a popup with no tab,
capture the active tab immediately when called, before awaiting application
startup. The SDK invokes this resolver once as it accepts the operation, before
its own startup waits, and preserves the resolved source throughout PKCE and
callback handling. Concurrent login requests from a different UI source are
rejected. Direct background `login()` passes no metadata; the consumer is
responsible for choosing a trustworthy source. The ordinary identity runtime
omits `sourceTabId` from `prepare`.

Opt-in pending flows use independent v2 keys. Enabling the port cancels old v1
pending flows; disabling it cancels v2 pending flows. Malformed records are
removed. Strict recovery runs the same context checks; if a restarted consumer
lost its token-to-source association, it must reject rather than reconstruct
identity from the token. A new strict login does not attach itself to another
pending authorization. The public facade remains `login()` and its request
still contains exactly `protocol`, `requestId`, and `action`; public session,
core configuration, token exchange and session storage shapes are unchanged.
