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
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
  pathPrefix: '',
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
| `redirectUri` | yes | Exact registered callback URL. Use the Chromium identity URL for the identity flow or the registered Web page for the adjacent-tab flow. |
| `scopes` | yes | Non-empty unique scope identifiers. |
| `authOrigin` | yes | Origin serving authorize, token, revoke, session and contexts. |
| `apiOrigin` | yes | Resource origin allowed by `authorizedFetch`. Must differ from `authOrigin`. |
| `pathPrefix` | no | Protocol route prefix, default `/api`. Set `''` for the registered production routes. |
| `allowInsecureLoopback` | no | Allows explicit HTTP loopback origins for local tests only. |

Both origins must be explicit, canonical HTTPS origins such as `https://connect.q1lx.com` and `https://api.q1lx.com`, without a trailing slash. HTTP on localhost or 127.0.0.1 requires `allowInsecureLoopback: true`. Missing, identical or invalid origins fail initialization with `configuration_invalid`.

The SDK builds all five protocol URLs under `<authOrigin><pathPrefix>/app-authorizations/v1/`. Empty and root prefixes select the registered paths directly. Other prefixes start with a slash and contain only path segments. For a 0.3.0 migration, set both origins in every environment and point the context port at the supplied `contextsUrl`. An old configuration supplying only `apiOrigin` fails at startup.

## Background API

- `login()` launches `chrome.identity.launchWebAuthFlow`, validates the exact callback and exchanges one authorization code with PKCE S256.
- `ready()` waits for the one-time restored-session verification and exposes retryable startup failures.
- `logout()` attempts remote revocation and always clears local state. It throws `revocation_unconfirmed` when the remote result is unknown.
- `getSession()` returns only status, expiry, and scopes.
- `verifySession()` checks the server session and clears revoked credentials.
- `onSessionChange(callback)` subscribes to token-free session metadata.
- `authorizedFetch(input, init)` sends the bearer only to resource URLs on `apiOrigin`, rejects the five protocol paths and caller authorization headers, forces `credentials: 'omit'` and `redirect: 'error'`, and clears matching credentials after `401` or `invalid_token`.

## Error codes

Errors are `AppAuthorizationError` instances with a stable `code`, fixed `message`, and `retryable` flag:

`configuration_invalid`, `interaction_cancelled`, `interaction_failed`, `authorization_denied`, `invalid_callback`, `state_mismatch`, `network_unavailable`, `oauth_invalid_request`, `oauth_invalid_grant`, `invalid_token`, `server_unavailable`, `response_invalid`, `storage_unavailable`, `session_expired`, `session_revoked`, `forbidden`, `revocation_unconfirmed`, `request_not_allowed`, and `runtime_unavailable`.

Errors never retain callback URLs, authorization codes, PKCE verifiers, or access tokens.

## Security boundary

- Access tokens exist in background memory and `chrome.storage.session`; runtime initialization explicitly sets `TRUSTED_CONTEXTS`.
- Chrome exposes no service-worker-only session-storage access level. `TRUSTED_CONTEXTS` blocks content scripts and web pages, but extension-owned pages and the service worker remain one trust domain and can read session storage.
- SDK UI messages contain only session metadata and stable errors; tokens never reach content scripts, web pages, or those messages.
- Sessions expire locally after the server-issued fixed eight-hour lifetime; there is no refresh token or replay.
- Token exchange, revocation and session verification use fetch with redirects disabled. Session verification sends the protocol bearer header and revocation sends the token in the form body.
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
const config = {
  clientId: 'q1travel-ozon-manager-v2',
  redirectUri: 'https://dashboard.q1lx.com/oauth-callback.html',
  scopes: ['pricing:preview'],
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
  pathPrefix: '',
}
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
`alarms`. Include `https://connect.q1lx.com/*` and `https://api.q1lx.com/*` in
`host_permissions`, and both HTTPS origins in the extension page CSP's
`connect-src`. For the registered Ozon Web callback, use
`https://dashboard.q1lx.com/*` in `externally_connectable.matches` and set
`redirectUri` to the exact callback page shown above. The callback must be an exact registered HTTPS URL without
query or fragment. HTTP localhost/127.0.0.1 callbacks require
`allowInsecureLoopback: true`; this is for local development only.

The callback page preserves its initial callback URL in memory, removes its
query from browser history, and sends the following closed envelope to its
registered extension ID:

```ts
{ type: 'q1travel.appAuthorization.callback.v1', callbackUrl }
```

Only a top-frame Web sender whose Chrome-reported origin matches `redirectUri` and whose
sender URL matches the callback URL in the message and whose tab ID matches the persisted owned tab is
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

## Optional background authorization context

Both background runtimes accept `authorizationContextPort?: AuthorizationContextPort`.
Import this type and `AuthorizationSourceMetadata` from the background subpath.
The consumer implements:

```ts
interface AuthorizationContextPort {
  prepare(input: {
    contextsUrl: string; clientId: string; redirectUri: string; state: string; codeChallenge: string;
    sourceTabId?: number;
  }): Promise<{ token: string }>;
  assertCurrent(input: {
    token: string; phase: 'beforeExchange' | 'beforeSessionCommit';
  }): Promise<void>;
}
```

For a store-bound login, the background port sends the registered store constraint,
client ID, redirect URI, state and S256 challenge in a JSON POST to the supplied
`contextsUrl` on `authOrigin`. Use plain fetch with `credentials: 'omit'`,
`redirect: 'error'` and no bearer header. The port validates the contexts
response and returns its opaque authorization context token to the SDK.

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
still contains exactly `protocol`, `requestId`, and `action`; the SDK keeps credential handling in the background runtime.
