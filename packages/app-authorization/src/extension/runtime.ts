import { resolveAuthConfig, type AuthConfig } from '../core/config.js'
import { validateAuthorizationCallback } from '../core/callback.js'
import { createAuthorizationRequest, type CryptoPort } from '../core/pkce.js'
import { AppAuthorizationError, AuthErrorCode, type AuthSession } from '../core/types.js'
import { assertAuthorizationContext, prepareAuthorizationContext, type AuthorizationContextPort } from './authorizationContextPort.js'
import { createProofKey, createSignedFetch } from './dpop.js'
import { isInvalidToken, oauthClient, resourceRequest, type FetchPort } from './http.js'
import type { AuthFlowLauncher, AuthRuntimeChromePort, ChromePort } from './ports.js'
import { createSessions, publicSession } from './sessions.js'
import { SessionRepository, sessionNamespace, type StoredTransaction, type TokenGrant } from './storage.js'
import { browserCryptoPort } from './webCrypto.js'

export interface AuthRuntime {
  ready(): Promise<void>
  login(): Promise<AuthSession>
  restore(): Promise<AuthSession>
  refresh(): Promise<AuthSession>
  logout(): Promise<AuthSession>
  getIdentity(): Promise<AuthSession>
  onSessionChange(callback: (session: AuthSession) => void): () => void
  authorizedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
}

export interface AuthRuntimeOptions {
  readonly authorizationContextPort?: AuthorizationContextPort
  readonly launcher?: AuthFlowLauncher
}

export interface AuthRuntimeDependencies extends AuthRuntimeOptions {
  readonly chrome: AuthRuntimeChromePort & { readonly identity?: ChromePort['identity'] }
  readonly fetch: FetchPort
  readonly crypto?: CryptoPort
  readonly now?: () => number
  readonly database?: IDBFactory
  readonly locks?: LockManager
  readonly verifyOnStartup?: boolean
  readonly allowWebRedirect?: boolean
  readonly installResumeHandler?: (handler: (callback: string, transaction: StoredTransaction) => Promise<AuthSession>, cancel: () => Promise<void>) => void
}

export function requireServiceWorker() {
  const scope = globalThis as typeof globalThis & { ServiceWorkerGlobalScope?: typeof EventTarget }
  if (!scope.ServiceWorkerGlobalScope || !(scope instanceof scope.ServiceWorkerGlobalScope)) {
    throw new AppAuthorizationError(AuthErrorCode.runtimeUnavailable)
  }
}

export function createAuthRuntime(input: AuthConfig, options: AuthRuntimeOptions = {}): AuthRuntime {
  requireServiceWorker()
  const chrome = (globalThis as typeof globalThis & { chrome: ChromePort }).chrome
  return createAuthRuntimeWithDependencies(input, { ...options, chrome, fetch: globalThis.fetch.bind(globalThis), verifyOnStartup: true })
}

function interrupted() { return new AppAuthorizationError(AuthErrorCode.interactionCancelled) }

// Consumer observation hooks may hang after their tab closes. Cancellation must settle independently.
async function untilCancelled<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  let abort!: () => void
  const cancellation = new Promise<never>((_, reject) => { abort = () => reject(interrupted()) })
  signal.addEventListener('abort', abort, { once: true })
  if (signal.aborted) abort()
  try { return await Promise.race([operation, cancellation]) }
  finally { signal.removeEventListener('abort', abort) }
}

export function createAuthRuntimeWithDependencies(input: AuthConfig, options: AuthRuntimeDependencies): AuthRuntime {
  const config = resolveAuthConfig(input, options.allowWebRedirect)
  if (options.chrome.runtime.id !== config.installationId) throw new AppAuthorizationError(AuthErrorCode.configurationInvalid)
  const now = options.now ?? Date.now
  const signed = createSignedFetch(options.fetch, now)
  const oauth = oauthClient(config, signed, now)
  const database = options.database ?? globalThis.indexedDB
  const locks = options.locks ?? globalThis.navigator?.locks
  if (!database || !locks) throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
  const repository = new SessionRepository(sessionNamespace(config), database)
  const subscribers = new Set<(session: AuthSession) => void>()
  const sessions = createSessions(repository, locks, oauth, now, (session) => {
    for (const subscriber of subscribers) {
      try { subscriber(structuredClone(session)) } catch { /* Observer errors cannot roll back a transaction. */ }
    }
  })

  const context = options.authorizationContextPort
  let attempt = new AbortController()
  const newAttempt = () => {
    attempt.abort()
    attempt = new AbortController()
    return attempt.signal
  }
  const check = (signal: AbortSignal) => { if (signal.aborted) throw interrupted() }

  let hookInProgress = false
  let resumed: Promise<AuthSession> | undefined
  async function assertContext(transaction: StoredTransaction, phase: 'beforeExchange' | 'beforeSessionCommit', signal: AbortSignal) {
    if (!context) return
    hookInProgress = true
    try { await untilCancelled(assertAuthorizationContext(context, transaction.authorizationContextToken, phase), signal) }
    finally { hookInProgress = false }
  }

  async function complete(callback: string, transaction: StoredTransaction, signal: AbortSignal) {
    const code = validateAuthorizationCallback(callback, config.redirectUri, transaction.state, config.issuer)
    const key = await createProofKey()
    check(signal)
    let grant: TokenGrant | undefined
    try {
      await assertContext(transaction, 'beforeExchange', signal)
      check(signal)
      grant = await oauth.exchange(code, transaction.codeVerifier, key)
      check(signal)
      const identity = await oauth.identity(grant, key)
      check(signal)
      await assertContext(transaction, 'beforeSessionCommit', signal)
      const stored = { ...grant, identity, key, version: crypto.randomUUID() }
      await sessions.commit(stored, () => check(signal))
      return publicSession(stored)
    } catch (error) {
      if (grant) {
        try { await oauth.revoke(grant, key) }
        catch { throw new AppAuthorizationError(AuthErrorCode.revocationUnconfirmed) }
      }
      throw error
    }
  }

  async function launch(url: string) {
    try {
      const callback = options.launcher ? await options.launcher.launch(url)
        : await options.chrome.identity?.launchWebAuthFlow({ url, interactive: true })
      if (!callback) throw interrupted()
      return callback
    } catch (error) {
      if (error instanceof AppAuthorizationError) throw error
      if (error instanceof Error && ['The user did not approve access.', 'User rejected the request.'].includes(error.message)) throw interrupted()
      throw new AppAuthorizationError(AuthErrorCode.interactionFailed)
    }
  }

  const startup = options.verifyOnStartup ? sessions.identity(AbortSignal.timeout(10_000)).then(() => undefined) : Promise.resolve()
  const settled = startup.catch(() => undefined)
  async function login(signal: AbortSignal) {
    await settled
    check(signal)
    await sessions.logout()
    check(signal)
    const prepared = await createAuthorizationRequest(config, options.crypto ?? browserCryptoPort())
    const url = new URL(prepared.authorizationUrl)
    check(signal)
    const token = context && await untilCancelled(prepareAuthorizationContext(context, {
      contextsUrl: config.contextsUrl, clientId: config.clientId, redirectUri: config.redirectUri,
      state: prepared.state, codeChallenge: prepared.codeChallenge,
    }), signal)
    if (token) url.searchParams.set('authorization_context', token)
    check(signal)
    const callback = await untilCancelled(launch(url.href), signal)
    return complete(callback, { ...prepared, authorizationContextToken: token }, signal)
  }

  let pending: Promise<AuthSession> | undefined
  options.installResumeHandler?.((callback, transaction) => {
    resumed = complete(callback, transaction, newAttempt())
    return resumed
  }, async () => {
    const settling = hookInProgress && resumed
    newAttempt()
    if (settling) await settling.catch((error) => {
      if (!(error instanceof AppAuthorizationError && error.code === AuthErrorCode.interactionCancelled)) throw error
    })
  })
  return Object.freeze<AuthRuntime>({
    ready: () => startup,
    login() {
      if (!pending) {
        const operation = login(newAttempt()).finally(() => { if (pending === operation) pending = undefined })
        pending = operation
      }
      return pending
    },
    async restore() { await settled; return publicSession(await sessions.current()) },
    async refresh() { await settled; return publicSession(await sessions.current(true)) },
    async getIdentity() { await settled; return sessions.identity() },
    async logout() { newAttempt(); pending = undefined; return sessions.logout() },
    onSessionChange(callback) { subscribers.add(callback); return () => subscribers.delete(callback) },
    async authorizedFetch(input, init = {}) {
      const request = resourceRequest(input, init, config.apiOrigin)
      await settled
      const stored = await sessions.current()
      if (!stored) throw new AppAuthorizationError(AuthErrorCode.sessionExpired)
      const response = await signed('rs', stored.key, request, stored.accessToken)
      if (await isInvalidToken(response)) await sessions.discard(stored.version)
      return response
    },
  })
}
