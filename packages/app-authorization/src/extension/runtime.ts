import { validateAuthorizationCallback } from '../core/callback.js'
import {
  browserCryptoPort,
  createAuthorizationRequest,
  type CryptoPort,
} from '../core/pkce.js'
import {
  AppAuthorizationError,
  AuthErrorCode,
  resolveAuthConfig,
  type AuthConfig,
  type AuthSession,
  type ResolvedAuthConfig,
} from '../core/types.js'
import {
  exchangeAuthorizationCode,
  revokeSession,
  verifyRemoteSession,
  type FetchPort,
} from './http.js'
import type { AuthFlowLauncher, ChromePort } from './ports.js'
import { SessionRepository, type StoredSession } from './storage.js'

export interface AuthRuntime {
  ready(): Promise<void>
  login(): Promise<AuthSession>
  logout(): Promise<AuthSession>
  getSession(): Promise<AuthSession>
  verifySession(): Promise<AuthSession>
  onSessionChange(callback: (session: AuthSession) => void): () => void
  authorizedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>
}

export interface AuthRuntimeOptions {
  readonly launcher?: AuthFlowLauncher
}

export interface AuthRuntimeDependencies extends AuthRuntimeOptions {
  readonly chrome: ChromePort
  readonly fetch: FetchPort
  readonly crypto?: CryptoPort
  readonly now?: () => number
  readonly verifyOnStartup?: boolean
}

const STARTUP_VERIFICATION_TIMEOUT_MS = 10_000

const getChrome = (): ChromePort => {
  const value = (globalThis as typeof globalThis & { chrome?: ChromePort }).chrome
  if (!value) throw new AppAuthorizationError(AuthErrorCode.configurationInvalid)
  return value
}

const asPublicSession = (stored: StoredSession): AuthSession => ({
  status: 'authenticated',
  expiresAt: stored.expiresAt,
  scopes: [...stored.scopes],
})

const isCancellation = (error: unknown): boolean =>
  error instanceof Error &&
  (error.message === 'The user did not approve access.' ||
    error.message === 'User rejected the request.')

const createSerialExecutor = () => {
  let tail = Promise.resolve()
  return async <Value>(operation: () => Promise<Value>): Promise<Value> => {
    const previous = tail
    let release!: () => void
    tail = new Promise<void>((resolve) => { release = resolve })
    await previous.catch(() => undefined)
    try {
      return await operation()
    } finally {
      release()
    }
  }
}

export const createAuthRuntime = (
  inputConfig: AuthConfig,
  options: AuthRuntimeOptions = {},
): AuthRuntime => createAuthRuntimeWithDependencies(inputConfig, {
  chrome: getChrome(),
  fetch: globalThis.fetch.bind(globalThis),
  ...options,
  verifyOnStartup: true,
})

export const createAuthRuntimeWithDependencies = (
  inputConfig: AuthConfig,
  options: AuthRuntimeDependencies,
): AuthRuntime => {
  const config: ResolvedAuthConfig = resolveAuthConfig(inputConfig)
  const chrome = options.chrome
  const fetch = options.fetch
  const crypto = options.crypto ?? browserCryptoPort()
  const now = options.now ?? Date.now
  const launcher: AuthFlowLauncher = options.launcher ?? {
    async launch(authorizationUrl: string) {
      const callback = await chrome.identity.launchWebAuthFlow({
        url: authorizationUrl,
        interactive: true,
      })
      if (typeof callback !== 'string') {
        throw new AppAuthorizationError(AuthErrorCode.interactionCancelled)
      }
      return callback
    },
  }
  const repository = new SessionRepository(chrome.storage.session)
  const startupReady = repository.ready.then(() => repository.clearTransaction())
  void startupReady.catch(() => undefined)
  const subscribers = new Set<(session: AuthSession) => void>()
  const mutateSession = createSerialExecutor()
  let loginInFlight: Promise<AuthSession> | null = null
  let sessionGeneration = 0
  let latestLogin: { readonly generation: number; readonly stored: StoredSession } | null = null
  let startupVerification: Promise<AuthSession> | null = null
  let startupVerificationSettled = true

  const publish = (session: AuthSession) => {
    for (const subscriber of subscribers) {
      try {
        subscriber(structuredClone(session))
      } catch {
        // A consumer callback cannot roll back a completed session transition.
      }
    }
  }

  const launchAuthorization = async (authorizationUrl: string): Promise<string> => {
    try {
      return await launcher.launch(authorizationUrl)
    } catch (error) {
      if (error instanceof AppAuthorizationError) throw error
      throw new AppAuthorizationError(
        isCancellation(error)
          ? AuthErrorCode.interactionCancelled
          : AuthErrorCode.interactionFailed,
      )
    }
  }

  const current = async (): Promise<{ stored: StoredSession | null; session: AuthSession }> => {
    await startupReady
    const result = await mutateSession(async () => {
      const stored = await repository.read()
      if (!stored) return { stored: null, expired: false }
      if (Date.parse(stored.expiresAt) <= now()) {
        await repository.clearSession()
        if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
        return { stored: null, expired: true }
      }
      return { stored, expired: false }
    })
    if (!result.stored) {
      const session = { status: 'signed-out' } as const
      if (result.expired) publish(session)
      return { stored: null, session }
    }
    return { stored: result.stored, session: asPublicSession(result.stored) }
  }

  const performLogin = async (expectedGeneration: number): Promise<AuthSession> => {
    await startupReady
    const prepared = await createAuthorizationRequest(
      {
        authorizeUrl: config.authorizeUrl,
        clientId: config.clientId,
        redirectUri: config.redirectUri,
        scopes: config.scopes,
      },
      crypto,
    )
    await repository.writeTransaction({
      state: prepared.state,
      codeVerifier: prepared.codeVerifier,
    })
    try {
      const callback = await launchAuthorization(prepared.authorizationUrl)
      const code = validateAuthorizationCallback(
        callback,
        config.redirectUri,
        prepared.state,
      )
      const stored = await exchangeAuthorizationCode(
        fetch,
        config,
        code,
        prepared.codeVerifier,
        now(),
      )
      if (sessionGeneration !== expectedGeneration) {
        await revokeSession(fetch, config, stored.accessToken).catch(() => undefined)
        throw new AppAuthorizationError(AuthErrorCode.interactionCancelled)
      }
      const committed = await mutateSession(async () => {
        if (sessionGeneration !== expectedGeneration) return false
        await repository.write(stored)
        if (sessionGeneration === expectedGeneration) {
          latestLogin = { generation: expectedGeneration, stored }
          return true
        }
        await repository.clearSession()
        if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
        return false
      })
      if (!committed || sessionGeneration !== expectedGeneration) {
        await revokeSession(fetch, config, stored.accessToken).catch(() => undefined)
        throw new AppAuthorizationError(AuthErrorCode.interactionCancelled)
      }
      const session = asPublicSession(stored)
      publish(session)
      return session
    } finally {
      await repository.clearTransaction()
    }
  }

  const login = (): Promise<AuthSession> => {
    if (loginInFlight) return loginInFlight
    sessionGeneration += 1
    const operation = performLogin(sessionGeneration)
    const tracked = operation.finally(() => {
      if (loginInFlight === tracked) loginInFlight = null
    })
    loginInFlight = tracked
    return tracked
  }

  const verifySession = async (
    shouldCommit: () => boolean = () => true,
    signal?: AbortSignal,
  ): Promise<AuthSession> => {
    const expectedGeneration = sessionGeneration
    const { stored, session } = await current()
    if (!stored) return session
    if (sessionGeneration !== expectedGeneration) return (await current()).session
    try {
      const verified = await verifyRemoteSession(fetch, config, stored.accessToken, signal)
      if (!shouldCommit()) return (await current()).session
      const expiresAt = new Date(
        Math.min(Date.parse(stored.expiresAt), Date.parse(verified.expiresAt)),
      ).toISOString()
      const updated = { ...stored, expiresAt, scopes: [...verified.scopes] }
      const metadataChanged =
        updated.expiresAt !== stored.expiresAt ||
        updated.scopes.length !== stored.scopes.length ||
        updated.scopes.some((scope, index) => scope !== stored.scopes[index])
      const result = await mutateSession(async () => {
        const latest = await repository.read()
        if (
          !shouldCommit() ||
          sessionGeneration !== expectedGeneration ||
          latest?.accessToken !== stored.accessToken
        ) {
          return {
            session: latest ? asPublicSession(latest) : { status: 'signed-out' } as const,
            cleared: false,
            changed: false,
          }
        }
        if (Date.parse(expiresAt) <= now()) {
          await repository.clearSession()
          if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
          return {
            session: { status: 'signed-out' } as const,
            cleared: true,
            changed: false,
          }
        }
        await repository.write(updated)
        if (latestLogin?.stored.accessToken === stored.accessToken) {
          latestLogin = { ...latestLogin, stored: updated }
        }
        if (!shouldCommit() || sessionGeneration !== expectedGeneration) {
          await repository.clearSession()
          if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
          return {
            session: { status: 'signed-out' } as const,
            cleared: true,
            changed: false,
          }
        }
        return {
          session: asPublicSession(updated),
          cleared: false,
          changed: metadataChanged,
        }
      })
      if (result.cleared || result.changed) publish(result.session)
      return result.session
    } catch (error) {
      if (
        error instanceof AppAuthorizationError &&
        error.code === AuthErrorCode.invalidToken
      ) {
        if (!shouldCommit()) return (await current()).session
        const result = await mutateSession(async () => {
          const latest = await repository.read()
          if (
            !shouldCommit() ||
            sessionGeneration !== expectedGeneration ||
            latest?.accessToken !== stored.accessToken
          ) {
            return {
              session: latest ? asPublicSession(latest) : { status: 'signed-out' } as const,
              cleared: false,
            }
          }
          await repository.clearSession()
          if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
          return { session: { status: 'signed-out' } as const, cleared: true }
        })
        if (result.cleared) publish(result.session)
        return result.session
      }
      throw error
    }
  }

  const waitForStartupVerification = async (): Promise<void> => {
    if (startupVerification) await startupVerification.catch(() => undefined)
  }

  const runtime: AuthRuntime = {
    async ready() {
      await startupReady
      if (startupVerification) await startupVerification.then(() => undefined)
    },
    login,
    async logout() {
      const expectedGeneration = ++sessionGeneration
      let stored: StoredSession | null = null
      let readFailure: unknown
      try {
        stored = (await current()).stored
      } catch (error) {
        readFailure = error
      }
      let revocationFailed = false
      try {
        if (stored) await revokeSession(fetch, config, stored.accessToken)
      } catch {
        revocationFailed = true
      }
      const cleanup = await mutateSession(async () => {
        if (latestLogin && latestLogin.generation > expectedGeneration) {
          return {
            session: asPublicSession(latestLogin.stored),
            cleared: false,
          }
        }
        await repository.clear()
        latestLogin = null
        return { session: { status: 'signed-out' } as const, cleared: true }
      })
      if (cleanup.cleared) {
        publish(cleanup.session)
      }
      if (readFailure) throw readFailure
      if (revocationFailed) {
        throw new AppAuthorizationError(AuthErrorCode.revocationUnconfirmed)
      }
      return cleanup.session
    },
    async getSession() {
      await waitForStartupVerification()
      return (await current()).session
    },
    async verifySession() {
      if (startupVerification && !startupVerificationSettled) return startupVerification
      return verifySession()
    },
    onSessionChange(callback) {
      subscribers.add(callback)
      return () => subscribers.delete(callback)
    },
    async authorizedFetch(input, init = {}) {
      let url: URL
      try {
        url = input instanceof URL
          ? new URL(input.toString())
          : typeof input === 'string'
            ? new URL(input)
            : new URL(input.url)
      } catch {
        throw new AppAuthorizationError(AuthErrorCode.requestNotAllowed)
      }
      if (
        url.origin !== config.apiOrigin ||
        url.username !== '' ||
        url.password !== '' ||
        url.protocol !== new URL(config.apiOrigin).protocol
      ) {
        throw new AppAuthorizationError(AuthErrorCode.requestNotAllowed)
      }
      const inputHeaders = input instanceof Request ? input.headers : undefined
      const headers = new Headers(inputHeaders)
      if (init.headers) {
        for (const [name, value] of new Headers(init.headers)) headers.set(name, value)
      }
      if (headers.has('authorization')) {
        throw new AppAuthorizationError(AuthErrorCode.requestNotAllowed)
      }
      await waitForStartupVerification()
      const { stored } = await current()
      if (!stored) throw new AppAuthorizationError(AuthErrorCode.sessionExpired)
      headers.set('authorization', `Bearer ${stored.accessToken}`)
      let response: Response
      try {
        const target = input instanceof Request ? input : url.toString()
        response = await fetch(target, { ...init, headers, credentials: 'omit' })
      } catch {
        throw new AppAuthorizationError(AuthErrorCode.networkUnavailable)
      }
      let invalidToken = response.status === 401
      if (
        !invalidToken &&
        response.status >= 400 &&
        response.headers.get('content-type')?.includes('application/json')
      ) {
        try {
          const body = await response.clone().json()
          invalidToken = Boolean(
            body && typeof body === 'object' &&
            (body as Record<string, unknown>).error === 'invalid_token',
          )
        } catch {
          invalidToken = false
        }
      }
      if (invalidToken) {
        const cleared = await mutateSession(async () => {
          const latest = await repository.read()
          if (latest?.accessToken !== stored.accessToken) return false
          await repository.clearSession()
          if (latestLogin?.stored.accessToken === stored.accessToken) latestLogin = null
          return true
        })
        if (cleared) publish({ status: 'signed-out' })
      }
      return response
    },
  }

  if (options.verifyOnStartup) {
    let acceptResult = true
    const controller = new AbortController()
    startupVerificationSettled = false
    const verification = verifySession(() => acceptResult, controller.signal)
    let timeout: ReturnType<typeof setTimeout> | undefined
    const timedOut = new Promise<never>((_resolve, reject) => {
      timeout = setTimeout(() => {
        acceptResult = false
        controller.abort()
        reject(new AppAuthorizationError(AuthErrorCode.networkUnavailable))
      }, STARTUP_VERIFICATION_TIMEOUT_MS)
    })
    startupVerification = Promise.race([verification, timedOut]).finally(() => {
      acceptResult = false
      startupVerificationSettled = true
      if (timeout !== undefined) clearTimeout(timeout)
    })
    void startupVerification.catch(() => undefined)
  }

  return Object.freeze(runtime)
}
