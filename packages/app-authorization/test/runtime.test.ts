import { describe, expect, it, vi } from 'vitest'
import type { AuthSession } from '../src/core/types.js'
import { createAuthFacadeWithDependencies } from '../src/extension/facade.js'
import { createAuthRuntime } from '../src/extension/index.js'
import { createAuthRuntimeWithDependencies } from '../src/extension/runtime.js'
import {
  SESSION_STORAGE_KEY,
  TRANSACTION_STORAGE_KEY,
} from '../src/extension/storage.js'
import {
  MemorySessionStorage,
  createChromePort,
  jsonResponse,
} from './helpers/fakes.js'

const redirectUri =
  'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/callback'
const config = {
  clientId: 'extension-client',
  redirectUri,
  scopes: ['orders:read'],
  apiOrigin: 'https://api.example.com',
  pathPrefix: '/api',
} as const
const token = 't'.repeat(43)

describe('background auth runtime', () => {
  it('deduplicates concurrent login and exchanges an exact form request', async () => {
    const { chrome, storage } = createChromePort()
    let release!: (callback: string) => void
    const launcher = vi.fn<(authorizationUrl: string) => Promise<string>>(
      () => new Promise<string>((resolve) => { release = resolve }),
    )
    const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = new URLSearchParams(String(init?.body))
      expect(Object.fromEntries(body)).toEqual({
        grant_type: 'authorization_code',
        client_id: 'extension-client',
        code: 'c'.repeat(43),
        redirect_uri: redirectUri,
        code_verifier: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
      })
      return jsonResponse({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 28_800,
        scope: 'orders:read',
      })
    })
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch,
      launcher: { launch: launcher },
      now: () => 1_000,
    })

    const first = runtime.login()
    const second = runtime.login()
    await vi.waitFor(() => expect(launcher).toHaveBeenCalledOnce())
    const authorizationUrl = new URL(launcher.mock.calls[0][0])
    release(
      `${redirectUri}?code=${'c'.repeat(43)}&state=${authorizationUrl.searchParams.get('state')}`,
    )

    await expect(first).resolves.toEqual({
      status: 'authenticated',
      expiresAt: new Date(28_801_000).toISOString(),
      scopes: ['orders:read'],
    })
    await expect(second).resolves.toEqual(await first)
    expect(fetch).toHaveBeenCalledOnce()
    expect(storage.accessLevel).toBe('TRUSTED_CONTEXTS')
  })

  it('treats an expired stored token as signed out without sending a request', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(2_000).toISOString(),
      scopes: ['orders:read'],
    }
    const fetch = vi.fn()
    const runtime = createAuthRuntimeWithDependencies(config, { chrome, fetch, now: () => 2_000 })

    await expect(runtime.getSession()).resolves.toEqual({ status: 'signed-out' })
    await expect(
      runtime.authorizedFetch('https://api.example.com/orders'),
    ).rejects.toMatchObject({ code: 'session_expired' })
    expect(fetch).not.toHaveBeenCalled()
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('rejects requests outside apiOrigin and caller Authorization headers', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const fetch = vi.fn()
    const runtime = createAuthRuntimeWithDependencies(config, { chrome, fetch, now: () => 1_000 })

    await expect(
      runtime.authorizedFetch('https://outside.example.com/orders'),
    ).rejects.toMatchObject({ code: 'request_not_allowed' })
    await expect(
      runtime.authorizedFetch('https://api.example.com/orders', {
        headers: { Authorization: 'Bearer caller-token' },
      }),
    ).rejects.toMatchObject({ code: 'request_not_allowed' })
    await expect(
      runtime.authorizedFetch(new Request('https://api.example.com/orders', {
        headers: { Authorization: 'Bearer request-token' },
      })),
    ).rejects.toMatchObject({ code: 'request_not_allowed' })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('uses the validated URL snapshot when the caller mutates a URL object', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const fetch = vi.fn<(input: RequestInfo | URL) => Promise<Response>>(
      async () => new Response(null, { status: 200 }),
    )
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch,
      now: () => 1_000,
    })
    const target = new URL('https://api.example.com/orders')

    const request = runtime.authorizedFetch(target)
    target.href = 'https://outside.example.com/collect'
    await request

    expect(String(fetch.mock.calls[0]?.[0])).toBe('https://api.example.com/orders')
  })

  it('clears and publishes signed-out after an invalid token response', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const fetch = vi.fn(async () =>
      jsonResponse({ error: 'invalid_token', error_description: 'expired' }, 401),
    )
    const runtime = createAuthRuntimeWithDependencies(config, { chrome, fetch, now: () => 1_000 })
    const changes: unknown[] = []
    runtime.onSessionChange((session) => changes.push(session))

    const response = await runtime.authorizedFetch('https://api.example.com/orders')

    expect(response.status).toBe(401)
    expect(changes).toEqual([{ status: 'signed-out' }])
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('clears local state even when revocation cannot be confirmed', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => { throw new TypeError('offline') }),
      now: () => 1_000,
    })

    await expect(runtime.logout()).rejects.toMatchObject({
      code: 'revocation_unconfirmed',
    })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('restores a valid background session after service worker restart', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(),
      now: () => 1_000,
    })

    await expect(runtime.getSession()).resolves.toEqual({
      status: 'authenticated',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    })
  })

  it('verifies a restored session when the public background runtime starts', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: '2099-01-02T00:00:00.000Z',
      scopes: ['orders:read'],
    }
    const fetch = vi.fn(async () => jsonResponse({
      active: true,
      expires_at: '2099-01-01T00:00:00.000Z',
      scope: ['orders:read'],
    }))
    vi.stubGlobal('chrome', chrome)
    vi.stubGlobal('fetch', fetch)
    try {
      createAuthRuntime(config)
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('blocks background, authorized fetch, and UI reads until startup revocation settles', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: '2099-01-02T00:00:00.000Z',
      scopes: ['orders:read'],
    }
    let resolveVerification!: (response: Response) => void
    const fetch = vi.fn((input: RequestInfo | URL) => {
      if (String(input).endsWith('/session')) {
        return new Promise<Response>((resolve) => { resolveVerification = resolve })
      }
      return Promise.resolve(new Response(null, { status: 200 }))
    })
    vi.stubGlobal('chrome', chrome)
    vi.stubGlobal('fetch', fetch)
    try {
      const runtime = createAuthRuntime(config)
      const facade = createAuthFacadeWithDependencies({ chrome })
      const backgroundRead = runtime.getSession()
      const uiRead = facade.getSession()
      const authorizedRequest = runtime.authorizedFetch('https://api.example.com/orders')
      const settled = vi.fn()
      void backgroundRead.then(settled, settled)
      void uiRead.then(settled, settled)
      void authorizedRequest.then(settled, settled)

      await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
      await Promise.resolve()
      expect(settled).not.toHaveBeenCalled()

      resolveVerification(jsonResponse({
        error: 'invalid_token',
        error_description: 'Access token is invalid or expired.',
      }, 401))

      await expect(runtime.ready()).resolves.toBeUndefined()
      await expect(backgroundRead).resolves.toEqual({ status: 'signed-out' })
      await expect(uiRead).resolves.toEqual({ status: 'signed-out' })
      await expect(authorizedRequest).rejects.toMatchObject({ code: 'session_expired' })
      expect(fetch).toHaveBeenCalledOnce()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('settles startup after a network failure and preserves an unexpired local session', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: '2099-01-02T00:00:00.000Z',
      scopes: ['orders:read'],
    }
    vi.stubGlobal('chrome', chrome)
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline') }))
    try {
      const runtime = createAuthRuntime(config)

      await expect(runtime.ready()).rejects.toMatchObject({
        code: 'network_unavailable',
        retryable: true,
      })
      await expect(runtime.getSession()).resolves.toEqual({
        status: 'authenticated',
        expiresAt: '2099-01-02T00:00:00.000Z',
        scopes: ['orders:read'],
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('times out startup verification and then preserves an unexpired local session', async () => {
    vi.useFakeTimers()
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: '2099-01-02T00:00:00.000Z',
      scopes: ['orders:read'],
    }
    vi.stubGlobal('chrome', chrome)
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
    try {
      const runtime = createAuthRuntime(config)
      const readiness = expect(runtime.ready()).rejects.toMatchObject({
        code: 'network_unavailable',
      })
      const session = runtime.getSession()

      await vi.advanceTimersByTimeAsync(10_000)

      await readiness
      await expect(session).resolves.toMatchObject({ status: 'authenticated' })
    } finally {
      vi.useRealTimers()
      vi.unstubAllGlobals()
    }
  })

  it('clears an interrupted PKCE transaction during worker recovery', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[TRANSACTION_STORAGE_KEY] = {
      state: 's'.repeat(43),
      codeVerifier: 'v'.repeat(43),
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(),
      now: () => 1_000,
    })

    await runtime.getSession()

    expect(storage.values).not.toHaveProperty(TRANSACTION_STORAGE_KEY)
  })

  it('clears a remotely invalid session during verification', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => jsonResponse({
        error: 'invalid_token',
        error_description: 'Access token is invalid or expired.',
      }, 401)),
      now: () => 1_000,
    })

    await expect(runtime.verifySession()).resolves.toEqual({ status: 'signed-out' })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('treats an already expired remote session as signed out', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => jsonResponse({
        active: true,
        expires_at: new Date(999).toISOString(),
        scope: ['orders:read'],
      })),
      now: () => 1_000,
    })

    await expect(runtime.verifySession()).resolves.toEqual({ status: 'signed-out' })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('publishes session metadata changed by remote verification', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => jsonResponse({
        active: true,
        expires_at: new Date(40_000).toISOString(),
        scope: ['orders:read'],
      })),
      now: () => 1_000,
    })
    const changes: AuthSession[] = []
    runtime.onSessionChange((session) => changes.push(session))

    const verified = await runtime.verifySession()

    expect(changes).toEqual([verified])
  })

  it('does not clear the session after a forbidden API response', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => new Response(null, { status: 403 })),
      now: () => 1_000,
    })

    await expect(
      runtime.authorizedFetch('https://api.example.com/orders'),
    ).resolves.toMatchObject({ status: 403 })
    await expect(runtime.getSession()).resolves.toMatchObject({
      status: 'authenticated',
    })
  })

  it('classifies a rejected identity prompt as user cancellation', async () => {
    const { chrome } = createChromePort()
    chrome.identity.launchWebAuthFlow = async () => {
      throw new Error('The user did not approve access.')
    }
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(),
    })

    await expect(runtime.login()).rejects.toMatchObject({
      code: 'interaction_cancelled',
    })
  })

  it('does not retain rejected credential material in errors or logs', async () => {
    const { chrome } = createChromePort()
    const rejectedCredential = 'rejected-credential-material'
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      launcher: {
        async launch(url) {
          const state = new URL(url).searchParams.get('state')
          return `${redirectUri}?code=${'c'.repeat(43)}&state=${state}`
        },
      },
      fetch: vi.fn(async () => jsonResponse({
        error: 'invalid_grant',
        error_description: rejectedCredential,
      }, 400)),
    })

    const error = await runtime.login().catch((reason: unknown) => reason)
    expect(error).toMatchObject({ code: 'oauth_invalid_grant' })
    expect(JSON.stringify({
      name: (error as Error).name,
      message: (error as Error).message,
      code: (error as { code: string }).code,
    })).not.toContain(rejectedCredential)
    expect(errorLog).not.toHaveBeenCalled()
    errorLog.mockRestore()
  })

  it('fails closed for missing configuration and unavailable secure storage', async () => {
    const { chrome } = createChromePort()
    expect(() => createAuthRuntimeWithDependencies(
      { ...config, clientId: '' },
      { chrome, fetch: vi.fn() },
    )).toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))

    class UnavailableStorage extends MemorySessionStorage {
      override async setAccessLevel(): Promise<void> {
        throw new Error('unavailable')
      }
    }
    const unavailable = createChromePort(new UnavailableStorage())
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome: unavailable.chrome,
      fetch: vi.fn(),
    })
    await expect(runtime.getSession()).rejects.toMatchObject({
      code: 'storage_unavailable',
    })
  })

  it('sanitizes failures from an injected launcher', async () => {
    const { chrome } = createChromePort()
    const sensitiveDetail = 'callback contained sensitive material'
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(),
      launcher: {
        async launch() {
          throw new Error(sensitiveDetail)
        },
      },
    })

    const error = await runtime.login().catch((reason: unknown) => reason)
    expect(error).toMatchObject({ code: 'interaction_failed' })
    expect((error as Error).message).not.toContain(sensitiveDetail)
  })

  it('prevents an in-flight login from restoring a session after logout', async () => {
    const { chrome, storage } = createChromePort()
    let release!: (callback: string) => void
    let authorizationUrl = ''
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => jsonResponse({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 28_800,
        scope: 'orders:read',
      })),
      launcher: {
        launch(url) {
          authorizationUrl = url
          return new Promise<string>((resolve) => { release = resolve })
        },
      },
      now: () => 1_000,
    })

    const login = runtime.login()
    await vi.waitFor(() => expect(authorizationUrl).not.toBe(''))
    await runtime.logout()
    const state = new URL(authorizationUrl).searchParams.get('state')
    release(`${redirectUri}?code=${'c'.repeat(43)}&state=${state}`)

    await expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await expect(runtime.getSession()).resolves.toEqual({ status: 'signed-out' })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('does not let a throwing session subscriber fail a completed login', async () => {
    const { chrome } = createChromePort()
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => jsonResponse({
        access_token: token,
        token_type: 'Bearer',
        expires_in: 28_800,
        scope: 'orders:read',
      })),
      launcher: {
        async launch(url) {
          const state = new URL(url).searchParams.get('state')
          return `${redirectUri}?code=${'c'.repeat(43)}&state=${state}`
        },
      },
      now: () => 1_000,
    })
    runtime.onSessionChange(() => { throw new Error('consumer failure') })

    await expect(runtime.login()).resolves.toMatchObject({ status: 'authenticated' })
  })

  it('does not restore an old session when verification completes after logout', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    let resolveVerification!: (response: Response) => void
    const fetch = vi.fn((input: RequestInfo | URL) => {
      if (String(input).endsWith('/session')) {
        return new Promise<Response>((resolve) => { resolveVerification = resolve })
      }
      return Promise.resolve(new Response(null, { status: 200 }))
    })
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch,
      now: () => 1_000,
    })

    const verification = runtime.verifySession()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    await runtime.logout()
    resolveVerification(jsonResponse({
      active: true,
      expires_at: new Date(40_000).toISOString(),
      scope: ['orders:read'],
    }))

    await expect(verification).resolves.toEqual({ status: 'signed-out' })
    await expect(runtime.getSession()).resolves.toEqual({ status: 'signed-out' })
  })

  it('does not let an old logout clear a later successful login', async () => {
    const { chrome, storage } = createChromePort()
    const newToken = 'n'.repeat(43)
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    let resolveRevocation!: () => void
    const fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/revoke')) {
        return new Promise<Response>((resolve) => {
          resolveRevocation = () => resolve(new Response(null, { status: 200 }))
        })
      }
      return Promise.resolve(jsonResponse({
        access_token: newToken,
        token_type: 'Bearer',
        expires_in: 28_800,
        scope: 'orders:read',
      }))
    })
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch,
      launcher: {
        async launch(url) {
          const state = new URL(url).searchParams.get('state')
          return `${redirectUri}?code=${'c'.repeat(43)}&state=${state}`
        },
      },
      now: () => 1_000,
    })
    const changes: AuthSession[] = []
    runtime.onSessionChange((session) => changes.push(session))

    const logout = runtime.logout()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    await runtime.login()
    resolveRevocation()
    await logout

    expect(storage.values[SESSION_STORAGE_KEY]).toMatchObject({ accessToken: newToken })
    expect(changes.at(-1)).toMatchObject({ status: 'authenticated' })
  })

  it('clears the old session when a later login is cancelled', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    let resolveRevocation!: () => void
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(() => new Promise<Response>((resolve) => {
        resolveRevocation = () => resolve(new Response(null, { status: 200 }))
      })),
      launcher: {
        async launch() {
          throw new Error('The user did not approve access.')
        },
      },
      now: () => 1_000,
    })

    const logout = runtime.logout()
    await vi.waitFor(() => expect(resolveRevocation).toBeTypeOf('function'))
    await expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    resolveRevocation()

    await expect(logout).resolves.toEqual({ status: 'signed-out' })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('clears locally without a second storage read during logout', async () => {
    class SecondReadFailureStorage extends MemorySessionStorage {
      reads = 0

      override async get(keys: string | readonly string[] | null) {
        this.reads += 1
        if (this.reads > 1) throw new Error('second read failed')
        return super.get(keys)
      }
    }
    const storage = new SecondReadFailureStorage()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const { chrome } = createChromePort(storage)
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => new Response(null, { status: 200 })),
      now: () => 1_000,
    })

    await expect(runtime.logout()).resolves.toEqual({ status: 'signed-out' })
    expect(storage.reads).toBe(1)
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('does not let an old verification failure clear a newer login', async () => {
    const { chrome, storage } = createChromePort()
    const newToken = 'n'.repeat(43)
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    let resolveVerification!: (response: Response) => void
    const fetch = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/session')) {
        return new Promise<Response>((resolve) => { resolveVerification = resolve })
      }
      if (url.endsWith('/token')) {
        return Promise.resolve(jsonResponse({
          access_token: newToken,
          token_type: 'Bearer',
          expires_in: 28_800,
          scope: 'orders:read',
        }))
      }
      return Promise.resolve(new Response(null, { status: 200 }))
    })
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch,
      launcher: {
        async launch(url) {
          const state = new URL(url).searchParams.get('state')
          return `${redirectUri}?code=${'c'.repeat(43)}&state=${state}`
        },
      },
      now: () => 1_000,
    })

    const verification = runtime.verifySession()
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    await runtime.login()
    resolveVerification(jsonResponse({
      error: 'invalid_token',
      error_description: 'Access token is invalid or expired.',
    }, 401))

    await expect(verification).resolves.toMatchObject({ status: 'authenticated' })
    await expect(runtime.getSession()).resolves.toMatchObject({
      status: 'authenticated',
      scopes: ['orders:read'],
    })
    expect(storage.values[SESSION_STORAGE_KEY]).toMatchObject({ accessToken: newToken })
  })

  it('still attempts local cleanup when reading storage fails during logout', async () => {
    class ReadFailureStorage extends MemorySessionStorage {
      override async get(): Promise<Record<string, unknown>> {
        throw new Error('read failed')
      }
    }
    const storage = new ReadFailureStorage()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    const { chrome } = createChromePort(storage)
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(),
      now: () => 1_000,
    })

    await expect(runtime.logout()).rejects.toMatchObject({
      code: 'storage_unavailable',
    })
    expect(storage.values).not.toHaveProperty(SESSION_STORAGE_KEY)
  })

  it('returns a successful streaming response without waiting for its body to close', async () => {
    const { chrome, storage } = createChromePort()
    storage.values[SESSION_STORAGE_KEY] = {
      accessToken: token,
      tokenType: 'Bearer',
      expiresAt: new Date(50_000).toISOString(),
      scopes: ['orders:read'],
    }
    let controller!: ReadableStreamDefaultController<Uint8Array>
    const stream = new ReadableStream<Uint8Array>({
      start(value) {
        controller = value
        value.enqueue(new TextEncoder().encode('data: ready\n\n'))
      },
    })
    const runtime = createAuthRuntimeWithDependencies(config, {
      chrome,
      fetch: vi.fn(async () => new Response(stream, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })),
      now: () => 1_000,
    })

    const pending = runtime.authorizedFetch('https://api.example.com/events')
    const result = await Promise.race([
      pending,
      new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 25)),
    ])
    controller.close()

    expect(result).toBeInstanceOf(Response)
    await pending
  })
})
