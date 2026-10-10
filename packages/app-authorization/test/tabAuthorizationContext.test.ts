import { afterEach, describe, expect, it, vi } from 'vitest'
import { AUTH_PROTOCOL } from '../src/extension/protocol.js'
import type { AuthorizationContextPort } from '../src/extension/authorizationContextPort.js'
import type { AuthorizationSourceMetadata, RuntimeMessageSender } from '../src/extension/ports.js'
import { contextTabHarness } from './helpers/contextTabFakes.js'

const token = 'a'.repeat(42) + 'A'
const key = 'q1travel.appAuthorization.tabTransaction.v2'
const legacyKey = 'q1travel.appAuthorization.tabTransaction.v1'
const port = () => ({ prepare: vi.fn(async () => ({ token })), assertCurrent: vi.fn<AuthorizationContextPort['assertCurrent']>(async () => undefined) })
const sender = (tabId?: number): RuntimeMessageSender => ({ id: 'abcdefghijklmnopabcdefghijklmnop', url: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/ui.html?ignored=1', origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop', frameId: tabId ? 3 : 0, documentId: 'ui-document', ...(tabId ? { tab: { id: tabId } } : {}) })
const dispatchLogin = async (h: ReturnType<typeof contextTabHarness>, source = sender()) => {
  for (const listener of h.listeners) {
    let resolve!: (value: unknown) => void
    const response = new Promise<unknown>((accept) => { resolve = accept })
    if (listener({ protocol: AUTH_PROTOCOL, requestId: 'request', action: 'login' }, source, resolve) === true) return await response
  }
  return undefined
}
afterEach(() => vi.useRealTimers())

describe('adjacent backend context and trusted source', () => {
  it('binds iframe metadata and the original source to PKCE and callback even when active differs', async () => {
    const h = contextTabHarness()
    const context = port()
    h.tabs.set(8, { id: 8, active: true, index: 5, windowId: 9 })
    const getSourceTab = vi.fn(async (source?: AuthorizationSourceMetadata) => h.tabs.get(source?.tabId ?? 8)!)
    h.create({ authorizationContextPort: context, getSourceTab })
    const login = dispatchLogin(h, sender(7))
    await h.started()
    expect(getSourceTab).toHaveBeenCalledExactlyOnceWith({ tabId: 7, frameId: 3, documentId: 'ui-document' })
    expect(context.prepare).toHaveBeenCalledWith({ sourceTabId: 7, clientId: 'client-v2', redirectUri: 'https://web.example.test/oauth-callback.html', state: expect.any(String), codeChallenge: expect.any(String) })
    expect(Object.keys(h.storage.values[key] as object).sort()).toEqual(['state', 'codeVerifier', 'config', 'sourceTabId', 'sourceWindowId', 'authTabId', 'expiresAt', 'phase', 'authorizationContextToken'].sort())
    expect(h.storage.values[legacyKey]).toBeUndefined()
    expect(await h.dispatch()).toEqual({ ok: true })
    expect(await login).toMatchObject({ ok: true })
    expect(context.assertCurrent.mock.calls).toEqual([[{ token, phase: 'beforeExchange' }], [{ token, phase: 'beforeSessionCommit' }]])
    expect(getSourceTab).toHaveBeenCalledOnce()
  })

  it('captures popup active source once and rejects a competing iframe operation without cross-binding', async () => {
    const h = contextTabHarness()
    const context = port()
    let active = 7
    const getSourceTab = vi.fn(async () => h.tabs.get(active)!)
    h.create({ authorizationContextPort: context, getSourceTab })
    const login = dispatchLogin(h)
    await h.started()
    active = 99
    expect(await dispatchLogin(h, sender(99))).toMatchObject({ ok: false, error: { code: 'interaction_cancelled' } })
    expect((h.storage.values[key] as { sourceTabId: number }).sourceTabId).toBe(7)
    await h.dispatch()
    expect(await login).toMatchObject({ ok: true })
    expect(getSourceTab).toHaveBeenCalledOnce()
  })

  it.each([{ id: 'other' }, { origin: 'https://untrusted.test' }, { tab: {} }])('rejects unsafe sender before resolving source %j', async (override) => {
    const h = contextTabHarness()
    const context = port()
    const getSourceTab = vi.fn(async () => h.tabs.get(7)!)
    h.create({ authorizationContextPort: context, getSourceTab })
    expect(await dispatchLogin(h, { ...sender(7), ...override })).toBeUndefined()
    expect(getSourceTab).not.toHaveBeenCalled()
    expect(context.prepare).not.toHaveBeenCalled()
  })

  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('fails closed at %s through the shared completion path', async (phase) => {
    const h = contextTabHarness()
    const context = port()
    context.assertCurrent.mockImplementation(async (input) => { if (input.phase === phase) throw new Error('private adapter detail') })
    const runtime = h.create({ authorizationContextPort: context })
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_failed' })
    await h.started()
    expect(await h.dispatch()).toMatchObject({ ok: false, error: { code: 'interaction_failed' } })
    await rejection
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    expect(h.fetch).toHaveBeenCalledTimes(phase === 'beforeExchange' ? 0 : 2)
    expect(h.storage.values[key]).toBeUndefined()
  })

  it('fails a restored v2 context when consumer associations were lost', async () => {
    const h = contextTabHarness()
    void h.create({ authorizationContextPort: port() }).login()
    await h.started()
    const context = port()
    context.assertCurrent.mockRejectedValue(new Error('missing association'))
    const runtime = h.restart({ authorizationContextPort: context })
    await runtime.ready()
    expect(await h.dispatch()).toMatchObject({ ok: false })
    expect(h.fetch).not.toHaveBeenCalled()
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    expect(h.storage.values[key]).toBeUndefined()
  })

  it.each([true, false])('clears incompatible pending versions without exchange, strict=%s', async (strict) => {
    const h = contextTabHarness()
    void h.create(strict ? {} : { authorizationContextPort: port() }).login()
    await h.started()
    const runtime = h.restart(strict ? { authorizationContextPort: port() } : {})
    await runtime.ready()
    expect(h.storage.values[key]).toBeUndefined()
    expect(h.storage.values[legacyKey]).toBeUndefined()
    expect(await h.dispatch()).toMatchObject({ ok: false })
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('clears malformed v2 records and allows a new explicit attempt', async () => {
    const h = contextTabHarness()
    h.storage.values[key] = { state: 's'.repeat(43), authorizationContextToken: token, injected: true }
    const runtime = h.create({ authorizationContextPort: port() })
    await runtime.ready()
    expect(h.storage.values[key]).toBeUndefined()
    const login = runtime.login()
    await h.started()
    await h.dispatch()
    await expect(login).resolves.toMatchObject({ status: 'authenticated' })
  })

  it('cancels a deferred prepare on logout without opening any auth tab', async () => {
    const h = contextTabHarness()
    const context = port()
    let release!: (value: { token: string }) => void
    context.prepare.mockImplementation(() => new Promise((resolve) => { release = resolve }))
    const runtime = h.create({ authorizationContextPort: context })
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.waitFor(() => expect(context.prepare).toHaveBeenCalledOnce())
    const logout = runtime.logout()
    release({ token })
    await logout
    await rejection
    expect(h.chrome.tabs.create).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('source capture and delayed context fences', () => {
  it('captures popup source before awaiting startup verification', async () => {
    const h = contextTabHarness()
    h.storage.values['q1travel.appAuthorization.session.v1'] = { accessToken: 'o'.repeat(43), tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00.000Z', scopes: ['orders:read'] }
    let active = 7
    h.tabs.set(8, { id: 8, active: true, index: 5, windowId: 9 })
    let release!: (value: Response) => void
    h.fetch.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const context = port()
    const getSourceTab = vi.fn(async () => h.tabs.get(active)!)
    h.create({ authorizationContextPort: context, getSourceTab, verifyOnStartup: true })
    const login = dispatchLogin(h)
    expect(getSourceTab).toHaveBeenCalledOnce()
    active = 8
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    release(new Response(JSON.stringify({ active: true, expires_at: '2099-01-01T00:00:00.000Z', scope: ['orders:read'] }), { headers: { 'content-type': 'application/json' } }))
    await h.started()
    expect((h.storage.values[key] as { sourceTabId: number }).sourceTabId).toBe(7)
    await h.dispatch()
    expect(await login).toMatchObject({ ok: true })
    expect(getSourceTab).toHaveBeenCalledOnce()
  })

  it('rejects a second iframe source while the first source resolver is pending', async () => {
    const h = contextTabHarness()
    let release!: (value: NonNullable<ReturnType<typeof h.tabs.get>>) => void
    const getSourceTab = vi.fn(async (_source?: AuthorizationSourceMetadata) => new Promise<NonNullable<ReturnType<typeof h.tabs.get>>>((resolve) => { release = resolve }))
    h.create({ authorizationContextPort: port(), getSourceTab })
    const login = dispatchLogin(h, sender(7))
    expect(await dispatchLogin(h, sender(8))).toMatchObject({ ok: false })
    release(h.tabs.get(7)!)
    await h.started()
    expect((h.storage.values[key] as { sourceTabId: number }).sourceTabId).toBe(7)
    await h.dispatch()
    expect(await login).toMatchObject({ ok: true })
    expect(getSourceTab).toHaveBeenCalledOnce()
  })

  it('fences a late post-exchange hook after the auth tab is closed', async () => {
    const h = contextTabHarness()
    const context = port()
    let release!: () => void
    context.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === 'beforeSessionCommit') await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create({ authorizationContextPort: context })
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    const callback = h.dispatch()
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    await h.chrome.tabs.remove(11)
    await rejection
    release()
    expect(await callback).toMatchObject({ ok: false })
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    expect(h.fetch).toHaveBeenCalledTimes(2)
  })

  it('expires a hanging prepare without creating an authorization tab', async () => {
    const h = contextTabHarness()
    const context = port()
    context.prepare.mockImplementation(() => new Promise(() => undefined))
    const runtime = h.create({ authorizationContextPort: context, crypto: { randomBytes: () => new Uint8Array(32), sha256: async () => new Uint8Array(32) } })
    await runtime.ready()
    vi.useFakeTimers()
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.advanceTimersByTimeAsync(0)
    expect(context.prepare).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(1_001)
    await rejection
    expect(h.chrome.tabs.create).not.toHaveBeenCalled()
  })
})

describe('original iframe source enforcement', () => {
  it('rejects a resolver returning the active tab instead of the iframe original tab', async () => {
    const h = contextTabHarness()
    h.tabs.set(8, { id: 8, active: true, index: 5, windowId: 9 })
    const context = port()
    h.create({ authorizationContextPort: context, getSourceTab: async () => h.tabs.get(8)! })
    expect(await dispatchLogin(h, sender(7))).toMatchObject({ ok: false, error: { code: 'interaction_failed' } })
    expect(context.prepare).not.toHaveBeenCalled()
    expect(h.chrome.tabs.create).not.toHaveBeenCalled()
  })
})

describe('strict terminal hook failure clears prior sessions', () => {
  it.each([
    ['beforeExchange', 'timeout'], ['beforeSessionCommit', 'timeout'],
    ['beforeExchange', 'close'], ['beforeSessionCommit', 'close'],
  ] as const)('settles hanging %s after %s before releasing the hook', async (phase, terminal) => {
    const h = contextTabHarness()
    h.storage.values['q1travel.appAuthorization.session.v1'] = { accessToken: 'o'.repeat(43), tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00.000Z', scopes: ['orders:read'] }
    const context = port()
    let release!: () => void
    context.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === phase) await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create({ authorizationContextPort: context, timeoutMs: 200 })
    const changes = vi.fn()
    runtime.onSessionChange(changes)
    const login = runtime.login().catch((error: unknown) => error)
    let callback: Promise<unknown> | undefined
    try {
      await h.started()
      callback = h.dispatch()
      await vi.waitFor(() => expect(release).toBeTypeOf('function'))
      if (terminal === 'close') await h.chrome.tabs.remove(11)
      expect(await login).toMatchObject({ code: 'interaction_cancelled' })
      expect(await callback).toMatchObject({ ok: false, error: { code: 'interaction_cancelled' } })
      expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
      await expect(runtime.authorizedFetch('https://api.example.test/orders')).rejects.toMatchObject({ code: 'session_expired' })
      expect(h.storage.values[key]).toBeUndefined()
      const paths = h.fetch.mock.calls.map(([url]) => new URL(String(url)).pathname.split('/').at(-1))
      expect(paths).toEqual(phase === 'beforeSessionCommit' ? ['token', 'revoke'] : [])
      release()
      await Promise.resolve()
      expect(changes.mock.calls.some(([session]) => session.status === 'authenticated')).toBe(false)
    } finally {
      release?.()
      await callback
      await login
    }
  })

  it.each(['timeout', 'close', 'logout'] as const)('reports unconfirmed acquired-token compensation after %s', async (terminal) => {
    const h = contextTabHarness()
    h.storage.values['q1travel.appAuthorization.session.v1'] = { accessToken: 'o'.repeat(43), tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00.000Z', scopes: ['orders:read'] }
    const implementation = h.fetch.getMockImplementation()!
    h.fetch.mockImplementation(async (url, init) => {
      if (String(url).endsWith('/revoke') && new URLSearchParams(String(init?.body)).get('token') === 't'.repeat(43)) throw new Error('offline')
      return implementation(url, init)
    })
    const context = port()
    let release!: () => void
    context.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === 'beforeSessionCommit') await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create({ authorizationContextPort: context, timeoutMs: 200 })
    const login = runtime.login().catch((error: unknown) => error)
    let callback: Promise<unknown> | undefined
    try {
      await h.started()
      callback = h.dispatch()
      await vi.waitFor(() => expect(release).toBeTypeOf('function'))
      if (terminal === 'close') await h.chrome.tabs.remove(11)
      if (terminal === 'logout') await runtime.logout()
      expect(await login).toMatchObject({ code: 'revocation_unconfirmed' })
      expect(await callback).toMatchObject({ ok: false, error: { code: 'revocation_unconfirmed' } })
      expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
      expect(h.fetch).toHaveBeenCalledTimes(terminal === 'logout' ? 3 : 2)
    } finally {
      release?.()
      await callback
      await login
    }
  })
})

describe('terminal compensation ownership', () => {
  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('preserves a new session after timed-out %s returns late', async (phase) => {
    const h = contextTabHarness()
    h.storage.values['q1travel.appAuthorization.session.v1'] = { accessToken: 'o'.repeat(43), tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00.000Z', scopes: ['orders:read'] }
    const context = port()
    let release!: () => void
    context.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === phase) await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create({ authorizationContextPort: context, timeoutMs: 200 })
    const failed = runtime.login().catch((error: unknown) => error)
    await h.started()
    const oldCallback = h.dispatch()
    expect(await failed).toMatchObject({ code: 'interaction_cancelled' })
    expect(await oldCallback).toMatchObject({ ok: false })
    context.assertCurrent.mockImplementation(async () => undefined)
    h.chrome.tabs.update.mockClear()
    const changes = vi.fn()
    runtime.onSessionChange(changes)
    const login = runtime.login()
    await h.started()
    expect(await h.dispatch()).toEqual({ ok: true })
    await expect(login).resolves.toMatchObject({ status: 'authenticated' })
    const snapshot = structuredClone(h.storage.values['q1travel.appAuthorization.session.v1'])
    release()
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(h.storage.values['q1travel.appAuthorization.session.v1']).toEqual(snapshot)
    expect(changes).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ status: 'authenticated' }))
  })

  it('compensates a cancelled late token response without clearing a newer session', async () => {
    const h = contextTabHarness()
    h.storage.values['q1travel.appAuthorization.session.v1'] = { accessToken: 'o'.repeat(43), tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00.000Z', scopes: ['orders:read'] }
    let release!: (value: Response) => void
    h.fetch.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const runtime = h.create({ authorizationContextPort: port() })
    const failed = runtime.login().catch((error: unknown) => error)
    await h.started()
    const oldCallback = h.dispatch()
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    await h.chrome.tabs.remove(11)
    expect(await failed).toMatchObject({ code: 'interaction_cancelled' })
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    h.chrome.tabs.update.mockClear()
    const login = runtime.login()
    await h.started()
    await h.dispatch()
    await login
    const snapshot = structuredClone(h.storage.values['q1travel.appAuthorization.session.v1'])
    release(new Response(JSON.stringify({ access_token: 'l'.repeat(43), token_type: 'Bearer', expires_in: 28_800, scope: 'orders:read' }), { headers: { 'content-type': 'application/json' } }))
    expect(await oldCallback).toMatchObject({ ok: false })
    expect(h.storage.values['q1travel.appAuthorization.session.v1']).toEqual(snapshot)
    const revoked = h.fetch.mock.calls.filter(([url]) => String(url).endsWith('/revoke')).map(([, init]) => new URLSearchParams(String(init?.body)).get('token'))
    expect(revoked).toEqual(['l'.repeat(43)])
  })
})
