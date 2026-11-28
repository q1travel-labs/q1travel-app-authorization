import { AppAuthorizationError, AuthErrorCode } from '../src/core/types.js'
import { describe, expect, it, vi } from 'vitest'
import { createAuthRuntimeWithDependencies } from '../src/extension/runtime.js'
import { browserPorts, callbackFor, config as registration, grant, inspectFetch, oauthResponse } from './helpers/oauth.js'
import { SessionRepository } from '../src/extension/storage.js'
import { createChromePort } from './helpers/fakes.js'

const config = { ...registration, scopes: ['orders:read'] }
const contextToken = 'a'.repeat(42) + 'A'
const harness = (failure?: 'beforeExchange' | 'beforeSessionCommit') => {
  const h = createChromePort()
  const ports = browserPorts(config)
  const prepare = vi.fn(async (_input: unknown) => ({ token: contextToken }))
  const assertCurrent = vi.fn(async (input: { token: string; phase: string }) => {
    if (input.phase === failure) throw new Error('private adapter detail')
  })
  const fetch = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => oauthResponse(url, config.scopes))
  const launch = vi.fn(async (url: string) => {
    expect(new URL(url).searchParams.get('authorization_context')).toBe(contextToken)
    return callbackFor(url)
  })
  const create = () => createAuthRuntimeWithDependencies(config, { ...ports, chrome: h.chrome, fetch: inspectFetch(fetch),
    launcher: { launch }, authorizationContextPort: { prepare, assertCurrent } })
  return { ...h, ...ports, create, prepare, assertCurrent, fetch, launch }
}

describe('optional backend authorization context', () => {
  it('prepares PKCE context and fences exchange and commit without exposing bearer or verifier', async () => {
    const h = harness()
    await expect(h.create().login()).resolves.toMatchObject({ status: 'authenticated' })
    const url = new URL(h.launch.mock.calls[0][0])
    expect(h.prepare).toHaveBeenCalledWith({ contextsUrl: 'https://connect.example.test/oauth/contexts', clientId: config.clientId, redirectUri: config.redirectUri, state: url.searchParams.get('state'), codeChallenge: url.searchParams.get('code_challenge') })
    expect(h.assertCurrent.mock.calls).toEqual([[{ token: contextToken, phase: 'beforeExchange' }], [{ token: contextToken, phase: 'beforeSessionCommit' }]])
    expect(new URLSearchParams(String(h.fetch.mock.calls[0][1]?.body)).has('authorization_context')).toBe(false)
  })

  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('fails closed at %s and compensates only acquired tokens', async (phase) => {
    const h = harness(phase)
    const runtime = h.create()
    const publish = vi.fn()
    runtime.onSessionChange(publish)
    const error = await runtime.login().catch((value: unknown) => value)
    expect(error).toMatchObject({ code: 'interaction_failed' })
    expect(String(error)).not.toContain('private adapter detail')
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
    expect(publish.mock.calls.some(([session]) => session.status === 'authenticated')).toBe(false)
    expect(h.fetch).toHaveBeenCalledTimes(phase === 'beforeExchange' ? 0 : 3)
    expect(await h.repository.read()).toBeUndefined()
  })

  it.each([null, [], {}, { token: '' }, { token: 'bad handle' }, { token: contextToken, extra: true }, { token: '\n' }])('rejects malformed prepare result without launching', async (value) => {
    const h = harness()
    h.prepare.mockResolvedValueOnce(value as never)
    await expect(h.create().login()).rejects.toMatchObject({ code: 'interaction_failed' })
    expect(h.launch).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('context cancellation and compensation', () => {
  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('fences logout during the %s hook', async (phase) => {
    const h = harness()
    let release!: () => void
    h.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === phase) await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create()
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    await runtime.logout()
    release()
    await rejection
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
    expect(h.fetch).toHaveBeenCalledTimes(phase === 'beforeExchange' ? 0 : 3)
  })

  it('reports unconfirmed compensation without publishing authenticated state', async () => {
    const h = harness('beforeSessionCommit')
    const implementation = h.fetch.getMockImplementation()!
    h.fetch.mockImplementation(async (url, init) => {
      if (String(url).endsWith('/revoke')) throw new Error('offline')
      return implementation(url, init)
    })
    const runtime = h.create()
    const changes = vi.fn()
    runtime.onSessionChange(changes)
    await expect(runtime.login()).rejects.toMatchObject({ code: 'revocation_unconfirmed' })
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
    expect(changes.mock.calls.some(([session]) => session.status === 'authenticated')).toBe(false)
  })

  it.each(['prepare', 'beforeExchange', 'beforeSessionCommit'] as const)('clears an existing local session on %s failure', async (phase) => {
    const h = harness(phase === 'prepare' ? undefined : phase)
    await h.seed()
    if (phase === 'prepare') h.prepare.mockRejectedValueOnce(new Error('private prepare detail'))
    const runtime = h.create()
    await expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_failed' })
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
  })

  it('revokes an acquired token when session persistence fails', async () => {
    const h = harness()
    vi.spyOn(SessionRepository.prototype, 'write').mockRejectedValueOnce(new AppAuthorizationError(AuthErrorCode.storageUnavailable))
    const runtime = h.create()
    await expect(runtime.login()).rejects.toMatchObject({ code: 'storage_unavailable' })
    expect(h.fetch).toHaveBeenCalledTimes(3)
    expect(String(h.fetch.mock.calls[2][0])).toMatch(/\/revoke$/u)
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
  })

  it('never launches after logout cancels a deferred prepare', async () => {
    const h = harness()
    let release!: (value: { token: string }) => void
    h.prepare.mockImplementation(() => new Promise((resolve) => { release = resolve }))
    const runtime = h.create()
    const rejection = expect(runtime.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.waitFor(() => expect(h.prepare).toHaveBeenCalledOnce())
    await runtime.logout()
    release({ token: contextToken })
    await rejection
    expect(h.launch).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('terminal cancellation of hanging context hooks', () => {
  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('settles %s cancellation without waiting for the hook', async (phase) => {
    const h = harness()
    await h.seed()
    let release!: () => void
    h.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === phase) await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create()
    const settled = vi.fn()
    const login = runtime.login().then(settled, settled)
    try {
      await vi.waitFor(() => expect(release).toBeTypeOf('function'))
      await runtime.logout()
      await vi.waitFor(() => expect(settled).toHaveBeenCalledOnce())
      expect(settled).toHaveBeenCalledWith(expect.objectContaining({ code: 'interaction_cancelled' }))
      expect(await runtime.restore()).toEqual({ status: 'signed-out' })
      const revoked = h.fetch.mock.calls.filter(([url]) => String(url).endsWith('/revoke')).map(([, init]) => new URLSearchParams(String(init?.body)).get('token'))
      expect(revoked).toContain('prior-refresh')
      if (phase === 'beforeSessionCommit') expect(revoked).toContain(grant.refresh_token)
    } finally {
      release?.()
      await login
    }
  })
})

describe('cancelled hooks cannot affect a newer login', () => {
  it.each(['beforeExchange', 'beforeSessionCommit'] as const)('keeps a newer committed session after late %s completion', async (phase) => {
    const h = harness()
    await h.seed()
    let release!: () => void
    h.assertCurrent.mockImplementation(async (input) => {
      if (input.phase === phase) await new Promise<void>((resolve) => { release = resolve })
    })
    const runtime = h.create()
    const failed = runtime.login().catch((error: unknown) => error)
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    await runtime.logout()
    expect(await failed).toMatchObject({ code: 'interaction_cancelled' })
    h.assertCurrent.mockImplementation(async () => undefined)
    const changes = vi.fn()
    runtime.onSessionChange(changes)
    await expect(runtime.login()).resolves.toMatchObject({ status: 'authenticated' })
    const snapshot = (await h.repository.read())?.version
    release()
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect((await h.repository.read())?.version).toEqual(snapshot)
    expect(changes).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ status: 'authenticated' }))
  })
})
