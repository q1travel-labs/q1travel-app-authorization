import { afterEach, describe, expect, it, vi } from 'vitest'
import { resolveAuthConfig } from '../src/core/config.js'
import { createAdjacentTabAuthRuntimeWithDependencies, TAB_AUTH_CALLBACK } from '../src/extension/tabAuthRuntime.js'
import type { AuthTab, ExternalCallbackListener } from '../src/extension/tabAuthPorts.js'
import { createChromePort, jsonResponse, MemorySessionStorage } from './helpers/fakes.js'

const redirectUri = 'https://web.example.test/oauth-callback.html'
const config = { clientId: 'client-v2', redirectUri, scopes: ['orders:read'], apiOrigin: 'https://api.example.test' }
const key = 'q1travel.appAuthorization.tabTransaction.v1'
const alarmName = 'q1travel.appAuthorization.tabTimeout.v1'
const token = 't'.repeat(43)

const harness = (storage = new MemorySessionStorage()) => {
  let currentTime = 1_000
  const base = createChromePort(storage)
  const external = new Set<ExternalCallbackListener>()
  const removed = new Set<(id: number) => void>()
  const alarms = new Set<(alarm: { name: string }) => void>()
  const tabs = new Map<number, AuthTab>([[7, { id: 7, windowId: 9, index: 3, active: false }]])
  const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 28_800, scope: 'orders:read' }))
  const chrome = {
    storage: base.chrome.storage,
    runtime: { ...base.chrome.runtime, onMessageExternal: {
      addListener: (listener: ExternalCallbackListener) => { external.add(listener) },
      removeListener: (listener: ExternalCallbackListener) => { external.delete(listener) },
    } },
    tabs: {
      create: vi.fn(async (input: { openerTabId: number }) => {
        const tab = { id: 11, windowId: 9, index: 4, active: true, openerTabId: input.openerTabId }
        tabs.set(11, tab)
        return tab
      }),
      get: vi.fn(async (id: number) => { const tab = tabs.get(id); if (!tab) throw new Error('missing'); return tab }),
      query: vi.fn(async () => [...tabs.values()]),
      update: vi.fn(async (_id: number, _options: { url?: string; active?: true }) => undefined),
      remove: vi.fn(async (id: number) => {
        tabs.delete(id)
        for (const listener of removed) listener(id)
      }),
      onRemoved: { addListener: (listener: (id: number) => void) => { removed.add(listener) } },
    },
    windows: { get: vi.fn(async () => ({ focused: true })), update: vi.fn(async () => undefined) },
    alarms: {
      create: vi.fn(async () => undefined), clear: vi.fn(async () => true),
      onAlarm: { addListener: (listener: (alarm: { name: string }) => void) => { alarms.add(listener) } },
    },
  }
  const create = () => createAdjacentTabAuthRuntimeWithDependencies(config, {
    chrome, fetch, now: () => currentTime, getSourceTab: async () => tabs.get(7)!, timeoutMs: 1_000,
  })
  const dispatch = async (url?: string, senderOverrides: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => {
    const transaction = storage.values[key] as { state: string } | undefined
    const callbackUrl = url ?? `${redirectUri}?code=${'c'.repeat(43)}&state=${transaction?.state}`
    const sender = { origin: 'https://web.example.test', url: callbackUrl, frameId: 0, tab: { id: 11 }, ...senderOverrides }
    for (const listener of external) {
      let resolve!: (response: unknown) => void
      const response = new Promise<unknown>((accept) => { resolve = accept })
      const result = listener({ type: TAB_AUTH_CALLBACK, callbackUrl, ...extra }, sender, resolve)
      if (result === true) return await response
    }
    return undefined
  }
  const started = async () => vi.waitFor(() => expect(chrome.tabs.update).toHaveBeenCalledWith(11, { url: expect.stringContaining('/authorize?') }))
  const restart = () => { external.clear(); removed.clear(); alarms.clear(); base.listeners.clear(); return create() }
  return { chrome, fetch, storage, tabs, create, dispatch, started, restart, external, removed, alarms, setTime: (value: number) => { currentTime = value } }
}

afterEach(() => vi.useRealTimers())

describe('persistent adjacent-tab authorization', () => {
  it('installs wake-up listeners synchronously and creates an adjacent owned tab', async () => {
    const h = harness()
    const runtime = h.create()
    expect(h.chrome).not.toHaveProperty('identity')
    expect(h.external.size).toBe(1)
    expect(h.alarms.size).toBe(1)
    expect(h.removed.size).toBe(1)
    const login = runtime.login()
    await h.started()
    expect(h.chrome.tabs.create).toHaveBeenCalledWith({ url: 'about:blank', windowId: 9, index: 4, openerTabId: 7, active: true })
    expect(await h.dispatch()).toEqual({ ok: true })
    await expect(login).resolves.toMatchObject({ status: 'authenticated' })
    expect(h.fetch).toHaveBeenCalledOnce()
    const body = new URLSearchParams(String(h.fetch.mock.calls[0]?.[1]?.body))
    expect(body.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(h.chrome.tabs.remove).toHaveBeenCalledWith(11)
    expect(h.storage.values[key]).toBeUndefined()
    expect(JSON.stringify(await h.dispatch())).not.toContain(token)
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  it.each([
    { origin: 'https://evil.example.test' }, { url: redirectUri + '?extra=1' },
    { frameId: 2 }, { tab: { id: 7 } }, { id: 'another-extension' },
  ])('rejects untrusted callback sender %j without spending the code', async (sender) => {
    const h = harness()
    const runtime = h.create()
    const login = runtime.login()
    await h.started()
    const result = await h.dispatch(undefined, sender)
    if (sender.tab) expect(result).toMatchObject({ ok: false })
    else expect(result).toBeUndefined()
    expect(h.fetch).not.toHaveBeenCalled()
    await h.dispatch()
    await login
  })

  it('rejects wrong state and extra callback fields without killing the valid transaction', async () => {
    const h = harness()
    const login = h.create().login()
    await h.started()
    expect(await h.dispatch(`${redirectUri}?code=${'c'.repeat(43)}&state=${'x'.repeat(43)}`)).toMatchObject({ ok: false, error: { code: 'state_mismatch' } })
    expect(await h.dispatch(undefined, {}, { unexpected: true })).toBeUndefined()
    expect(h.fetch).not.toHaveBeenCalled()
    await h.dispatch()
    await login
  })

  it('deduplicates concurrent login and callback replay', async () => {
    const h = harness()
    const runtime = h.create()
    const a = runtime.login()
    const b = runtime.login()
    expect(a).toBe(b)
    await h.started()
    const replies = await Promise.all([h.dispatch(), h.dispatch()])
    expect(replies).toEqual([expect.objectContaining({ ok: true }), expect.objectContaining({ ok: false })])
    await a
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  it('completes authorization after worker restart using only the persisted PKCE transaction', async () => {
    const h = harness()
    void h.create().login()
    await h.started()
    const original = structuredClone(h.storage.values[key]) as { codeVerifier: string }
    const runtime = h.restart()
    expect(h.external.size).toBe(1)
    await runtime.ready()
    expect(await h.dispatch()).toEqual({ ok: true })
    expect(await runtime.getSession()).toMatchObject({ status: 'authenticated' })
    const body = new URLSearchParams(String(h.fetch.mock.calls[0]?.[1]?.body))
    expect(body.get('code_verifier')).toBe(original.codeVerifier)
    expect(h.chrome.tabs.create).toHaveBeenCalledOnce()
  })

  it('never replays an exchange claimed before worker termination', async () => {
    const h = harness()
    void h.create().login()
    await h.started()
    h.storage.values[key] = { ...(h.storage.values[key] as object), phase: 'exchanging' }
    await h.restart().ready()
    expect(h.storage.values[key]).toBeUndefined()
    expect(await h.dispatch()).toMatchObject({ ok: false })
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('cancels when the user closes the exact auth tab', async () => {
    const h = harness()
    const login = h.create().login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    await h.chrome.tabs.remove(11)
    await rejection
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('uses a wake-up alarm to expire authorization', async () => {
    const h = harness()
    const login = h.create().login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    h.setTime(2_001)
    for (const listener of h.alarms) listener({ name: alarmName })
    await rejection
    expect(h.chrome.tabs.remove).toHaveBeenCalledWith(11)
  })

  it('does not steal focus if the auth tab is inactive', async () => {
    const h = harness()
    const login = h.create().login()
    await h.started()
    h.tabs.set(11, { ...h.tabs.get(11)!, active: false })
    await h.dispatch()
    await login
    expect(h.chrome.tabs.update).not.toHaveBeenCalledWith(7, { active: true })
  })

  it('does not close a tab that no longer proves its opener ownership', async () => {
    const h = harness()
    void h.create().login()
    await h.started()
    h.tabs.set(11, { ...h.tabs.get(11)!, openerTabId: 99 })
    await h.restart().ready()
    expect(h.chrome.tabs.remove).not.toHaveBeenCalled()
    expect(h.storage.values[key]).toBeUndefined()
  })

  it('terminates a denied authorization without exchanging a code', async () => {
    const h = harness()
    const login = h.create().login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'authorization_denied' })
    await h.started()
    const transaction = h.storage.values[key] as { state: string }
    expect(await h.dispatch(`${redirectUri}?error=access_denied&state=${transaction.state}`)).toMatchObject({ ok: false, error: { code: 'authorization_denied' } })
    await rejection
    expect(h.storage.values[key]).toBeUndefined()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('fences a deferred token response before session commit when logout wins', async () => {
    const h = harness()
    const runtime = h.create()
    const login = runtime.login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    let release!: (response: Response) => void
    h.fetch.mockImplementationOnce(() => new Promise<Response>((accept) => { release = accept }))
    const callback = h.dispatch()
    await vi.waitFor(() => expect(h.fetch).toHaveBeenCalledOnce())
    expect(await runtime.logout()).toEqual({ status: 'signed-out' })
    await rejection
    release(jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 28_800, scope: 'orders:read' }))
    expect(await callback).toMatchObject({ ok: false, error: { code: 'interaction_cancelled' } })
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    expect(h.fetch).toHaveBeenCalledTimes(2)
  })

  it('rejects a queued callback when logout starts before its transaction claim', async () => {
    const h = harness()
    const runtime = h.create()
    const login = runtime.login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    const callback = h.dispatch()
    const logout = runtime.logout()
    await logout
    await rejection
    expect(await callback).toMatchObject({ ok: false })
    expect(h.fetch).not.toHaveBeenCalled()
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
  })

  it('cancels a hanging tab create and cleans up the exact late-created tab', async () => {
    const h = harness()
    await h.create().ready()
    vi.useFakeTimers()
    let release!: (tab: AuthTab) => void
    h.chrome.tabs.create.mockImplementationOnce(() => new Promise<AuthTab>((accept) => { release = accept }) as never)
    const runtime = h.create()
    const login = runtime.login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(1_000)
    await rejection
    const tab = { id: 11, windowId: 9, index: 4, active: true, openerTabId: 7 }
    h.tabs.set(11, tab)
    release(tab)
    await vi.advanceTimersByTimeAsync(0)
    expect(h.chrome.tabs.remove).toHaveBeenCalledWith(11)
    expect(h.storage.values[key]).toBeUndefined()
  })


  it('keeps old Chromium redirect validation strict while enabling explicit loopback Web callbacks', () => {
    expect(() => resolveAuthConfig(config)).toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
    const local = { ...config, redirectUri: 'http://localhost:5173/oauth-callback.html' }
    expect(() => resolveAuthConfig(local, true)).toThrowError()
    expect(resolveAuthConfig({ ...local, allowInsecureLoopback: true }, true).redirectUri).toBe(local.redirectUri)
    expect(() => resolveAuthConfig({ ...local, redirectUri: 'http://evil.example.test/callback', allowInsecureLoopback: true }, true)).toThrowError()
  })

  it('expires a persisted transaction on worker restart without spending its code', async () => {
    const h = harness()
    void h.create().login()
    await h.started()
    h.setTime(2_001)
    await h.restart().ready()
    expect(h.chrome.tabs.remove).toHaveBeenCalledWith(11)
    expect(h.storage.values[key]).toBeUndefined()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('fences a deferred exchange immediately when the user closes the authorization tab', async () => {
    const h = harness()
    const runtime = h.create()
    const login = runtime.login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await h.started()
    let release!: (response: Response) => void
    h.fetch.mockImplementationOnce(() => new Promise<Response>((accept) => { release = accept }))
    const callback = h.dispatch()
    await vi.waitFor(() => expect(h.fetch).toHaveBeenCalledOnce())
    await h.chrome.tabs.remove(11)
    await rejection
    release(jsonResponse({ access_token: token, token_type: 'Bearer', expires_in: 28_800, scope: 'orders:read' }))
    expect(await callback).toMatchObject({ ok: false, error: { code: 'interaction_cancelled' } })
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
  })

  it('revokes a partially committed session if owned-tab cleanup fails', async () => {
    const h = harness()
    const runtime = h.create()
    const login = runtime.login()
    const rejection = expect(login).rejects.toMatchObject({ code: 'interaction_failed' })
    await h.started()
    h.chrome.tabs.remove.mockRejectedValueOnce(new Error('cleanup failed'))
    expect(await h.dispatch()).toMatchObject({ ok: false })
    await rejection
    expect(await runtime.getSession()).toEqual({ status: 'signed-out' })
    expect(h.fetch).toHaveBeenCalledTimes(2)
  })

})
