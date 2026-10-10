import { expect, vi } from 'vitest'
import { createAdjacentTabAuthRuntimeWithDependencies, TAB_AUTH_CALLBACK, type AdjacentTabAuthRuntimeDependencies } from '../../src/extension/tabAuthRuntime.js'
import type { AuthTab, ExternalCallbackListener } from '../../src/extension/tabAuthPorts.js'
import { createChromePort, jsonResponse, MemorySessionStorage } from './fakes.js'

const redirectUri = 'https://web.example.test/oauth-callback.html'
const config = { clientId: 'client-v2', redirectUri, scopes: ['orders:read'], apiOrigin: 'https://api.example.test' }
const key = 'q1travel.appAuthorization.tabTransaction.v1'
const contextKey = 'q1travel.appAuthorization.tabTransaction.v2'
const token = 't'.repeat(43)

export const contextTabHarness = (storage = new MemorySessionStorage()) => {
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
  const create = (overrides: Partial<AdjacentTabAuthRuntimeDependencies> = {}) => createAdjacentTabAuthRuntimeWithDependencies(config, {
    chrome, fetch, now: () => currentTime, getSourceTab: async () => tabs.get(7)!, timeoutMs: 1_000, ...overrides,
  })
  const dispatch = async (url?: string, senderOverrides: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => {
    const transaction = (storage.values[contextKey] ?? storage.values[key]) as { state: string } | undefined
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
  const restart = (overrides: Partial<AdjacentTabAuthRuntimeDependencies> = {}) => { external.clear(); removed.clear(); alarms.clear(); base.listeners.clear(); return create(overrides) }
  return { listeners: base.listeners, chrome, fetch, storage, tabs, create, dispatch, started, restart, external, removed, alarms, setTime: (value: number) => { currentTime = value } }
}

