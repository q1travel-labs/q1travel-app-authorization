import { validateAuthorizationCallback } from '../core/callback.js'
import { resolveAuthConfig, type AuthConfig } from '../core/config.js'
import { browserCryptoPort, createAuthorizationRequest, type CryptoPort } from '../core/pkce.js'
import { AppAuthorizationError, AuthErrorCode, type AuthSession } from '../core/types.js'
import { installRuntime } from './listener.js'
import { serializeError } from './protocol.js'
import { createAuthRuntimeWithDependencies, type AuthRuntime } from './runtime.js'
import type { FetchPort } from './http.js'
import type { StoredTransaction } from './storage.js'
import type { AuthTab, ExternalCallbackSender, TabAuthChromePort } from './tabAuthPorts.js'

export const TAB_AUTH_CALLBACK = 'q1travel.appAuthorization.callback.v1'
const KEY = 'q1travel.appAuthorization.tabTransaction.v1'
const ALARM = 'q1travel.appAuthorization.tabTimeout.v1'
const opaque = /^[A-Za-z0-9_-]{43}$/u
const id = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value) && value >= 0
const fail = () => new AppAuthorizationError(AuthErrorCode.interactionFailed)
const cancel = () => new AppAuthorizationError(AuthErrorCode.interactionCancelled)
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

interface TabTransaction extends StoredTransaction {
  readonly config: string
  readonly sourceTabId: number
  readonly sourceWindowId: number
  readonly authTabId: number | null
  readonly expiresAt: number
  readonly phase: 'opening' | 'authorizing' | 'exchanging'
}

export interface AdjacentTabAuthRuntimeOptions {
  readonly chrome: TabAuthChromePort
  readonly getSourceTab: () => Promise<AuthTab>
  readonly timeoutMs?: number
}

export interface AdjacentTabAuthRuntimeDependencies extends AdjacentTabAuthRuntimeOptions {
  readonly fetch: FetchPort
  readonly crypto?: CryptoPort
  readonly now?: () => number
  readonly verifyOnStartup?: boolean
}

export const createAdjacentTabAuthRuntime = (
  config: AuthConfig,
  options: AdjacentTabAuthRuntimeOptions,
): AuthRuntime => createAdjacentTabAuthRuntimeWithDependencies(config, {
  ...options, fetch: globalThis.fetch.bind(globalThis), verifyOnStartup: true,
})

export const createAdjacentTabAuthRuntimeWithDependencies = (
  input: AuthConfig,
  options: AdjacentTabAuthRuntimeDependencies,
): AuthRuntime => {
  const config = resolveAuthConfig(input, true)
  const fingerprint = JSON.stringify(config)
  const timeoutMs = options.timeoutMs ?? 10 * 60 * 1_000
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 10 * 60 * 1_000) {
    throw new AppAuthorizationError(AuthErrorCode.configurationInvalid)
  }
  const { chrome } = options
  const storage = chrome.storage.session
  const now = options.now ?? Date.now
  let cancelResume!: () => void
  let resume!: (callback: string, transaction: StoredTransaction) => Promise<AuthSession>
  const base = createAuthRuntimeWithDependencies(input, {
    ...options, allowWebRedirect: true,
    installResumeHandler: (handler, cancel) => { resume = handler; cancelResume = cancel },
  })
  let tail = Promise.resolve()
  const serial = <T>(operation: () => Promise<T>): Promise<T> => {
    const pending = tail.then(operation)
    tail = pending.then(() => undefined, () => undefined)
    return pending
  }
  const load = async (): Promise<TabTransaction | null> => {
    const value = (await storage.get(KEY))[KEY]
    if (value === undefined) return null
    if (!record(value) || Object.keys(value).length !== 8 ||
      value.config !== fingerprint || !id(value.sourceTabId) || !id(value.sourceWindowId) ||
      (value.authTabId !== null && !id(value.authTabId)) ||
      typeof value.state !== 'string' || !opaque.test(value.state) ||
      typeof value.codeVerifier !== 'string' || !opaque.test(value.codeVerifier) ||
      typeof value.expiresAt !== 'number' || !Number.isFinite(value.expiresAt) ||
      !['opening', 'authorizing', 'exchanging'].includes(String(value.phase))) throw fail()
    return value as unknown as TabTransaction
  }
  const save = async (transaction: TabTransaction) => storage.set({ [KEY]: transaction })
  let waiters: { accept(session: AuthSession): void; reject(error: unknown): void } | null = null
  let loginInFlight: Promise<AuthSession> | null = null
  let generation = 0
  let knownAuthTabId: number | null = null
  let closingTabId: number | null = null
  const cleanup = async (transaction: TabTransaction, restoreFocus: boolean) => {
    if (transaction.authTabId !== null) {
      const tabs = await chrome.tabs.query({})
      const auth = tabs.find((tab) => tab.id === transaction.authTabId)
      if (auth) {
        // Ownership needs the exact recorded ID and the Chrome-maintained opener relation.
        if (auth.openerTabId !== transaction.sourceTabId) throw fail()
        if (restoreFocus && auth.active && auth.windowId === transaction.sourceWindowId) {
          try {
            if ((await chrome.windows.get(auth.windowId)).focused) {
              const source = await chrome.tabs.get(transaction.sourceTabId)
              if (source.windowId === transaction.sourceWindowId) {
                await chrome.tabs.update(transaction.sourceTabId, { active: true })
                await chrome.windows.update(source.windowId, { focused: true })
              }
            }
          } catch { /* A missing source never changes which auth tab may be closed. */ }
        }
        closingTabId = transaction.authTabId
        try { await chrome.tabs.remove(transaction.authTabId) }
        finally { closingTabId = null }
      }
    }
    await chrome.alarms.clear(ALARM)
    await storage.remove(KEY)
    knownAuthTabId = null
  }
  const terminate = async (transaction: TabTransaction, error: unknown) => {
    generation += 1
    cancelResume()
    waiters?.reject(error instanceof AppAuthorizationError ? error : fail())
    waiters = null
    await cleanup(transaction, false)
  }
  const startup = serial(async () => {
    await storage.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
    const transaction = await load()
    if (!transaction) return
    if (transaction.expiresAt <= now() || transaction.phase !== 'authorizing') {
      await cleanup(transaction, false)
      return
    }
    const tab = (await chrome.tabs.query({})).find((candidate) => candidate.id === transaction.authTabId)
    if (!tab || tab.openerTabId !== transaction.sourceTabId) {
      await storage.remove(KEY)
      await chrome.alarms.clear(ALARM)
      return
    }
    knownAuthTabId = transaction.authTabId
    await chrome.alarms.create(ALARM, { when: transaction.expiresAt })
  })
  void startup.catch(() => undefined)
  const trustedSender = (sender: ExternalCallbackSender, callbackUrl: string): boolean =>
    sender.id === undefined && sender.origin === new URL(config.redirectUri).origin &&
    sender.url === callbackUrl && sender.frameId === 0 && id(sender.tab?.id)

  // Register synchronously at construction so Chrome can wake a suspended MV3 worker.
  chrome.runtime.onMessageExternal.addListener((message, sender, respond) => {
    if (!record(message) || Object.keys(message).length !== 2 ||
      message.type !== TAB_AUTH_CALLBACK || typeof message.callbackUrl !== 'string' ||
      message.callbackUrl.length > 2_048 || !trustedSender(sender, message.callbackUrl)) return
    const callbackUrl = message.callbackUrl
    const requestedGeneration = generation
    let claimed: TabTransaction | null = null
    let expectedGeneration = generation
    let committed = false
    void serial(async () => {
      await startup
      const transaction = await load()
      if (requestedGeneration !== generation || !transaction || transaction.phase !== 'authorizing' ||
        transaction.authTabId !== sender.tab?.id || transaction.expiresAt <= now()) throw fail()
      const auth = (await chrome.tabs.query({})).find((tab) => tab.id === transaction.authTabId)
      if (!auth || auth.openerTabId !== transaction.sourceTabId) throw fail()
      try {
        validateAuthorizationCallback(callbackUrl, config.redirectUri, transaction.state)
      } catch (error) {
        if (error instanceof AppAuthorizationError && error.code === AuthErrorCode.authorizationDenied) {
          await terminate(transaction, error)
        }
        throw error
      }
      // Durable claim before spending the code: restart never replays an exchange.
      claimed = { ...transaction, phase: 'exchanging' }
      await save(claimed)
      expectedGeneration = generation
      return transaction
    }).then(async (transaction) => {
      if (expectedGeneration !== generation) throw cancel()
      const session = await bounded(resume(callbackUrl, transaction), transaction.expiresAt)
      committed = true
      await serial(async () => {
        const current = await load()
        if (expectedGeneration !== generation || current?.state !== transaction.state ||
          current.phase !== 'exchanging') throw cancel()
        await cleanup(transaction, true)
        if (expectedGeneration !== generation) throw cancel()
        waiters?.accept(session)
        waiters = null
      })
      respond({ ok: true })
    }).catch(async (error) => {
      if (committed && expectedGeneration === generation) {
        try { await base.logout() } catch { /* Local logout still clears the committed session. */ }
      }
      if (claimed) {
        try {
          await serial(async () => {
            const current = await load()
            if (current && claimed && current.state === claimed.state) await terminate(current, error)
          })
        } catch { error = fail() }
      }
      respond({ ok: false, error: serializeError(error) })
    })
    return true
  })
  chrome.tabs.onRemoved.addListener((tabId) => {
    if (tabId === closingTabId) return
    if (tabId === knownAuthTabId) { generation += 1; cancelResume() }
    void serial(async () => {
      await startup
      const transaction = await load()
      if (transaction?.authTabId === tabId) await terminate(transaction, cancel())
    }).catch(() => undefined)
  })
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== ALARM) return
    void serial(async () => {
      await startup
      const transaction = await load()
      if (transaction && transaction.expiresAt <= now()) await terminate(transaction, cancel())
    }).catch(() => undefined)
  })

  const bounded = async <T>(operation: Promise<T>, expiresAt: number): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeout = new Promise<never>((_accept, reject) => {
      timer = setTimeout(() => reject(cancel()), Math.max(0, Math.min(10_000, expiresAt - now())))
    })
    try { return await Promise.race([operation, timeout]) }
    finally { if (timer !== undefined) clearTimeout(timer) }
  }
  const startLogin = async (): Promise<AuthSession> => {
    await startup
    await base.ready()
    const result = new Promise<AuthSession>((accept, reject) => { waiters = { accept, reject } })
    void result.catch(() => undefined)
    void serial(async () => {
      const existing = await load()
      if (existing) {
        if (existing.expiresAt <= now()) await cleanup(existing, false)
        else if (existing.phase === 'authorizing' && existing.authTabId !== null) {
          const tab = await chrome.tabs.get(existing.authTabId)
          if (tab.openerTabId !== existing.sourceTabId) throw fail()
          await chrome.tabs.update(existing.authTabId, { active: true })
          await chrome.windows.update(tab.windowId, { focused: true })
          return
        } else throw fail()
      }
      const source = await bounded(options.getSourceTab(), now() + timeoutMs)
      if (!id(source.id) || !id(source.windowId) || !id(source.index)) throw fail()
      const prepared = await createAuthorizationRequest(config, options.crypto ?? browserCryptoPort())
      const transaction: TabTransaction = {
        state: prepared.state, codeVerifier: prepared.codeVerifier, config: fingerprint,
        sourceTabId: source.id, sourceWindowId: source.windowId, authTabId: null,
        expiresAt: now() + timeoutMs, phase: 'opening',
      }
      await save(transaction)
      await chrome.alarms.create(ALARM, { when: transaction.expiresAt })
      let bound = transaction
      try {
        let creationExpired = false
        const creation = chrome.tabs.create({ url: 'about:blank', windowId: source.windowId,
          index: source.index + 1, openerTabId: source.id, active: true })
        void creation.then(async (tab) => {
          if (creationExpired && id(tab.id) && tab.openerTabId === source.id) await chrome.tabs.remove(tab.id)
        }).catch(() => undefined)
        let tab: AuthTab
        try { tab = await bounded(creation, transaction.expiresAt) }
        catch (error) { creationExpired = true; throw error }
        if (!id(tab.id)) throw fail()
        bound = { ...transaction, authTabId: tab.id, phase: 'authorizing' }
        await save(bound)
        knownAuthTabId = tab.id
        if (tab.windowId !== source.windowId || tab.openerTabId !== source.id) throw fail()
        await bounded(chrome.tabs.update(tab.id, { url: prepared.authorizationUrl }), transaction.expiresAt)
      } catch (error) {
        await cleanup(bound, false)
        throw error
      }
    }).catch(async (error) => {
      const sanitized = error instanceof AppAuthorizationError ? error : fail()
      waiters?.reject(sanitized)
      waiters = null
      try {
        const transaction = await load()
        if (transaction) await terminate(transaction, sanitized)
      } catch { /* Retain a failed cleanup record so a future worker cannot replay it. */ }
    })
    return result
  }
  const runtime: AuthRuntime = {
    ...base,
    ready: async () => { await startup; await base.ready() },
    login() {
      if (loginInFlight) return loginInFlight
      const pending = startLogin().finally(() => { if (loginInFlight === pending) loginInFlight = null })
      loginInFlight = pending
      return pending
    },
    async logout() {
      generation += 1
      // Fence token exchange immediately, before waiting behind the callback queue.
      const logout = base.logout()
      await serial(async () => {
        await startup
        const transaction = await load()
        if (transaction) await terminate(transaction, cancel())
      })
      return logout
    },
  }
  return installRuntime(Object.freeze(runtime), chrome)
}
