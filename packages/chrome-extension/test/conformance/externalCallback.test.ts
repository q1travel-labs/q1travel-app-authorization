import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  SERVER_AUTHORIZATION_CODE_LIFETIME_MS,
  TOKEN_EXCHANGE_TIMEOUT_MS,
  WEB_MESSAGE_TIMEOUT_MS,
  sendExternalCallbackWithTimeout,
  validateExternalCallbackMessage,
} from '../../src/chrome-adapter/externalCallback'
import {
  TRANSACTION_STORAGE_KEY,
  createSessionTransactionRepository,
  type TabTransactionV1,
} from '../../src/chrome-adapter/sessionRepository'
import { createTabCoordinator } from '../../src/chrome-adapter/tabCoordinator'
import {
  AUTHORIZATION_TRANSACTION_ALARM,
  createAuthorizationCoordinator,
  type StoredAuthorizationGrant,
} from '../../src/background-runtime/authorizationCoordinator'
import { BackgroundRuntime } from '../../src/background-runtime/runtime'
import type {
  AuthorizationSnapshotV2,
  CoreCryptoPort,
} from '../../src/core/contracts'

const EXTENSION_ID = 'a'.repeat(32)
const CALLBACK_ORIGIN = 'https://web.example.test'
const CALLBACK_PATH = '/apps/extension-auth/callback/client-v2'
const CALLBACK_URL = `${CALLBACK_ORIGIN}${CALLBACK_PATH}`
const STATE = 's'.repeat(43)
const CODE = 'opaque-code.2026/alpha+beta='
const NOW = Date.parse('2026-08-26T04:01:00.000Z')

const transaction = (
  phase: TabTransactionV1['phase'] = 'authorizing',
): TabTransactionV1 => ({
  version: 1,
  transactionId: 'transaction-id',
  clientId: 'browser-client-v2',
  redirectUri: CALLBACK_URL,
  state: STATE,
  codeVerifier: 'v'.repeat(43),
  sourceTabId: 17,
  sourceWindowId: 9,
  createdAt: '2026-08-26T04:00:00.000Z',
  expiresAt: '2026-08-26T04:10:00.000Z',
  phase,
  authTabId: 31,
}) as TabTransactionV1

const approvedMessage = {
  type: 'q1travel.extensionAuth.callback.v1',
  result: 'approved',
  code: CODE,
  state: STATE,
} as const

const deniedMessage = {
  type: 'q1travel.extensionAuth.callback.v1',
  result: 'denied',
  error: 'access_denied',
  state: STATE,
} as const

const callbackSender = {
  frameId: 0,
  origin: CALLBACK_ORIGIN,
  url: CALLBACK_URL,
  tab: { id: 31, windowId: 9 },
}

const signedOutSnapshot = (
  phase: AuthorizationSnapshotV2['interaction']['phase'] = 'authorizing',
): AuthorizationSnapshotV2 => ({
  profile: { profileId: 'client-v2-development', environment: 'development' },
  runtime: 'ready',
  authorization:
    phase === 'opening' || phase === 'authorizing' || phase === 'exchanging'
      ? { kind: 'authorizing' }
      : { kind: 'signed-out', reason: 'never-authorized' },
  interaction:
    phase === 'idle' ||
    phase === 'opening' ||
    phase === 'authorizing' ||
    phase === 'exchanging'
      ? { phase }
      : { phase, occurredAt: new Date(NOW).toISOString() },
})

const callbackCrypto = (comparisons: Array<readonly [string, string]> = []) =>
  ({
    randomBytes() {
      throw new Error('callback must not request randomness')
    },
    async sha256() {
      throw new Error('callback must not hash')
    },
    timingSafeEqual(left, right) {
      comparisons.push([left, right])
      return left.length === right.length && left === right
    },
  }) satisfies CoreCryptoPort

class SessionArea {
  readonly values = new Map<string, unknown>()
  readonly writes: unknown[] = []
  readonly failAlways = new Set<'get' | 'set' | 'remove'>()
  failNext: 'get' | 'set' | 'remove' | null = null
  getCalls = 0
  getGate: Promise<void> | null = null

  async setAccessLevel(): Promise<void> {}
  async get(key: string): Promise<Record<string, unknown>> {
    this.getCalls += 1
    if (this.getGate !== null) await this.getGate
    if (this.failAlways.has('get') || this.failNext === 'get') {
      this.failNext = null
      throw new Error('controlled session get failure')
    }
    return this.values.has(key)
      ? { [key]: structuredClone(this.values.get(key)) }
      : {}
  }
  async set(values: Record<string, unknown>): Promise<void> {
    if (this.failAlways.has('set') || this.failNext === 'set') {
      this.failNext = null
      throw new Error('controlled session set failure')
    }
    this.writes.push(structuredClone(values[TRANSACTION_STORAGE_KEY]))
    for (const [key, value] of Object.entries(values)) {
      this.values.set(key, structuredClone(value))
    }
  }
  async remove(key: string): Promise<void> {
    if (this.failAlways.has('remove') || this.failNext === 'remove') {
      this.failNext = null
      throw new Error('controlled session remove failure')
    }
    this.values.delete(key)
  }
}

const deferred = () => {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

const createHarness = async ({
  initialGrant = null as StoredAuthorizationGrant | null,
  initialTransaction = true,
  initialSnapshot,
  beginAuthorization,
  exchange,
  authorizationUrl,
}: {
  initialGrant?: StoredAuthorizationGrant | null
  initialTransaction?: boolean
  initialSnapshot?: AuthorizationSnapshotV2
  beginAuthorization?: () => Promise<{
    transactionId: string
    clientId: string
    redirectUri: string
    prepared: {
      state: string
      codeVerifier: string
      authorizeUrl: string
    }
    sourceTabId: number
    sourceWindowId: number
  }>
  exchange?: (input: {
    code: string
    codeVerifier: string
    redirectUri: string
    signal: AbortSignal
  }) => Promise<StoredAuthorizationGrant>
  authorizationUrl?: (active: TabTransactionV1) => Promise<string>
} = {}) => {
  const operationLog: string[] = []
  const failures = new Set<string>()
  const persistentFailures = new Set<string>()
  const shouldFail = (operation: string): boolean =>
    persistentFailures.has(operation) || failures.delete(operation)
  let currentNow = NOW
  const session = new SessionArea()
  const transactions = createSessionTransactionRepository({ session })
  if (initialTransaction) await transactions.save(transaction())
  const tabs = new Map([
    [
      17,
      {
        id: 17,
        windowId: 9,
        active: false,
        url: 'https://seller.example.test/manager',
      },
    ],
    [
      31,
      {
        id: 31,
        windowId: 9,
        active: true,
        url: 'https://sso.example.test/intermediate',
      },
    ],
    [
      44,
      {
        id: 44,
        windowId: 12,
        active: true,
        url: 'https://unrelated.example.test/',
      },
    ],
  ])
  if (!initialTransaction) tabs.delete(31)
  const tabRemovedListeners = new Set<(tabId: number) => void>()
  let senderPortAlive = true
  const chrome = {
    runtime: {
      id: EXTENSION_ID,
      getURL: (path: string) =>
        `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//u, '')}`,
    },
    tabs: {
      async create(input: {
        url: string
        windowId: number
        openerTabId: number
        active: true
      }) {
        operationLog.push('tabs.create')
        if (shouldFail('tabs.create')) {
          throw new Error('tab create failure')
        }
        const created = {
          id: 31,
          windowId: input.windowId,
          active: input.active,
          url: input.url,
        }
        tabs.set(31, created)
        return structuredClone(created)
      },
      async get(tabId: number) {
        operationLog.push(`tabs.get:${tabId}`)
        if (shouldFail('tabs.get')) throw new Error('tab get failure')
        const tab = tabs.get(tabId)
        if (!tab) return null
        return structuredClone(tab)
      },
      async update(tabId: number, input: { url?: string; active?: boolean }) {
        operationLog.push(`tabs.update:${tabId}`)
        if (shouldFail('tabs.update')) {
          throw new Error('tab update failure')
        }
        const tab = tabs.get(tabId)
        if (!tab) throw new Error('tab missing')
        Object.assign(tab, input)
        return structuredClone(tab)
      },
      async remove(tabId: number) {
        operationLog.push(`tabs.remove:${tabId}`)
        if (shouldFail('tabs.remove')) {
          throw new Error('tab remove failure')
        }
        if (!tabs.delete(tabId)) throw new Error('tab missing')
        if (tabId === 31) senderPortAlive = false
        for (const listener of tabRemovedListeners) listener(tabId)
      },
    },
    windows: {
      async get(windowId: number) {
        operationLog.push(`windows.get:${windowId}`)
        if (shouldFail('windows.get')) {
          throw new Error('window get failure')
        }
        return { id: windowId, focused: true }
      },
      async update(windowId: number, _input: { focused: true }) {
        operationLog.push(`windows.update:${windowId}`)
        if (shouldFail('windows.update')) {
          throw new Error('window update failure')
        }
        return { id: windowId, focused: true }
      },
    },
  }
  const tabCoordinator = createTabCoordinator({
    chrome,
    transactions,
    now: () => currentNow,
    authorizationUrl:
      authorizationUrl ??
      (async () => {
        throw new Error('callback must not rebuild authorization URL')
      }),
  })
  let snapshot =
    initialSnapshot ??
    signedOutSnapshot(initialTransaction ? 'authorizing' : 'idle')
  let grant = initialGrant
  let exchangeCalls = 0
  const state = {
    async readSnapshot() {
      operationLog.push('state.readSnapshot')
      if (shouldFail('state.readSnapshot')) {
        throw new Error('snapshot read failure')
      }
      return structuredClone(snapshot)
    },
    async saveSnapshot(value: AuthorizationSnapshotV2) {
      operationLog.push(`state.saveSnapshot:${value.interaction.phase}`)
      if (shouldFail('state.saveSnapshot')) {
        throw new Error('snapshot write failure')
      }
      snapshot = structuredClone(value)
    },
    async readGrant() {
      operationLog.push('state.readGrant')
      if (shouldFail('state.readGrant')) {
        throw new Error('grant read failure')
      }
      return grant === null ? null : structuredClone(grant)
    },
    async saveGrant(value: StoredAuthorizationGrant) {
      operationLog.push('state.saveGrant')
      if (shouldFail('state.saveGrant')) {
        throw new Error('grant write failure')
      }
      grant = structuredClone(value)
    },
  }
  const alarms = new Set(
    initialTransaction ? [AUTHORIZATION_TRANSACTION_ALARM] : [],
  )
  const alarmTimes = new Map<string, number>()
  const alarmPort = {
    async create(name: string, alarm: { when: number }) {
      operationLog.push(`alarms.create:${name}`)
      if (shouldFail('alarms.create')) {
        throw new Error('alarm create failure')
      }
      alarms.add(name)
      alarmTimes.set(name, alarm.when)
    },
    async clear(name: string) {
      operationLog.push(`alarms.clear:${name}`)
      if (shouldFail('alarms.clear')) {
        throw new Error('alarm clear failure')
      }
      alarmTimes.delete(name)
      return alarms.delete(name)
    },
  }
  const exchangedGrant: StoredAuthorizationGrant = {
    accessToken: 'eyJsecret.header.signature',
    expiresAt: '2026-08-26T05:00:00.000Z',
    sessionRevision: 'revision-8',
  }
  const coordinator = createAuthorizationCoordinator({
    transactions,
    tabs: tabCoordinator,
    alarms: alarmPort,
    state,
    crypto: callbackCrypto(),
    callbackOrigin: CALLBACK_ORIGIN,
    callbackPath: CALLBACK_PATH,
    now: () => currentNow,
    beginAuthorization:
      beginAuthorization ??
      (async () => {
        throw new Error('callback must not begin authorization')
      }),
    exchange: async (input) => {
      exchangeCalls += 1
      operationLog.push('exchange')
      return exchange ? await exchange(input) : exchangedGrant
    },
  })
  return {
    alarmTimes,
    alarms,
    coordinator,
    exchangedGrant,
    exchangeCalls: () => exchangeCalls,
    failures,
    grant: () => grant,
    operationLog,
    persistentFailures,
    session,
    snapshot: () => snapshot,
    setNow(value: number) {
      currentNow = value
    },
    isSenderPortAlive: () => senderPortAlive,
    listenForTabRemoval(listener: (tabId: number) => void) {
      tabRemovedListeners.add(listener)
    },
    tabs,
    transactions,
  }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('strict external callback ingress', () => {
  it.each([
    [approvedMessage, { kind: 'approved', code: CODE }],
    [deniedMessage, { kind: 'denied' }],
  ])('accepts an exact callback message and exact sender', (message, expected) => {
    const comparisons: Array<readonly [string, string]> = []

    expect(
      validateExternalCallbackMessage(
        {
          message,
          sender: callbackSender,
          transaction: transaction(),
          callbackOrigin: CALLBACK_ORIGIN,
          callbackPath: CALLBACK_PATH,
          now: NOW,
        },
        callbackCrypto(comparisons),
      ),
    ).toEqual({ ok: true, value: expected })
    expect(comparisons).toEqual([[STATE, STATE]])
  })

  it.each([
    [
      'an unknown field',
      { ...approvedMessage, extra: true },
      callbackSender,
      transaction(),
      NOW,
    ],
    [
      'the wrong sender origin',
      approvedMessage,
      { ...callbackSender, origin: 'https://attacker.example.test' },
      transaction(),
      NOW,
    ],
    [
      'the wrong sender path',
      approvedMessage,
      { ...callbackSender, url: `${CALLBACK_ORIGIN}/other` },
      transaction(),
      NOW,
    ],
    [
      'a sender URL query',
      approvedMessage,
      { ...callbackSender, url: `${CALLBACK_URL}?state=${STATE}` },
      transaction(),
      NOW,
    ],
    [
      'the wrong tab',
      approvedMessage,
      { ...callbackSender, tab: { id: 44, windowId: 12 } },
      transaction(),
      NOW,
    ],
    [
      'a non-authorizing transaction',
      approvedMessage,
      callbackSender,
      transaction('exchanging'),
      NOW,
    ],
    [
      'an expired transaction',
      approvedMessage,
      callbackSender,
      transaction(),
      Date.parse('2026-08-26T04:10:00.000Z'),
    ],
    [
      'the wrong state',
      { ...approvedMessage, state: 'x'.repeat(43) },
      callbackSender,
      transaction(),
      NOW,
    ],
  ])('rejects %s with one non-probing error', (_name, message, sender, active, now) => {
    expect(
      validateExternalCallbackMessage(
        {
          message,
          sender,
          transaction: active,
          callbackOrigin: CALLBACK_ORIGIN,
          callbackPath: CALLBACK_PATH,
          now,
        },
        callbackCrypto(),
      ),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })

  it('freezes Web, exchange and server-code deadlines at the required boundaries', () => {
    expect(WEB_MESSAGE_TIMEOUT_MS).toBe(20_000)
    expect(TOKEN_EXCHANGE_TIMEOUT_MS).toBe(15_000)
    expect(SERVER_AUTHORIZATION_CODE_LIFETIME_MS).toBe(60_000)
    expect(TOKEN_EXCHANGE_TIMEOUT_MS).toBeLessThan(
      SERVER_AUTHORIZATION_CODE_LIFETIME_MS,
    )
  })

  it('returns connectionFailed at the exact 20000 ms Web message deadline', async () => {
    vi.useFakeTimers()
    let settled = false
    const response = sendExternalCallbackWithTimeout(
      async () => await new Promise<never>(() => undefined),
    ).then((value) => {
      settled = true
      return value
    })

    await vi.advanceTimersByTimeAsync(19_999)
    expect(settled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)

    await expect(response).resolves.toEqual({
      ok: false,
      error: 'connectionFailed',
    })
  })

  it('normalizes a rejected Web message send without exposing its error detail', async () => {
    await expect(
      sendExternalCallbackWithTimeout(async () => {
        throw new Error(`private ${CODE} ${STATE}`)
      }),
    ).resolves.toEqual({ ok: false, error: 'connectionFailed' })
  })

  it('normalizes a synchronous Web message adapter fault', async () => {
    await expect(
      sendExternalCallbackWithTimeout(() => {
        throw new Error(`synchronous private ${STATE}`)
      }),
    ).resolves.toEqual({ ok: false, error: 'connectionFailed' })
  })

  it.each([
    { ok: true },
    { ok: false, error: 'callbackRejected' },
    { ok: false, error: 'connectionFailed' },
  ] as const)('passes through only an exact external response $error', async (wire) => {
    await expect(
      sendExternalCallbackWithTimeout(async () => wire),
    ).resolves.toEqual(wire)
  })

  it('normalizes an unknown external response shape', async () => {
    await expect(
      sendExternalCallbackWithTimeout(async () => ({
        ok: true,
        state: STATE,
      })),
    ).resolves.toEqual({ ok: false, error: 'connectionFailed' })
  })
})

describe('serialized callback completion', () => {
  it('settles the external response after durable commit and before closing its sender tab', async () => {
    const harness = await createHarness()
    const runtime = new BackgroundRuntime(harness.coordinator, Promise.resolve())
    harness.listenForTabRemoval((tabId) => {
      harness.operationLog.push(`tabs.onRemoved:${tabId}`)
      runtime.handleTabRemoved(tabId)
    })
    let response: unknown

    expect(
      runtime.handleExternalMessage(
        approvedMessage,
        callbackSender,
        (value) => {
          if (!harness.isSenderPortAlive()) {
            throw new Error('Chrome callback message port is disconnected')
          }
          harness.operationLog.push('sendResponse')
          response = value
        },
      ),
    ).toBe(true)
    await vi.waitFor(() => expect(response).toEqual({ ok: true }))

    const commit = harness.operationLog.indexOf('state.saveSnapshot:idle')
    const respond = harness.operationLog.indexOf('sendResponse')
    const close = harness.operationLog.indexOf('tabs.remove:31')
    expect(commit).toBeLessThan(respond)
    expect(respond).toBeLessThan(close)
    await vi.waitFor(() =>
      expect(harness.tabs.has(31)).toBe(false),
    )
    expect(harness.operationLog).toContain('tabs.onRemoved:31')
    expect(harness.exchangeCalls()).toBe(1)
    expect(
      harness.operationLog.filter(
        (operation) => operation === 'state.saveSnapshot:idle',
      ),
    ).toHaveLength(1)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('continues post-response cleanup when sendResponse throws and absorbs cleanup rejection', async () => {
    const harness = await createHarness()
    const runtime = new BackgroundRuntime(harness.coordinator, Promise.resolve())
    harness.persistentFailures.add('alarms.clear')

    expect(
      runtime.handleExternalMessage(approvedMessage, callbackSender, () => {
        throw new Error('sender disconnected during response settlement')
      }),
    ).toBe(true)

    await vi.waitFor(() => expect(harness.tabs.has(31)).toBe(false))
    expect(await harness.transactions.loadStored()).toMatchObject({
      transactionId: 'transaction-id',
      authTabId: 31,
    })
    expect(harness.grant()).toEqual(harness.exchangedGrant)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('acquires the single-flight before the first asynchronous repository read', async () => {
    const harness = await createHarness()
    const gate = deferred()
    harness.session.getGate = gate.promise

    const callback = harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    const removal = harness.coordinator.handleTabRemoved(31)
    for (let index = 0; index < 10 && harness.session.getCalls === 0; index += 1) {
      await Promise.resolve()
    }
    const readsBeforeRelease = harness.session.getCalls
    gate.resolve()
    await Promise.all([callback, removal])
    expect(readsBeforeRelease).toBe(1)
  })

  it('persists grant then authorized snapshot before cleanup and closes no unrelated tab across SSO', async () => {
    const harness = await createHarness()

    await expect(
      harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      ),
    ).resolves.toEqual({ ok: true })

    expect(harness.grant()).toEqual(harness.exchangedGrant)
    expect(harness.snapshot()).toEqual({
      ...signedOutSnapshot('idle'),
      authorization: {
        kind: 'authorized',
        expiresAt: '2026-08-26T05:00:00.000Z',
        sessionRevision: 'revision-8',
      },
    })
    expect(await harness.transactions.load(NOW)).toMatchObject({
      transactionId: 'transaction-id',
      phase: 'exchanging',
      authTabId: 31,
    })
    expect(harness.tabs.has(31)).toBe(true)

    await harness.coordinator.runPostResponseCleanup()

    expect(await harness.transactions.load(NOW)).toBeNull()
    expect(harness.alarms.size).toBe(0)
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
    expect(harness.operationLog.indexOf('state.saveGrant')).toBeLessThan(
      harness.operationLog.indexOf('state.saveSnapshot:idle'),
    )
    expect(harness.operationLog.indexOf('state.saveSnapshot:idle')).toBeLessThan(
      harness.operationLog.indexOf('tabs.remove:31'),
    )
    expect(harness.operationLog.indexOf('tabs.remove:31')).toBeLessThan(
      harness.operationLog.indexOf(
        `alarms.clear:${AUTHORIZATION_TRANSACTION_ALARM}`,
      ),
    )
    expect(JSON.stringify(harness.session.writes)).not.toContain(CODE)
    expect(
      harness.operationLog.filter(
        (operation) => operation === 'state.saveSnapshot:idle',
      ),
    ).toHaveLength(1)
  })

  it('maps an exact denial to cancelled without exchanging or touching an unrelated tab', async () => {
    const harness = await createHarness()

    await expect(
      harness.coordinator.handleExternalCallback(deniedMessage, callbackSender),
    ).resolves.toEqual({ ok: true })

    expect(harness.exchangeCalls()).toBe(0)
    expect(harness.grant()).toBeNull()
    expect(harness.snapshot().interaction).toEqual({
      phase: 'cancelled',
      occurredAt: new Date(NOW).toISOString(),
    })
    expect(await harness.transactions.loadStored()).toEqual(transaction())
    expect(harness.tabs.has(31)).toBe(true)

    await harness.coordinator.runPostResponseCleanup()

    expect(await harness.transactions.load(NOW)).toBeNull()
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
  })

  it('retains the exact transaction when alarm cleanup fails so the next action can finish denial cleanup', async () => {
    const harness = await createHarness()
    harness.failures.add('alarms.clear')

    await expect(
      harness.coordinator.handleExternalCallback(deniedMessage, callbackSender),
    ).resolves.toEqual({ ok: true })

    await expect(harness.coordinator.runPostResponseCleanup()).rejects.toThrow(
      'alarm clear failure',
    )

    expect(await harness.transactions.loadStored()).toEqual(transaction())
    expect(harness.tabs.has(31)).toBe(false)

    await expect(harness.coordinator.status()).resolves.toMatchObject({
      interaction: { phase: 'cancelled' },
    })
    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.tabs.has(31)).toBe(false)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('lazily expires an exact callback at its absolute deadline and closes only its auth tab', async () => {
    const harness = await createHarness()
    harness.setNow(Date.parse('2026-08-26T04:10:00.000Z'))

    await expect(
      harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      ),
    ).resolves.toEqual({ ok: false, error: 'callbackRejected' })

    expect(harness.exchangeCalls()).toBe(0)
    expect(harness.snapshot().interaction).toEqual({
      phase: 'expired',
      occurredAt: '2026-08-26T04:10:00.000Z',
    })
    expect(await harness.transactions.loadStored()).toEqual(transaction())

    await harness.coordinator.runPostResponseCleanup()

    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.alarms.size).toBe(0)
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
  })

  it('ignores an unrelated tab removal and cancels only after the exact auth tab is removed', async () => {
    const harness = await createHarness()

    await harness.coordinator.handleTabRemoved(44)
    expect(await harness.transactions.load(NOW)).toEqual(transaction())
    expect(harness.snapshot().interaction).toEqual({ phase: 'authorizing' })

    harness.tabs.delete(31)
    await harness.coordinator.handleTabRemoved(31)

    expect(harness.snapshot().interaction).toEqual({
      phase: 'cancelled',
      occurredAt: new Date(NOW).toISOString(),
    })
    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.tabs.has(17)).toBe(true)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('uses exact onRemoved as definitive cleanup-pending tab closure without tabs.get', async () => {
    const harness = await createHarness()
    await harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    harness.persistentFailures.add('tabs.get')
    await harness.coordinator.runPostResponseCleanup()
    expect(await harness.transactions.loadStored()).toMatchObject({
      authTabId: 31,
    })

    harness.tabs.delete(31)
    await harness.coordinator.handleTabRemoved(31)

    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.alarms.size).toBe(0)
    expect(harness.grant()).toEqual(harness.exchangedGrant)
    expect(harness.snapshot().interaction).toEqual({ phase: 'idle' })
    expect(harness.operationLog).not.toContain('state.saveSnapshot:cancelled')
    expect(harness.exchangeCalls()).toBe(1)
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
  })

  it('expires through the exact alarm and tolerates an SSO intermediate URL', async () => {
    const harness = await createHarness()
    harness.setNow(Date.parse('2026-08-26T04:10:00.000Z'))

    await harness.coordinator.handleAlarm({
      name: AUTHORIZATION_TRANSACTION_ALARM,
    })

    expect(harness.snapshot().interaction).toEqual({
      phase: 'expired',
      occurredAt: '2026-08-26T04:10:00.000Z',
    })
    expect(await harness.transactions.loadStored()).toBeNull()
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
  })

  it.each([
    ['transient', 'tabs.get'],
    ['persistent', 'tabs.get'],
    ['transient', 'tabs.remove'],
    ['persistent', 'tabs.remove'],
  ] as const)(
    'retains an expired alarm transaction after a %s %s close fault',
    async (duration, fault) => {
      const harness = await createHarness()
      harness.setNow(Date.parse('2026-08-26T04:10:00.000Z'))
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)

      await harness.coordinator.handleAlarm({
        name: AUTHORIZATION_TRANSACTION_ALARM,
      })

      expect(harness.snapshot().interaction.phase).toBe('expired')
      expect(await harness.transactions.loadStored()).toMatchObject({
        authTabId: 31,
      })
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)

      await harness.coordinator.status()
      if (duration === 'transient') {
        expect(await harness.transactions.loadStored()).toBeNull()
        expect(harness.tabs.has(31)).toBe(false)
      } else {
        expect(await harness.transactions.loadStored()).toMatchObject({
          authTabId: 31,
        })
        expect(harness.tabs.has(31)).toBe(true)
      }
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:expired',
        ),
      ).toHaveLength(1)
      expect(harness.exchangeCalls()).toBe(0)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each([
    ['transient', 'alarms.clear'],
    ['persistent', 'alarms.clear'],
    ['transient', 'session.remove'],
    ['persistent', 'session.remove'],
  ] as const)(
    'retains exact removed-tab authority after a %s %s cleanup fault',
    async (duration, fault) => {
      const harness = await createHarness()
      harness.tabs.delete(31)
      if (fault === 'session.remove') {
        if (duration === 'transient') harness.session.failNext = 'remove'
        else harness.session.failAlways.add('remove')
      } else {
        const faultSet =
          duration === 'transient'
            ? harness.failures
            : harness.persistentFailures
        faultSet.add(fault)
      }

      await expect(harness.coordinator.handleTabRemoved(31)).rejects.toThrow()

      expect(harness.snapshot().interaction.phase).toBe('cancelled')
      expect(await harness.transactions.loadStored()).toMatchObject({
        authTabId: 31,
      })
      expect(harness.tabs.has(17)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)

      if (duration === 'transient') {
        await harness.coordinator.status()
        expect(await harness.transactions.loadStored()).toBeNull()
      } else {
        await expect(harness.coordinator.status()).rejects.toThrow()
        expect(await harness.transactions.loadStored()).toMatchObject({
          authTabId: 31,
        })
      }
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:cancelled',
        ),
      ).toHaveLength(1)
      expect(harness.exchangeCalls()).toBe(0)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it('exchanges only once for duplicate callbacks and never echoes secrets', async () => {
    const gate = deferred()
    const started = deferred()
    const harness = await createHarness({
      exchange: async () => {
        started.resolve()
        await gate.promise
        return {
          accessToken: 'eyJsecret.header.signature',
          expiresAt: '2026-08-26T05:00:00.000Z',
          sessionRevision: 'revision-8',
        }
      },
    })

    const first = harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    await started.promise
    const duplicate = harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    gate.resolve()

    const responses = await Promise.all([first, duplicate])
    expect(responses).toEqual([
      { ok: true },
      { ok: false, error: 'callbackRejected' },
    ])
    expect(harness.exchangeCalls()).toBe(1)
    expect(JSON.stringify(responses)).not.toMatch(
      /opaque-code|ssss|vvvv|eyJsecret/u,
    )
  })

  it('lets an approved grant dominate queued denial, alarm and tab-removal events', async () => {
    const gate = deferred()
    const started = deferred()
    const harness = await createHarness({
      exchange: async () => {
        started.resolve()
        await gate.promise
        return {
          accessToken: 'eyJsecret.header.signature',
          expiresAt: '2026-08-26T05:00:00.000Z',
          sessionRevision: 'revision-8',
        }
      },
    })

    const approved = harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    await started.promise
    const denied = harness.coordinator.handleExternalCallback(
      deniedMessage,
      callbackSender,
    )
    const alarm = harness.coordinator.handleAlarm({
      name: AUTHORIZATION_TRANSACTION_ALARM,
    })
    const removed = harness.coordinator.handleTabRemoved(31)
    gate.resolve()
    await Promise.all([approved, denied, alarm, removed])

    expect(harness.snapshot().authorization).toEqual({
      kind: 'authorized',
      expiresAt: '2026-08-26T05:00:00.000Z',
      sessionRevision: 'revision-8',
    })
    expect(harness.snapshot().interaction).toEqual({ phase: 'idle' })
    expect(harness.operationLog).not.toContain('state.saveSnapshot:cancelled')
    expect(harness.operationLog).not.toContain('state.saveSnapshot:expired')
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('lets an already valid grant dominate alarm and exact tab removal', async () => {
    const existing: StoredAuthorizationGrant = {
      accessToken: 'eyJexisting.header.signature',
      expiresAt: '2026-08-26T05:00:00.000Z',
      sessionRevision: 'revision-existing',
    }
    const harness = await createHarness({ initialGrant: existing })

    await Promise.all([
      harness.coordinator.handleAlarm({
        name: AUTHORIZATION_TRANSACTION_ALARM,
      }),
      harness.coordinator.handleTabRemoved(31),
    ])

    expect(harness.grant()).toEqual(existing)
    expect(harness.snapshot().authorization).toEqual({
      kind: 'authorized',
      expiresAt: existing.expiresAt,
      sessionRevision: existing.sessionRevision,
    })
    expect(harness.snapshot().interaction).toEqual({ phase: 'idle' })
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('aborts a stalled token exchange at 15000 ms and preserves any prior grant', async () => {
    vi.useFakeTimers()
    const started = deferred()
    const priorGrant: StoredAuthorizationGrant = {
      accessToken: 'eyJprior.header.signature',
      expiresAt: '2026-08-26T04:00:30.000Z',
      sessionRevision: 'revision-prior',
    }
    const harness = await createHarness({
      initialGrant: priorGrant,
      exchange: async ({ signal }) =>
        await new Promise<StoredAuthorizationGrant>((_resolve, reject) => {
          started.resolve()
          signal.addEventListener('abort', () =>
            reject(new Error('controlled abort')),
          )
        }),
    })

    const completion = harness.coordinator.handleExternalCallback(
      approvedMessage,
      callbackSender,
    )
    await started.promise
    await vi.advanceTimersByTimeAsync(15_000)

    await expect(completion).resolves.toEqual({
      ok: false,
      error: 'connectionFailed',
    })
    expect(harness.grant()).toEqual(priorGrant)
    expect(harness.exchangeCalls()).toBe(1)
  })

  it('finishes at 15000 ms even when the exchange adapter ignores abort', async () => {
    vi.useFakeTimers()
    const started = deferred()
    const release = deferred()
    const harness = await createHarness({
      exchange: async () => {
        started.resolve()
        await release.promise
        return {
          accessToken: 'eyJlate.header.signature',
          expiresAt: '2026-08-26T05:00:00.000Z',
          sessionRevision: 'late-revision',
        }
      },
    })
    let responseAtDeadline: unknown
    const completion = harness.coordinator
      .handleExternalCallback(approvedMessage, callbackSender)
      .then((value) => {
        responseAtDeadline = value
        return value
      })
    await started.promise

    await vi.advanceTimersByTimeAsync(15_000)
    const observedAtDeadline = responseAtDeadline
    release.resolve()
    await completion

    expect(observedAtDeadline).toEqual({
      ok: false,
      error: 'connectionFailed',
    })
    expect(harness.grant()).toBeNull()
  })

  it('clears the exchange deadline after a synchronous adapter fault', async () => {
    vi.useFakeTimers()
    const harness = await createHarness({
      exchange: () => {
        throw new Error(`synchronous private exchange fault ${CODE}`)
      },
    })

    await expect(
      harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      ),
    ).resolves.toEqual({ ok: false, error: 'connectionFailed' })

    expect(vi.getTimerCount()).toBe(0)
    expect(harness.grant()).toBeNull()
  })

  it.each([
    ['transient', 'tabs.get'],
    ['persistent', 'tabs.get'],
    ['transient', 'tabs.remove'],
    ['persistent', 'tabs.remove'],
  ] as const)(
    'retains cleanup authority after a %s %s fault and retries only the bound tab',
    async (duration, fault) => {
      const harness = await createHarness()
      await expect(
        harness.coordinator.handleExternalCallback(
          approvedMessage,
          callbackSender,
        ),
      ).resolves.toEqual({ ok: true })
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)

      await expect(
        harness.coordinator.runPostResponseCleanup(),
      ).resolves.toBeUndefined()

      expect(await harness.transactions.loadStored()).toMatchObject({
        transactionId: 'transaction-id',
        authTabId: 31,
      })
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(17)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)
      expect(harness.grant()).toEqual(harness.exchangedGrant)
      expect(harness.exchangeCalls()).toBe(1)

      await harness.coordinator.status()
      if (duration === 'transient') {
        expect(await harness.transactions.loadStored()).toBeNull()
        expect(harness.tabs.has(31)).toBe(false)
      } else {
        expect(await harness.transactions.loadStored()).toMatchObject({
          authTabId: 31,
        })
        expect(harness.tabs.has(31)).toBe(true)
      }
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:idle',
        ),
      ).toHaveLength(1)
      expect(harness.exchangeCalls()).toBe(1)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each([
    ['transient', 'alarms.clear'],
    ['persistent', 'alarms.clear'],
    ['transient', 'session.remove'],
    ['persistent', 'session.remove'],
  ] as const)(
    'keeps the sealed record after a %s %s storage cleanup fault',
    async (duration, fault) => {
      const harness = await createHarness()
      await harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      )
      if (fault === 'session.remove') {
        if (duration === 'transient') harness.session.failNext = 'remove'
        else harness.session.failAlways.add('remove')
      } else {
        const faultSet =
          duration === 'transient'
            ? harness.failures
            : harness.persistentFailures
        faultSet.add(fault)
      }

      await expect(harness.coordinator.runPostResponseCleanup()).rejects.toThrow()

      expect(harness.tabs.has(31)).toBe(false)
      expect(await harness.transactions.loadStored()).toMatchObject({
        transactionId: 'transaction-id',
        authTabId: 31,
      })
      expect(harness.grant()).toEqual(harness.exchangedGrant)
      expect(harness.tabs.has(44)).toBe(true)

      if (duration === 'transient') {
        await harness.coordinator.status()
        expect(await harness.transactions.loadStored()).toBeNull()
      } else {
        await expect(harness.coordinator.status()).rejects.toThrow()
        expect(await harness.transactions.loadStored()).toMatchObject({
          authTabId: 31,
        })
      }
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:idle',
        ),
      ).toHaveLength(1)
      expect(harness.exchangeCalls()).toBe(1)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each([
    ['transient', 'windows.get'],
    ['persistent', 'windows.get'],
    ['transient', 'tabs.update'],
    ['persistent', 'tabs.update'],
    ['transient', 'windows.update'],
    ['persistent', 'windows.update'],
  ] as const)(
    'closes only the auth tab despite a %s optional-focus %s fault',
    async (duration, fault) => {
      const harness = await createHarness()
      await harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      )
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)

      await expect(
        harness.coordinator.runPostResponseCleanup(),
      ).resolves.toBeUndefined()

      expect(await harness.transactions.loadStored()).toBeNull()
      expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
      expect(harness.grant()).toEqual(harness.exchangedGrant)
      expect(harness.exchangeCalls()).toBe(1)
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:idle',
        ),
      ).toHaveLength(1)
    },
  )

  it.each(['transient', 'persistent'] as const)(
    'normalizes a %s session.get callback fault and never loses the stored binding',
    async (duration) => {
      const harness = await createHarness()
      const runtime = new BackgroundRuntime(
        harness.coordinator,
        Promise.resolve(),
      )
      if (duration === 'transient') harness.session.failNext = 'get'
      else harness.session.failAlways.add('get')
      const response = new Promise<unknown>((resolve) => {
        expect(
          runtime.handleExternalMessage(
            approvedMessage,
            callbackSender,
            resolve,
          ),
        ).toBe(true)
      })

      await expect(response).resolves.toEqual({
        ok: false,
        error: 'connectionFailed',
      })
      expect(harness.exchangeCalls()).toBe(0)
      expect(harness.session.values.get(TRANSACTION_STORAGE_KEY)).toEqual(
        transaction(),
      )
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)

      if (duration === 'transient') {
        const retry = new Promise<unknown>((resolve) => {
          runtime.handleExternalMessage(
            approvedMessage,
            callbackSender,
            resolve,
          )
        })
        await expect(retry).resolves.toEqual({ ok: true })
        await vi.waitFor(() => expect(harness.tabs.has(31)).toBe(false))
        expect(harness.exchangeCalls()).toBe(1)
      }
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each(['transient', 'persistent'] as const)(
    'fails terminally without exchange after a %s session.set callback fault',
    async (duration) => {
      const harness = await createHarness()
      const runtime = new BackgroundRuntime(
        harness.coordinator,
        Promise.resolve(),
      )
      if (duration === 'transient') harness.session.failNext = 'set'
      else harness.session.failAlways.add('set')
      const response = new Promise<unknown>((resolve) => {
        runtime.handleExternalMessage(
          approvedMessage,
          callbackSender,
          resolve,
        )
      })

      await expect(response).resolves.toEqual({
        ok: false,
        error: 'connectionFailed',
      })
      await vi.waitFor(() => expect(harness.tabs.has(31)).toBe(false))
      expect(harness.grant()).toBeNull()
      expect(harness.exchangeCalls()).toBe(0)
      expect(await harness.transactions.loadStored()).toBeNull()
      expect(harness.snapshot().interaction).toEqual({
        phase: 'failed',
        occurredAt: new Date(NOW).toISOString(),
      })
      expect(
        harness.operationLog.filter(
          (operation) => operation === 'state.saveSnapshot:failed',
        ),
      ).toHaveLength(1)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each([
    ['transient', 'state.readSnapshot'],
    ['persistent', 'state.readSnapshot'],
    ['transient', 'state.readGrant'],
    ['persistent', 'state.readGrant'],
  ] as const)(
    'normalizes a %s %s callback fault while retaining exact tab authority',
    async (duration, fault) => {
      const harness = await createHarness()
      const runtime = new BackgroundRuntime(
        harness.coordinator,
        Promise.resolve(),
      )
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)
      const response = new Promise<unknown>((resolve) => {
        runtime.handleExternalMessage(
          approvedMessage,
          callbackSender,
          resolve,
        )
      })

      await expect(response).resolves.toEqual({
        ok: false,
        error: 'connectionFailed',
      })
      expect(await harness.transactions.loadStored()).toEqual(transaction())
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)
      expect(harness.exchangeCalls()).toBe(0)
    },
  )

  it.each(['transient', 'persistent'] as const)(
    'preserves a failed terminal without a grant after a %s grant write fault',
    async (duration) => {
      const harness = await createHarness()
      const runtime = new BackgroundRuntime(
        harness.coordinator,
        Promise.resolve(),
      )
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add('state.saveGrant')
      const response = new Promise<unknown>((resolve) => {
        runtime.handleExternalMessage(
          approvedMessage,
          callbackSender,
          resolve,
        )
      })

      await expect(response).resolves.toEqual({
        ok: false,
        error: 'connectionFailed',
      })
      await vi.waitFor(() => expect(harness.tabs.has(31)).toBe(false))
      expect(harness.grant()).toBeNull()
      expect(harness.snapshot().interaction.phase).toBe('failed')
      expect(await harness.transactions.loadStored()).toBeNull()
      expect(harness.exchangeCalls()).toBe(1)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it.each(['transient', 'persistent'] as const)(
    'retains or completes cleanup deterministically after a %s snapshot write fault',
    async (duration) => {
      const harness = await createHarness()
      const runtime = new BackgroundRuntime(
        harness.coordinator,
        Promise.resolve(),
      )
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add('state.saveSnapshot')
      const response = new Promise<unknown>((resolve) => {
        runtime.handleExternalMessage(
          approvedMessage,
          callbackSender,
          resolve,
        )
      })

      await expect(response).resolves.toEqual({
        ok: false,
        error: 'connectionFailed',
      })
      if (duration === 'transient') {
        await vi.waitFor(() => expect(harness.tabs.has(31)).toBe(false))
        expect(await harness.transactions.loadStored()).toBeNull()
        expect(harness.snapshot().interaction.phase).toBe('failed')
      } else {
        await vi.waitFor(() =>
          expect(
            harness.operationLog.filter(
              (operation) => operation === 'state.saveSnapshot:failed',
            ).length,
          ).toBeGreaterThanOrEqual(2),
        )
        expect(await harness.transactions.loadStored()).toMatchObject({
          phase: 'exchanging',
          authTabId: 31,
        })
        expect(harness.tabs.has(31)).toBe(true)
        expect(harness.snapshot().interaction.phase).toBe('authorizing')
      }
      expect(harness.grant()).toBeNull()
      expect(harness.exchangeCalls()).toBe(0)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )
})

describe('login, focus and reload recovery', () => {
  const AUTHORIZE_URL =
    'https://accounts.example.test/app-authorizations/v1/authorize?client_id=browser-client-v2'
  const beginning = async () => ({
    transactionId: 'new-transaction-id',
    clientId: 'browser-client-v2',
    redirectUri: CALLBACK_URL,
    prepared: {
      state: STATE,
      codeVerifier: 'v'.repeat(43),
      authorizeUrl: AUTHORIZE_URL,
    },
    sourceTabId: 17,
    sourceWindowId: 9,
  })

  it.each([
    ['approved', 'tabs.get'],
    ['approved', 'tabs.remove'],
    ['denied', 'tabs.get'],
    ['denied', 'tabs.remove'],
  ] as const)(
    'does not replace cleanup-pending %s authority after a persistent %s fault',
    async (result, fault) => {
      let beginCalls = 0
      const harness = await createHarness({
        beginAuthorization: async () => {
          beginCalls += 1
          return {
            transactionId: 'replacement-transaction-id',
            clientId: 'browser-client-v2',
            redirectUri: CALLBACK_URL,
            prepared: {
              state: 'r'.repeat(43),
              codeVerifier: 'w'.repeat(43),
              authorizeUrl: AUTHORIZE_URL,
            },
            sourceTabId: 17,
            sourceWindowId: 9,
          }
        },
        authorizationUrl: async () => AUTHORIZE_URL,
      })
      await expect(
        harness.coordinator.handleExternalCallback(
          result === 'approved' ? approvedMessage : deniedMessage,
          callbackSender,
        ),
      ).resolves.toEqual({ ok: true })
      harness.persistentFailures.add(fault)
      await harness.coordinator.runPostResponseCleanup()

      const terminal =
        result === 'approved'
          ? {
              ...signedOutSnapshot('idle'),
              authorization: {
                kind: 'authorized' as const,
                expiresAt: harness.exchangedGrant.expiresAt,
                sessionRevision: harness.exchangedGrant.sessionRevision,
              },
            }
          : signedOutSnapshot('cancelled')

      await expect(harness.coordinator.login()).resolves.toEqual(terminal)
      await expect(harness.coordinator.status()).resolves.toEqual(terminal)
      await expect(harness.coordinator.focusAuthorization()).resolves.toEqual(
        terminal,
      )
      await expect(
        harness.coordinator.handleExternalCallback(
          approvedMessage,
          callbackSender,
        ),
      ).resolves.toEqual({ ok: false, error: 'callbackRejected' })
      await harness.coordinator.handleAlarm({
        name: AUTHORIZATION_TRANSACTION_ALARM,
      })
      await harness.coordinator.handleTabRemoved(44)

      expect(await harness.transactions.loadStored()).toMatchObject({
        transactionId: 'transaction-id',
        phase: result === 'approved' ? 'exchanging' : 'authorizing',
        authTabId: 31,
      })
      expect(harness.alarms.has(AUTHORIZATION_TRANSACTION_ALARM)).toBe(true)
      expect(beginCalls).toBe(0)
      expect(harness.exchangeCalls()).toBe(result === 'approved' ? 1 : 0)
      expect(harness.operationLog).not.toContain('tabs.create')
      expect([...harness.tabs.keys()].sort()).toEqual([17, 31, 44])
      expect(
        harness.operationLog
          .filter((operation) => operation.startsWith('tabs.remove:'))
          .every((operation) => operation === 'tabs.remove:31'),
      ).toBe(true)

      harness.persistentFailures.delete(fault)
      await expect(harness.coordinator.status()).resolves.toEqual(terminal)
      expect(await harness.transactions.loadStored()).toBeNull()
      expect(harness.alarms.size).toBe(0)
      expect([...harness.tabs.keys()].sort()).toEqual([17, 44])

      await expect(harness.coordinator.login()).resolves.toMatchObject({
        authorization: { kind: 'authorizing' },
        interaction: { phase: 'authorizing' },
      })
      expect(beginCalls).toBe(1)
      expect(await harness.transactions.loadStored()).toMatchObject({
        transactionId: 'replacement-transaction-id',
        phase: 'authorizing',
        authTabId: 31,
      })
      expect(harness.alarms.has(AUTHORIZATION_TRANSACTION_ALARM)).toBe(true)
      expect([...harness.tabs.keys()].sort()).toEqual([17, 31, 44])
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it('returns after the tab is bound, authorizing is persisted and navigation has started', async () => {
    const harness = await createHarness({
      initialTransaction: false,
      beginAuthorization: beginning,
      authorizationUrl: async () => AUTHORIZE_URL,
    })

    await expect(harness.coordinator.login()).resolves.toEqual(
      signedOutSnapshot('authorizing'),
    )

    const stored = await harness.transactions.load(NOW)
    expect(stored).toMatchObject({
      transactionId: 'new-transaction-id',
      phase: 'authorizing',
      authTabId: 31,
      createdAt: '2026-08-26T04:01:00.000Z',
      expiresAt: '2026-08-26T04:11:00.000Z',
    })
    expect(harness.alarmTimes.get(AUTHORIZATION_TRANSACTION_ALARM)).toBe(
      Date.parse('2026-08-26T04:11:00.000Z'),
    )
    expect(harness.tabs.get(31)?.url).toBe(AUTHORIZE_URL)
    expect(harness.operationLog.indexOf('tabs.create')).toBeLessThan(
      harness.operationLog.indexOf('tabs.update:31'),
    )
    expect(harness.snapshot().interaction).toEqual({ phase: 'authorizing' })
  })

  it.each([
    ['transient', 'session.set'],
    ['persistent', 'session.set'],
    ['transient', 'alarms.create'],
    ['persistent', 'alarms.create'],
    ['transient', 'tabs.create'],
    ['persistent', 'tabs.create'],
    ['transient', 'tabs.update'],
    ['persistent', 'tabs.update'],
    ['transient', 'state.saveSnapshot'],
  ] as const)('fails login closed at a %s %s fault and preserves unrelated tabs', async (duration, fault) => {
    const harness = await createHarness({
      initialTransaction: false,
      beginAuthorization: beginning,
      authorizationUrl: async () => AUTHORIZE_URL,
    })
    if (fault === 'session.set') {
      if (duration === 'transient') harness.session.failNext = 'set'
      else harness.session.failAlways.add('set')
    } else {
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)
    }

    await expect(harness.coordinator.login()).rejects.toThrow()

    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.alarms.size).toBe(0)
    expect([...harness.tabs.keys()].sort()).toEqual([17, 44])
    expect(harness.snapshot().authorization).toEqual({
      kind: 'signed-out',
      reason: 'never-authorized',
    })
  })

  it('keeps alarm and exact tab authority when navigation compensation cannot close the tab', async () => {
    const harness = await createHarness({
      initialTransaction: false,
      beginAuthorization: beginning,
      authorizationUrl: async () => AUTHORIZE_URL,
    })
    harness.failures.add('tabs.update')
    harness.failures.add('tabs.remove')

    await expect(harness.coordinator.login()).rejects.toThrow()

    expect(await harness.transactions.loadStored()).toMatchObject({
      transactionId: 'new-transaction-id',
      authTabId: 31,
    })
    expect(harness.alarms.has(AUTHORIZATION_TRANSACTION_ALARM)).toBe(true)
    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabs.has(44)).toBe(true)

    await harness.coordinator.status()
    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.tabs.has(31)).toBe(false)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it('marks a missing exact authorization tab expired without touching another tab', async () => {
    const harness = await createHarness()
    harness.tabs.delete(31)

    await expect(harness.coordinator.focusAuthorization()).resolves.toEqual({
      ...signedOutSnapshot('expired'),
      interaction: {
        phase: 'expired',
        occurredAt: new Date(NOW).toISOString(),
      },
    })

    expect(await harness.transactions.loadStored()).toBeNull()
    expect(harness.tabs.has(17)).toBe(true)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it.each([
    ['transient', 'tabs.get'],
    ['persistent', 'tabs.get'],
    ['transient', 'tabs.update'],
    ['persistent', 'tabs.update'],
    ['transient', 'windows.update'],
    ['persistent', 'windows.update'],
  ] as const)(
    'retains an active transaction after a %s focus %s fault',
    async (duration, fault) => {
      const harness = await createHarness()
      const faultSet =
        duration === 'transient'
          ? harness.failures
          : harness.persistentFailures
      faultSet.add(fault)

      await expect(harness.coordinator.focusAuthorization()).resolves.toEqual(
        signedOutSnapshot('authorizing'),
      )

      expect(await harness.transactions.load(NOW)).toEqual(transaction())
      expect(harness.snapshot().interaction).toEqual({ phase: 'authorizing' })
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )

  it('rejects an old callback after extension reload loses session state and never reconstructs secrets from the tab', async () => {
    const harness = await createHarness({ initialTransaction: false })
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: true,
      url: CALLBACK_URL,
    })

    await expect(
      harness.coordinator.handleExternalCallback(
        approvedMessage,
        callbackSender,
      ),
    ).resolves.toEqual({ ok: false, error: 'callbackRejected' })

    expect(harness.exchangeCalls()).toBe(0)
    expect(harness.session.values.size).toBe(0)
    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabs.has(44)).toBe(true)
  })

  it.each(['authorizing', 'exchanging'] as const)(
    'converges a persisted %s snapshot to failed when session transaction state is lost',
    async (phase) => {
      const harness = await createHarness({
        initialTransaction: false,
        initialSnapshot: signedOutSnapshot(phase),
      })
      harness.tabs.set(31, {
        id: 31,
        windowId: 9,
        active: true,
        url: CALLBACK_URL,
      })

      await expect(harness.coordinator.status()).resolves.toEqual(
        signedOutSnapshot('failed'),
      )

      expect(harness.exchangeCalls()).toBe(0)
      expect(harness.session.values.size).toBe(0)
      expect(harness.operationLog).not.toContain('tabs.update:31')
      expect(harness.tabs.has(31)).toBe(true)
      expect(harness.tabs.has(44)).toBe(true)
    },
  )
})
