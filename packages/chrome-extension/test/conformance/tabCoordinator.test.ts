import { describe, expect, it } from 'vitest'

import {
  AUTHORIZATION_BOOTSTRAP_PATH,
  BOOTSTRAP_RETRY_DELAYS_MS,
  createTabCoordinator,
  reportBootstrapWithRetry,
} from '../../src/chrome-adapter/tabCoordinator'
import {
  TRANSACTION_STORAGE_KEY,
  createSessionTransactionRepository,
  type TabTransactionV1,
} from '../../src/chrome-adapter/sessionRepository'

const EXTENSION_ID = 'a'.repeat(32)
const NOW = Date.parse('2026-08-26T04:00:01.000Z')
const AUTHORIZE_URL =
  'https://accounts.example.test/app-authorizations/v1/authorize?client_id=browser-client-v2'

const transaction = (
  phase: TabTransactionV1['phase'] = 'opening',
  authTabId: number | null = null,
): TabTransactionV1 => ({
  version: 1,
  transactionId: 'transaction-id',
  clientId: 'browser-client-v2',
  redirectUri:
    'https://web.example.test/apps/extension-auth/callback/client-v2',
  state: 's'.repeat(43),
  codeVerifier: 'v'.repeat(43),
  sourceTabId: 17,
  sourceWindowId: 9,
  createdAt: '2026-08-26T04:00:00.000Z',
  expiresAt: '2026-08-26T04:10:00.000Z',
  phase,
  authTabId,
}) as TabTransactionV1

class SessionArea {
  readonly values = new Map<string, unknown>()
  readonly writes: unknown[] = []
  failOnSetNumber: number | null = null
  removeFailure = false
  private setCount = 0

  async setAccessLevel(): Promise<void> {}

  async get(key: string): Promise<Record<string, unknown>> {
    return this.values.has(key)
      ? { [key]: structuredClone(this.values.get(key)) }
      : {}
  }

  async set(values: Record<string, unknown>): Promise<void> {
    this.setCount += 1
    if (this.failOnSetNumber === this.setCount) {
      throw new Error('controlled transaction write failure')
    }
    const value = values[TRANSACTION_STORAGE_KEY]
    this.writes.push(structuredClone(value))
    for (const [key, stored] of Object.entries(values)) {
      this.values.set(key, structuredClone(stored))
    }
  }

  async remove(key: string): Promise<void> {
    if (this.removeFailure) throw new Error('controlled remove failure')
    this.values.delete(key)
  }
}

interface TabState {
  id: number
  windowId: number
  active: boolean
  url: string
}

const createHarness = async () => {
  let currentNow = NOW
  const session = new SessionArea()
  const repository = createSessionTransactionRepository({ session })
  await repository.ready()
  await repository.save(transaction())
  const tabs = new Map<number, TabState>([
    [
      17,
      {
        id: 17,
        windowId: 9,
        active: false,
        url: 'https://seller.example.test/manager',
      },
    ],
  ])
  const tabCalls: Array<readonly [string, unknown]> = []
  const windowCalls: Array<readonly [string, unknown]> = []
  const failures = new Set<string>()
  const chrome = {
    runtime: {
      id: EXTENSION_ID,
      getURL(path: string) {
        return `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//u, '')}`
      },
    },
    tabs: {
      async create(input: {
        url: string
        windowId: number
        openerTabId: number
        active: true
      }) {
        tabCalls.push(['create', structuredClone(input)])
        if (failures.has('tabs.create')) throw new Error('create failure')
        const created: TabState = {
          id: 31,
          windowId: input.windowId,
          active: input.active,
          url: input.url,
        }
        tabs.set(created.id, created)
        return structuredClone(created)
      },
      async update(
        tabId: number,
        input: { url?: string; active?: boolean },
      ) {
        tabCalls.push(['update', { tabId, ...structuredClone(input) }])
        if (failures.has('tabs.update')) throw new Error('update failure')
        const tab = tabs.get(tabId)
        if (!tab) throw new Error('tab missing')
        if (input.url !== undefined) tab.url = input.url
        if (input.active !== undefined) tab.active = input.active
        return structuredClone(tab)
      },
      async get(tabId: number) {
        tabCalls.push(['get', tabId])
        if (failures.has('tabs.get')) throw new Error('get failure')
        const tab = tabs.get(tabId)
        if (!tab) return null
        return structuredClone(tab)
      },
      async remove(tabId: number) {
        tabCalls.push(['remove', tabId])
        if (failures.has('tabs.remove')) throw new Error('remove failure')
        if (!tabs.delete(tabId)) throw new Error('tab missing')
      },
    },
    windows: {
      async get(windowId: number) {
        windowCalls.push(['get', windowId])
        if (failures.has('windows.get')) throw new Error('window get failure')
        return { id: windowId, focused: true }
      },
      async update(windowId: number, input: { focused: true }) {
        windowCalls.push(['update', { windowId, ...input }])
        if (failures.has('windows.update')) {
          throw new Error('window update failure')
        }
        return { id: windowId, focused: input.focused }
      },
    },
  }
  const coordinator = createTabCoordinator({
    chrome,
    transactions: repository,
    now: () => currentNow,
    authorizationUrl: async () => AUTHORIZE_URL,
  })
  return {
    chrome,
    coordinator,
    failures,
    repository,
    session,
    setNow(value: number) {
      currentNow = value
    },
    tabCalls,
    tabs,
    windowCalls,
  }
}

describe('two-phase authorization tab coordination', () => {
  it('creates in the source window, binds and persists authorizing before navigation', async () => {
    const harness = await createHarness()

    await expect(
      harness.coordinator.open(transaction(), AUTHORIZE_URL),
    ).resolves.toEqual(transaction('authorizing', 31))

    expect(harness.tabCalls).toEqual([
      [
        'create',
        {
          url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
          windowId: 9,
          openerTabId: 17,
          active: true,
        },
      ],
      ['update', { tabId: 31, url: AUTHORIZE_URL }],
    ])
    expect(
      harness.session.writes.map(
        (value) => (value as TabTransactionV1).phase,
      ),
    ).toEqual(['opening', 'opening', 'authorizing'])
    expect(await harness.repository.load(NOW)).toEqual(
      transaction('authorizing', 31),
    )
  })

  it('uses the freshly prepared authorize URL for initial navigation', async () => {
    const harness = await createHarness()
    const preparedAuthorizeUrl = `${AUTHORIZE_URL}&state=fresh-prepared-state`

    await harness.coordinator.open(transaction(), preparedAuthorizeUrl)

    expect(harness.tabs.get(31)?.url).toBe(preparedAuthorizeUrl)
  })

  it('clears an opening transaction when tab creation fails without removing any tab', async () => {
    const harness = await createHarness()
    harness.failures.add('tabs.create')

    await expect(harness.coordinator.open(transaction(), AUTHORIZE_URL)).rejects.toThrow(
      'create failure',
    )

    expect(await harness.repository.load(NOW)).toBeNull()
    expect(harness.tabCalls).toEqual([
      [
        'create',
        {
          url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
          windowId: 9,
          openerTabId: 17,
          active: true,
        },
      ],
    ])
    expect([...harness.tabs.keys()]).toEqual([17])
  })

  it.each([2, 3])(
    'closes only the created tab and clears state when transaction write %s fails',
    async (setNumber) => {
      const harness = await createHarness()
      harness.session.failOnSetNumber = setNumber

      await expect(harness.coordinator.open(transaction(), AUTHORIZE_URL)).rejects.toThrow(
        'controlled transaction write failure',
      )

      expect(harness.tabCalls.at(-1)).toEqual(['remove', 31])
      expect([...harness.tabs.keys()]).toEqual([17])
      expect(await harness.repository.load(NOW)).toBeNull()
    },
  )

  it('retains the created tab binding when compensating removal fails after bind persistence', async () => {
    const harness = await createHarness()
    harness.session.failOnSetNumber = 2
    harness.failures.add('tabs.remove')

    await expect(
      harness.coordinator.open(transaction(), AUTHORIZE_URL),
    ).rejects.toThrow()

    expect(await harness.repository.load(NOW)).toEqual(
      transaction('opening', 31),
    )
    expect(harness.tabCalls.at(-1)).toEqual(['remove', 31])
    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabs.has(17)).toBe(true)
  })

  it('retains an authorizing binding when navigation and compensating removal fail', async () => {
    const harness = await createHarness()
    harness.failures.add('tabs.update')
    harness.failures.add('tabs.remove')

    await expect(
      harness.coordinator.open(transaction(), AUTHORIZE_URL),
    ).rejects.toThrow()

    expect(await harness.repository.load(NOW)).toEqual(
      transaction('authorizing', 31),
    )
    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabs.has(17)).toBe(true)
  })

  it('closes only the bound auth tab and clears state when navigation fails', async () => {
    const harness = await createHarness()
    harness.failures.add('tabs.update')

    await expect(harness.coordinator.open(transaction(), AUTHORIZE_URL)).rejects.toThrow(
      'update failure',
    )

    expect(harness.tabCalls.at(-1)).toEqual(['remove', 31])
    expect([...harness.tabs.keys()]).toEqual([17])
    expect(await harness.repository.load(NOW)).toBeNull()
  })

  it.each([
    ['create and bind', transaction('opening', null)],
    ['bind and authorizing', transaction('opening', 31)],
    ['authorizing and navigate', transaction('authorizing', 31)],
  ])('recovers a worker stop between %s from an exact bootstrap report', async (_name, stored) => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: true,
      url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
    })
    await harness.repository.save(stored)

    await expect(
      harness.coordinator.handleBootstrapReport(
        { type: 'q1travel.extensionAuth.bootstrap.v1' },
        {
          id: EXTENSION_ID,
          frameId: 0,
          origin: `chrome-extension://${EXTENSION_ID}`,
          url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
          tab: { id: 31 },
        },
      ),
    ).resolves.toBe(true)

    expect(await harness.repository.load(NOW)).toEqual(
      transaction('authorizing', 31),
    )
    expect(harness.tabs.get(31)?.url).toBe(AUTHORIZE_URL)
  })

  it.each([
    [
      'unknown message field',
      { type: 'q1travel.extensionAuth.bootstrap.v1', state: 'secret' },
      {
        id: EXTENSION_ID,
        frameId: 0,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
        tab: { id: 31 },
      },
    ],
    [
      'wrong extension id',
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
      {
        id: 'b'.repeat(32),
        frameId: 0,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
        tab: { id: 31 },
      },
    ],
    [
      'subframe',
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
      {
        id: EXTENSION_ID,
        frameId: 2,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
        tab: { id: 31 },
      },
    ],
    [
      'wrong bootstrap path',
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
      {
        id: EXTENSION_ID,
        frameId: 0,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/popup.html`,
        tab: { id: 31 },
      },
    ],
    [
      'wrong bound tab',
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
      {
        id: EXTENSION_ID,
        frameId: 0,
        origin: `chrome-extension://${EXTENSION_ID}`,
        url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
        tab: { id: 99 },
      },
    ],
  ])('rejects a bootstrap report with %s', async (_name, message, sender) => {
    const harness = await createHarness()
    await harness.repository.save(transaction('opening', 31))
    const writesBefore = harness.session.writes.length

    await expect(
      harness.coordinator.handleBootstrapReport(message, sender),
    ).resolves.toBe(false)

    expect(harness.session.writes).toHaveLength(writesBefore)
    expect(harness.tabCalls).toEqual([])
  })

  it('rejects an expired bootstrap report without deleting the recoverable tab binding', async () => {
    const harness = await createHarness()
    const stored = transaction('authorizing', 31)
    await harness.repository.save(stored)
    harness.setNow(Date.parse(stored.expiresAt))

    await expect(
      harness.coordinator.handleBootstrapReport(
        { type: 'q1travel.extensionAuth.bootstrap.v1' },
        {
          id: EXTENSION_ID,
          frameId: 0,
          origin: `chrome-extension://${EXTENSION_ID}`,
          url: `chrome-extension://${EXTENSION_ID}/${AUTHORIZATION_BOOTSTRAP_PATH}`,
          tab: { id: 31 },
        },
      ),
    ).resolves.toBe(false)

    expect(await harness.repository.loadStored()).toEqual(stored)
    expect(harness.tabCalls).toEqual([])
  })

  it('uses only the bounded bootstrap retry schedule', async () => {
    const delays: number[] = []
    let attempts = 0

    await expect(
      reportBootstrapWithRetry(
        async () => {
          attempts += 1
          return attempts === BOOTSTRAP_RETRY_DELAYS_MS.length
        },
        async (delay) => {
          delays.push(delay)
        },
      ),
    ).resolves.toBe(true)

    expect(BOOTSTRAP_RETRY_DELAYS_MS).toEqual([0, 250, 500, 1000, 2000, 4000])
    expect(delays).toEqual([250, 500, 1000, 2000, 4000])
    expect(attempts).toBe(6)
  })
})

describe('authorization tab completion and focus', () => {
  it('returns retry and keeps the exact auth tab when tabs.get transiently fails', async () => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: true,
      url: 'https://sso.example.test/intermediate',
    })
    harness.failures.add('tabs.get')

    await expect(
      harness.coordinator.complete(transaction('exchanging', 31)),
    ).resolves.toBe('retry')

    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabCalls).toEqual([['get', 31]])
  })

  it('returns retry and keeps the exact auth tab when tabs.remove fails', async () => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: false,
      url: 'https://sso.example.test/intermediate',
    })
    harness.failures.add('tabs.remove')

    await expect(
      harness.coordinator.complete(transaction('exchanging', 31)),
    ).resolves.toBe('retry')

    expect(harness.tabs.has(31)).toBe(true)
    expect(harness.tabCalls).toEqual([
      ['get', 31],
      ['remove', 31],
    ])
  })

  it('returns missing only when tabs.get confirms the exact auth tab is absent', async () => {
    const harness = await createHarness()

    await expect(
      harness.coordinator.complete(transaction('exchanging', 31)),
    ).resolves.toBe('missing')

    expect(harness.tabCalls).toEqual([['get', 31]])
    expect([...harness.tabs.keys()]).toEqual([17])
  })

  it('restores the exact source only when the auth tab is active in a focused window', async () => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: true,
      url: 'https://sso.example.test/intermediate',
    })

    await harness.coordinator.complete(transaction('exchanging', 31))

    expect(harness.tabCalls).toEqual([
      ['get', 31],
      ['get', 17],
      ['update', { tabId: 17, active: true }],
      ['remove', 31],
    ])
    expect(harness.windowCalls).toEqual([
      ['get', 9],
      ['update', { windowId: 9, focused: true }],
    ])
    expect(harness.tabs.has(31)).toBe(false)
    expect(harness.tabs.has(17)).toBe(true)
  })

  it.each([
    ['another active tab', false, true],
    ['an unfocused browser window', true, false],
  ])('only closes the auth tab after the user moved to %s', async (_name, active, focused) => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active,
      url: 'https://sso.example.test/intermediate',
    })
    harness.chrome.windows.get = async (windowId: number) => ({
      id: windowId,
      focused,
    })

    await harness.coordinator.complete(transaction('exchanging', 31))

    expect(harness.tabCalls).not.toContainEqual([
      'update',
      { tabId: 17, active: true },
    ])
    expect(harness.windowCalls).not.toContainEqual([
      'update',
      { windowId: 9, focused: true },
    ])
    expect([...harness.tabs.keys()]).toEqual([17])
  })

  it('does not focus the source window after the auth tab was moved to another window', async () => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 12,
      active: true,
      url: 'https://sso.example.test/intermediate',
    })

    await harness.coordinator.complete(transaction('exchanging', 31))

    expect(harness.tabCalls).toEqual([
      ['get', 31],
      ['remove', 31],
    ])
    expect(harness.windowCalls).toEqual([])
    expect([...harness.tabs.keys()]).toEqual([17])
  })

  it('focuses only the exact authorization tab on an explicit user action', async () => {
    const harness = await createHarness()
    harness.tabs.set(31, {
      id: 31,
      windowId: 9,
      active: false,
      url: 'https://sso.example.test/intermediate',
    })

    await expect(
      harness.coordinator.focus(transaction('authorizing', 31)),
    ).resolves.toBe('focused')

    expect(harness.tabCalls).toEqual([
      ['get', 31],
      ['update', { tabId: 31, active: true }],
    ])
    expect(harness.windowCalls).toEqual([
      ['update', { windowId: 9, focused: true }],
    ])
    expect(harness.tabs.has(17)).toBe(true)
  })
})
