import { describe, expect, it } from 'vitest'

import {
  TRANSACTION_LIFETIME_MS,
  TRANSACTION_STORAGE_KEY,
  createOpeningTransaction,
  createSessionTransactionRepository,
  type TabTransactionV1,
} from '../../src/chrome-adapter/sessionRepository'

const CREATED_AT = '2026-08-26T04:00:00.000Z'
const EXPIRES_AT = '2026-08-26T04:10:00.000Z'

const openingTransaction = (
  overrides: Partial<TabTransactionV1> = {},
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
  createdAt: CREATED_AT,
  expiresAt: EXPIRES_AT,
  phase: 'opening',
  authTabId: null,
  ...overrides,
}) as TabTransactionV1

class SessionArea {
  readonly values = new Map<string, unknown>()
  readonly accessLevels: unknown[] = []
  failNext: 'setAccessLevel' | 'get' | 'set' | 'remove' | null = null

  private fail(operation: NonNullable<SessionArea['failNext']>): void {
    if (this.failNext !== operation) return
    this.failNext = null
    throw new Error(`controlled ${operation} failure`)
  }

  async setAccessLevel(value: unknown): Promise<void> {
    this.fail('setAccessLevel')
    this.accessLevels.push(structuredClone(value))
  }

  async get(key: string): Promise<Record<string, unknown>> {
    this.fail('get')
    return this.values.has(key)
      ? { [key]: structuredClone(this.values.get(key)) }
      : {}
  }

  async set(values: Record<string, unknown>): Promise<void> {
    this.fail('set')
    for (const [key, value] of Object.entries(values)) {
      this.values.set(key, structuredClone(value))
    }
  }

  async remove(key: string): Promise<void> {
    this.fail('remove')
    this.values.delete(key)
  }
}

const createHarness = () => {
  const session = new SessionArea()
  let localCalls = 0
  const storage = {
    session,
    local: {
      async get() {
        localCalls += 1
        throw new Error('local storage must never be read')
      },
      async set() {
        localCalls += 1
        throw new Error('local storage must never be written')
      },
      async remove() {
        localCalls += 1
        throw new Error('local storage must never be cleared')
      },
    },
  }
  const repository = createSessionTransactionRepository(storage)
  return { repository, session, localCalls: () => localCalls }
}

describe('sealed Chrome transaction repository', () => {
  it('creates an opening transaction with an absolute ten-minute lifetime', () => {
    const transaction = createOpeningTransaction({
      transactionId: 'transaction-id',
      clientId: 'browser-client-v2',
      redirectUri:
        'https://web.example.test/apps/extension-auth/callback/client-v2',
      prepared: {
        state: 's'.repeat(43),
        codeVerifier: 'v'.repeat(43),
        authorizeUrl:
          'https://accounts.example.test/app-authorizations/v1/authorize',
      },
      sourceTabId: 17,
      sourceWindowId: 9,
      now: Date.parse(CREATED_AT),
    })

    expect(TRANSACTION_LIFETIME_MS).toBe(600_000)
    expect(transaction).toEqual(openingTransaction())
    expect(JSON.stringify(transaction)).not.toContain('authorizeUrl')
  })

  it('restricts session storage before accepting reads or writes and never falls back to local storage', async () => {
    const harness = createHarness()

    await harness.repository.ready()
    await harness.repository.save(openingTransaction())
    await expect(
      harness.repository.load(Date.parse(CREATED_AT) + 1),
    ).resolves.toEqual(openingTransaction())

    expect(harness.session.accessLevels).toEqual([
      { accessLevel: 'TRUSTED_CONTEXTS' },
    ])
    expect(harness.localCalls()).toBe(0)
  })

  it('rejects an unknown transaction field instead of persisting an authorization code', async () => {
    const harness = createHarness()
    await harness.repository.ready()
    const untrusted = {
      ...openingTransaction(),
      code: 'authorization-code-must-not-persist',
    }

    await expect(harness.repository.save(untrusted)).rejects.toThrow()
    expect(harness.session.values.size).toBe(0)
    expect(harness.localCalls()).toBe(0)
  })

  it.each([
    ['an unknown field', { ...openingTransaction(), unexpected: true }],
    [
      'the wrong version',
      { ...openingTransaction(), version: 2 },
    ],
    [
      'an authorizing transaction without a bound tab',
      { ...openingTransaction(), phase: 'authorizing', authTabId: null },
    ],
    [
      'an exchanging transaction without a bound tab',
      { ...openingTransaction(), phase: 'exchanging', authTabId: null },
    ],
    [
      'a lifetime longer than ten minutes',
      {
        ...openingTransaction(),
        expiresAt: '2026-08-26T04:10:00.001Z',
      },
    ],
  ])('clears %s on load', async (_name, stored) => {
    const harness = createHarness()
    await harness.repository.ready()
    harness.session.values.set(TRANSACTION_STORAGE_KEY, stored)

    await expect(
      harness.repository.load(Date.parse(CREATED_AT) + 1),
    ).resolves.toBeNull()
    expect(harness.session.values.has(TRANSACTION_STORAGE_KEY)).toBe(false)
    expect(harness.localCalls()).toBe(0)
  })

  it('expires exactly at the absolute deadline and clears the record', async () => {
    const harness = createHarness()
    await harness.repository.ready()
    harness.session.values.set(
      TRANSACTION_STORAGE_KEY,
      openingTransaction(),
    )

    await expect(
      harness.repository.load(Date.parse(EXPIRES_AT)),
    ).resolves.toBeNull()
    expect(harness.session.values.has(TRANSACTION_STORAGE_KEY)).toBe(false)
  })

  it.each(['setAccessLevel', 'get', 'set', 'remove'] as const)(
    'propagates a session %s failure without touching local storage',
    async (operation) => {
      const harness = createHarness()
      if (operation === 'setAccessLevel') {
        harness.session.failNext = operation
        await expect(harness.repository.ready()).rejects.toThrow(
          'controlled setAccessLevel failure',
        )
      } else {
        await harness.repository.ready()
        harness.session.failNext = operation
        if (operation === 'get') {
          await expect(
            harness.repository.load(Date.parse(CREATED_AT) + 1),
          ).rejects.toThrow('controlled get failure')
        } else if (operation === 'set') {
          await expect(
            harness.repository.save(openingTransaction()),
          ).rejects.toThrow('controlled set failure')
        } else {
          await expect(harness.repository.remove()).rejects.toThrow(
            'controlled remove failure',
          )
        }
      }

      expect(harness.localCalls()).toBe(0)
    },
  )
})
