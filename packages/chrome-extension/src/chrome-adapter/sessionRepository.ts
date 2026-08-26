import type { PreparedAuthorization } from '../core/contracts.js'
import type { ChromeStoragePort } from './ports.js'

export const TRANSACTION_LIFETIME_MS = 600_000
export const TRANSACTION_STORAGE_KEY =
  'q1travel.appAuthorization.tabTransaction.v1'

interface TransactionBase {
  version: 1
  transactionId: string
  clientId: string
  redirectUri: string
  state: string
  codeVerifier: string
  sourceTabId: number
  sourceWindowId: number
  createdAt: string
  expiresAt: string
}

export type TabTransactionV1 =
  | (TransactionBase & {
      phase: 'opening'
      authTabId: null | number
    })
  | (TransactionBase & {
      phase: 'authorizing' | 'exchanging'
      authTabId: number
    })

export interface CreateOpeningTransactionInput {
  transactionId: string
  clientId: string
  redirectUri: string
  prepared: PreparedAuthorization
  sourceTabId: number
  sourceWindowId: number
  now: number
}

export interface SessionTransactionRepository {
  ready(): Promise<void>
  load(now: number): Promise<TabTransactionV1 | null>
  loadStored(): Promise<TabTransactionV1 | null>
  save(transaction: unknown): Promise<void>
  remove(): Promise<void>
}

const TRANSACTION_KEYS = [
  'version',
  'transactionId',
  'clientId',
  'redirectUri',
  'state',
  'codeVerifier',
  'sourceTabId',
  'sourceWindowId',
  'createdAt',
  'expiresAt',
  'phase',
  'authTabId',
] as const

const BASE64URL_32_BYTE_PATTERN = /^[A-Za-z0-9_-]{43}$/u

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (value: Record<string, unknown>): boolean => {
  const keys = Object.keys(value)
  return (
    keys.length === TRANSACTION_KEYS.length &&
    TRANSACTION_KEYS.every((key) =>
      Object.prototype.hasOwnProperty.call(value, key),
    )
  )
}

const isTabId = (value: unknown): value is number =>
  Number.isInteger(value) && typeof value === 'number' && value >= 0

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.trim() === value

const parseTransaction = (value: unknown): TabTransactionV1 | null => {
  if (!isRecord(value) || !hasExactKeys(value)) return null

  const createdAt =
    typeof value.createdAt === 'string' ? Date.parse(value.createdAt) : NaN
  const expiresAt =
    typeof value.expiresAt === 'string' ? Date.parse(value.expiresAt) : NaN
  if (
    value.version !== 1 ||
    !isNonEmptyString(value.transactionId) ||
    !isNonEmptyString(value.clientId) ||
    !isNonEmptyString(value.redirectUri) ||
    typeof value.state !== 'string' ||
    !BASE64URL_32_BYTE_PATTERN.test(value.state) ||
    typeof value.codeVerifier !== 'string' ||
    !BASE64URL_32_BYTE_PATTERN.test(value.codeVerifier) ||
    !isTabId(value.sourceTabId) ||
    !isTabId(value.sourceWindowId) ||
    !Number.isFinite(createdAt) ||
    !Number.isFinite(expiresAt) ||
    expiresAt - createdAt !== TRANSACTION_LIFETIME_MS
  ) {
    return null
  }

  if (
    value.phase === 'opening' &&
    (value.authTabId === null || isTabId(value.authTabId))
  ) {
    return value as unknown as TabTransactionV1
  }
  if (
    (value.phase === 'authorizing' || value.phase === 'exchanging') &&
    isTabId(value.authTabId)
  ) {
    return value as unknown as TabTransactionV1
  }
  return null
}

export const createOpeningTransaction = (
  input: CreateOpeningTransactionInput,
): TabTransactionV1 => {
  const createdAt = new Date(input.now).toISOString()
  return {
    version: 1,
    transactionId: input.transactionId,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    state: input.prepared.state,
    codeVerifier: input.prepared.codeVerifier,
    sourceTabId: input.sourceTabId,
    sourceWindowId: input.sourceWindowId,
    createdAt,
    expiresAt: new Date(input.now + TRANSACTION_LIFETIME_MS).toISOString(),
    phase: 'opening',
    authTabId: null,
  }
}

export const createSessionTransactionRepository = (
  storage: ChromeStoragePort,
): SessionTransactionRepository => {
  let readiness: Promise<void> | null = null
  const ready = (): Promise<void> => {
    readiness ??= storage.session.setAccessLevel({
      accessLevel: 'TRUSTED_CONTEXTS',
    })
    return readiness
  }
  const loadStored = async (): Promise<TabTransactionV1 | null> => {
    await ready()
    const stored = (await storage.session.get(TRANSACTION_STORAGE_KEY))[
      TRANSACTION_STORAGE_KEY
    ]
    if (stored === undefined) return null
    const transaction = parseTransaction(stored)
    if (transaction === null) {
      await storage.session.remove(TRANSACTION_STORAGE_KEY)
      return null
    }
    return transaction
  }

  return {
    ready,
    loadStored,
    async load(now) {
      const transaction = await loadStored()
      if (transaction === null) return null
      if (!Number.isFinite(now) || Date.parse(transaction.expiresAt) <= now) {
        await storage.session.remove(TRANSACTION_STORAGE_KEY)
        return null
      }
      return transaction
    },
    async save(value) {
      await ready()
      const transaction = parseTransaction(value)
      if (transaction === null) throw new Error('Invalid tab transaction')
      await storage.session.set({
        [TRANSACTION_STORAGE_KEY]: transaction,
      })
    },
    async remove() {
      await ready()
      await storage.session.remove(TRANSACTION_STORAGE_KEY)
    },
  }
}
