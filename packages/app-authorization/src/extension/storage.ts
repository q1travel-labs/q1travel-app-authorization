import { AppAuthorizationError, AuthErrorCode } from '../core/types.js'
import type { SessionStoragePort } from './ports.js'

export const SESSION_STORAGE_KEY = 'q1travel.appAuthorization.session.v1'
export const TRANSACTION_STORAGE_KEY = 'q1travel.appAuthorization.transaction.v1'

export interface StoredSession {
  readonly accessToken: string
  readonly tokenType: 'Bearer'
  readonly expiresAt: string
  readonly scopes: readonly string[]
}

export interface StoredTransaction {
  readonly state: string
  readonly codeVerifier: string
}

const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{43}$/u
const SCOPE_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/u
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const keys = Object.keys(value)
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

const isStoredSession = (value: unknown): value is StoredSession => {
  if (!isRecord(value) || !hasExactKeys(value, ['accessToken', 'tokenType', 'expiresAt', 'scopes'])) {
    return false
  }
  if (
    typeof value.accessToken !== 'string' ||
    !OPAQUE_PATTERN.test(value.accessToken) ||
    value.tokenType !== 'Bearer' ||
    typeof value.expiresAt !== 'string' ||
    !Array.isArray(value.scopes) ||
    value.scopes.some((scope) => typeof scope !== 'string' || !SCOPE_PATTERN.test(scope))
  ) {
    return false
  }
  const expiresAt = Date.parse(value.expiresAt)
  return Number.isFinite(expiresAt) && new Date(expiresAt).toISOString() === value.expiresAt
}

export class SessionRepository {
  readonly ready: Promise<void>

  constructor(private readonly storage: SessionStoragePort) {
    this.ready = storage
      .setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
      .catch(() => { throw new AppAuthorizationError(AuthErrorCode.storageUnavailable) })
  }

  async read(): Promise<StoredSession | null> {
    await this.ready
    try {
      const value = (await this.storage.get(SESSION_STORAGE_KEY))[SESSION_STORAGE_KEY]
      if (value === undefined) return null
      if (!isStoredSession(value)) {
        await this.storage.remove(SESSION_STORAGE_KEY)
        return null
      }
      return structuredClone(value)
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
  }
}
  async write(session: StoredSession): Promise<void> {
    await this.ready
    try {
      await this.storage.set({ [SESSION_STORAGE_KEY]: structuredClone(session) })
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
    }
  }

  async writeTransaction(transaction: StoredTransaction): Promise<void> {
    await this.ready
    try {
      await this.storage.set({ [TRANSACTION_STORAGE_KEY]: structuredClone(transaction) })
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
    }
  }

  async clearTransaction(): Promise<void> {
    await this.ready
    try {
      await this.storage.remove(TRANSACTION_STORAGE_KEY)
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
    }
  }

  async clearSession(): Promise<void> {
    await this.ready
    try {
      await this.storage.remove(SESSION_STORAGE_KEY)
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
    }
  }

  async clear(): Promise<void> {
    await this.ready
    try {
      await this.storage.remove([SESSION_STORAGE_KEY, TRANSACTION_STORAGE_KEY])
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
    }
  }
}
