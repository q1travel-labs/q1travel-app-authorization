import type { AuthIdentity } from '../core/types.js'
import { AppAuthorizationError, AuthErrorCode } from '../core/types.js'

export interface StoredTransaction {
  readonly state: string
  readonly codeVerifier: string
  readonly authorizationContextToken?: string
}

export interface TokenGrant {
  readonly accessToken: string
  readonly refreshToken: string
  readonly expiresAt: string
  readonly scopes: readonly string[]
}

export interface StoredSession extends TokenGrant {
  readonly key: CryptoKeyPair
  readonly version: string
  readonly identity: AuthIdentity
}

export type SessionRecord = StoredSession | { readonly rotating: true; readonly version: string }
const unavailable = () => new AppAuthorizationError(AuthErrorCode.storageUnavailable)

export class SessionRepository {
  constructor(readonly name: string, private readonly database: IDBFactory) {}

  private async transaction<T>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    try {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const open = this.database.open('q1travel.oauth', 1)
        open.onupgradeneeded = () => open.result.createObjectStore('sessions')
        open.onsuccess = () => resolve(open.result)
        open.onerror = () => reject(unavailable())
      })
      try {
        return await new Promise<T>((resolve, reject) => {
          const tx = db.transaction('sessions', mode, { durability: 'strict' })
          tx.onabort = () => reject(unavailable())
          const request = operation(tx.objectStore('sessions'))
          tx.oncomplete = () => resolve(request.result)
        })
      } finally { db.close() }
    } catch { throw unavailable() }
  }

  read(): Promise<SessionRecord | undefined> {
    return this.transaction('readonly', (store) => store.get(this.name))
  }
  write(record: SessionRecord): Promise<IDBValidKey> {
    return this.transaction('readwrite', (store) => store.put(record, this.name))
  }
  clear(): Promise<undefined> {
    return this.transaction('readwrite', (store) => store.delete(this.name))
  }
}
