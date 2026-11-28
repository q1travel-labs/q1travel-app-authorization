import { parseIdentity } from '../core/identity.js'
import { AppAuthorizationError, AuthErrorCode, type AuthSession } from '../core/types.js'
import type { oauthClient } from './http.js'
import { SessionRepository, type SessionRecord, type StoredSession } from './storage.js'

export const publicSession = (stored?: StoredSession): AuthSession => stored ? {
  status: 'authenticated', expiresAt: stored.expiresAt, identity: structuredClone(stored.identity),
} : { status: 'signed-out' }

export function createSessions(repository: SessionRepository, locks: LockManager,
  oauth: ReturnType<typeof oauthClient>, now: () => number, publish: (session: AuthSession) => void) {
  const locked = async <T>(fn: () => Promise<T>): Promise<T> => await locks.request('q1travel.oauth:' + repository.name, fn)
  const renewals = new Map<string, Promise<StoredSession | undefined>>()

  async function clear() {
    await repository.clear()
    publish(publicSession())
  }

  async function usable(record: SessionRecord | undefined) {
    if (!record) return undefined
    if ('rotating' in record || !record.key?.privateKey || !record.key.publicKey ||
      record.key.privateKey.extractable || !parseIdentity(record.identity) || !Number.isFinite(Date.parse(record.expiresAt))) {
      await clear()
      return undefined
    }
    return record
  }

  async function rotate(previous: StoredSession) {
    // Commit the claim without a usable refresh token before the first network write.
    await repository.write({ rotating: true, version: previous.version })
    try {
      const grant = await oauth.rotate(previous, previous.key)
      const next = { ...previous, ...grant, version: crypto.randomUUID(),
        identity: { ...previous.identity, scopes: previous.identity.scopes.filter((scope) => grant.scopes.includes(scope)) } }
      await repository.write(next)
      publish(publicSession(next))
      return next
    } catch (error) {
      // Even if deleting the claim fails, a restarted worker cannot replay the spent token.
      await clear()
      if (error instanceof AppAuthorizationError &&
        [AuthErrorCode.nonceChallenge, AuthErrorCode.oauthInvalidGrant].some((code) => code === error.code)) throw error
      throw new AppAuthorizationError(AuthErrorCode.reauthorizationRequired)
    }
  }

  async function current(force = false) {
    const observed = await repository.read()
    if (!observed) return undefined
    const existing = renewals.get(observed.version)
    if (existing) return existing
    const renew = force || 'rotating' in observed || Date.parse(observed.expiresAt) <= now()
    const operation = locked(async () => {
      const latest = await usable(await repository.read())
      if (!latest || latest.version !== observed.version || !renew) return latest
      return rotate(latest)
    })
    if (!renew) return operation
    renewals.set(observed.version, operation)
    try { return await operation } finally { renewals.delete(observed.version) }
  }

  return {
    current,
    async commit(session: StoredSession, assertCurrent: () => void) {
      await locked(async () => {
        assertCurrent()
        await repository.write(session)
        try { assertCurrent() } catch (error) { await clear(); throw error }
        publish(publicSession(session))
      })
    },
    async discard(version: string) {
      return locked(async () => {
        const latest = await usable(await repository.read())
        if (latest?.version !== version) return latest
        await clear()
        return undefined
      })
    },
    async identity(signal?: AbortSignal): Promise<AuthSession> {
      const session = await current()
      if (!session) return publicSession()
      try {
        const identity = await oauth.identity(session, session.key, signal)
        return await locked(async () => {
          const latest = await usable(await repository.read())
          if (latest?.version !== session.version) return publicSession(latest)
          const updated = { ...latest, identity }
          if (JSON.stringify(identity) !== JSON.stringify(latest.identity)) {
            await repository.write(updated)
            publish(publicSession(updated))
          }
          return publicSession(updated)
        })
      } catch (error) {
        if (error instanceof AppAuthorizationError && error.code === AuthErrorCode.invalidToken) {
          return publicSession(await this.discard(session.version))
        }
        throw error
      }
    },
    async logout() {
      await locked(async () => {
        let current: StoredSession | undefined
        try { current = await usable(await repository.read()) }
        catch (error) { await clear(); throw error }
        if (current) {
          try { await oauth.revoke(current, current.key) }
          catch { throw new AppAuthorizationError(AuthErrorCode.revocationUnconfirmed) }
          finally { await clear() }
        }
      })
      return publicSession()
    },
  }
}
