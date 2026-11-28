import { IDBFactory } from 'fake-indexeddb'
import { vi } from 'vitest'
import { createProofKey } from '../../src/extension/dpop.js'
import { SessionRepository, sessionNamespace, type StoredSession } from '../../src/extension/storage.js'
import { resolveAuthConfig, type AuthConfig } from '../../src/core/config.js'
import { jsonResponse } from './fakes.js'

export const installationId = 'abcdefghijklmnopabcdefghijklmnop'
export const config: AuthConfig = {
  installationId, clientId: 'test-extension', redirectUri: 'https://' + installationId + '.chromiumapp.org/callback',
  scopes: [], authOrigin: 'https://connect.example.test', apiOrigin: 'https://api.example.test',
}
export const identity = { object: 'identity', principal_type: 'user', user: 'usr_' + '0'.repeat(26),
  organization: 'org_' + '1'.repeat(26), scopes: [], store_ids: null } as const
export const grant = { access_token: 'test-access', refresh_token: 'test-refresh', token_type: 'DPoP', expires_in: 73 }

export function browserPorts(registration = config) {
  const database = new IDBFactory()
  const queues = new Map<string, Promise<void>>()
  const request = vi.fn(async (name: string, callback: () => Promise<unknown>) => {
    const pending = (queues.get(name) ?? Promise.resolve()).then(callback)
    queues.set(name, pending.then(() => undefined, () => undefined))
    return pending
  })
  const locks = { request } as unknown as LockManager
  const repository = new SessionRepository(sessionNamespace(resolveAuthConfig(registration, true)), database)
  async function seed(overrides: Partial<StoredSession> = {}) {
    const session: StoredSession = {
      accessToken: 'prior-access', refreshToken: 'prior-refresh', version: crypto.randomUUID(),
      expiresAt: '2099-01-01T00:00:00.000Z', scopes: registration.scopes, key: await createProofKey(),
      identity: { ...identity, scopes: registration.scopes }, ...overrides,
    }
    await repository.write(session)
    return session
  }
  return { database, locks, repository, seed, request }
}

// Inspect the effective fetch input, including the method and body inherited from Request.
export const inspectFetch = (handler: typeof fetch): typeof fetch => async (input, init) => {
  const request = new Request(input, init)
  return handler(request.url, {
    method: request.method, headers: request.headers, credentials: request.credentials,
    redirect: request.redirect, signal: request.signal, body: request.body && await request.text(),
  })
}

export function oauthResponse(url: RequestInfo | URL, scopes: readonly string[]) {
  if (String(url).endsWith('/revoke')) return new Response(null)
  if (String(url).endsWith('/identity')) return jsonResponse({ ...identity, scopes })
  return jsonResponse({ ...grant, ...(scopes.length ? { scope: scopes.join(' ') } : {}) })
}

export function callbackFor(url: string) {
  const authorize = new URL(url)
  const callback = new URL(authorize.searchParams.get('redirect_uri')!)
  callback.search = new URLSearchParams({ code: 'issued-code', state: authorize.searchParams.get('state')!, iss: 'https://connect.q1lx.com' }).toString()
  return callback.href
}
