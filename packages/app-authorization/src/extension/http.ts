import {
  AppAuthorizationError,
  AuthErrorCode,
} from '../core/types.js'
import type { ResolvedAuthConfig } from '../core/config.js'
import type { StoredSession } from './storage.js'

export type FetchPort = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>

// Inspect the original hierarchy before URL parsing can discard separators or dot segments.
const hasAmbiguousPath = (address: string): boolean => {
  const [hierarchy] = address.split(/[?#]/u, 1)
  if (address.trim() !== address || /[\u0000-\u001f\\]/u.test(hierarchy)) return true
  return hierarchy.split('/').some((segment) => {
    if (!segment.includes('%')) return false
    const decoded = decodeURIComponent(segment)
    return /[\\/]/u.test(decoded) || /%[\da-f]{2}/iu.test(decoded) ||
      decoded === '.' || decoded === '..'
  })
}

export const resourceFetchTarget = (
  input: RequestInfo | URL,
  apiOrigin: string,
  reservedPaths: ReadonlySet<string>,
): string | Request => {
  // Fetch uses the Request's internal URL even when an instance shadows its url getter.
  try {
    const address: string = input instanceof Request
      ? Reflect.get(Request.prototype, 'url', input)
      : input instanceof URL ? input.href : input
    if (typeof address !== 'string') throw new TypeError()
    const url = new URL(address)
    if (url.origin === apiOrigin && url.protocol === new URL(apiOrigin).protocol &&
      !url.username && !url.password && !hasAmbiguousPath(address)) {
      const path = decodeURIComponent(url.pathname).replace(/\/{2,}/gu, '/').replace(/\/$/u, '').toLowerCase()
      if (!reservedPaths.has(path)) return input instanceof Request ? input : url.href
    }
  } catch {
    // Invalid URLs and malformed percent escapes are denied before the session is read.
  }
  throw new AppAuthorizationError(AuthErrorCode.requestNotAllowed)
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
const hasExactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const keys = Object.keys(value)
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

const readJson = async (response: Response): Promise<unknown> => {
  try {
    return await response.json()
  } catch {
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
}

const oauthFailure = async (response: Response): Promise<never> => {
  let error: unknown
  try {
    const body = await response.json()
    error = isRecord(body) ? body.error : undefined
  } catch {
    error = undefined
  }
  if (error === 'invalid_grant') {
    throw new AppAuthorizationError(AuthErrorCode.oauthInvalidGrant)
  }
  if (error === 'invalid_token') {
    throw new AppAuthorizationError(AuthErrorCode.invalidToken)
  }
  if (response.status >= 500 || error === 'temporarily_unavailable' || error === 'server_error') {
    throw new AppAuthorizationError(AuthErrorCode.serverUnavailable)
  }
  throw new AppAuthorizationError(AuthErrorCode.oauthInvalidRequest)
}

const request = async (
  fetch: FetchPort,
  input: string,
  init: RequestInit,
): Promise<Response> => {
  try {
    return await fetch(input, { ...init, redirect: 'error' })
  } catch {
    throw new AppAuthorizationError(AuthErrorCode.networkUnavailable)
  }
}

export const exchangeAuthorizationCode = async (
  fetch: FetchPort,
  config: ResolvedAuthConfig,
  code: string,
  codeVerifier: string,
  now: number,
): Promise<StoredSession> => {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier,
  })
  const response = await request(fetch, config.tokenUrl, {
    method: 'POST',
    credentials: 'omit',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (response.status !== 200) return await oauthFailure(response)
  const value = await readJson(response)
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['access_token', 'token_type', 'expires_in', 'scope']) ||
    typeof value.access_token !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(value.access_token) ||
    value.token_type !== 'Bearer' ||
    value.expires_in !== 28_800 ||
    typeof value.scope !== 'string'
  ) {
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
  const scopes = value.scope === '' ? [] : value.scope.split(' ')
  if (scopes.some((scope) => !config.scopes.includes(scope))) {
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
  return {
    accessToken: value.access_token,
    tokenType: 'Bearer',
    expiresAt: new Date(now + 28_800_000).toISOString(),
    scopes,
  }
}

export const revokeSession = async (
  fetch: FetchPort,
  config: ResolvedAuthConfig,
  token: string,
): Promise<void> => {
  const response = await request(fetch, config.revokeUrl, {
    method: 'POST',
    credentials: 'omit',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      token,
      token_type_hint: 'access_token',
    }),
  })
  if (!response.ok) await oauthFailure(response)
}

export const verifyRemoteSession = async (
  fetch: FetchPort,
  config: ResolvedAuthConfig,
  token: string,
  signal?: AbortSignal,
): Promise<{ expiresAt: string; scopes: readonly string[] }> => {
  const response = await request(fetch, config.sessionUrl, {
    method: 'GET',
    credentials: 'omit',
    headers: { authorization: `Bearer ${token}` },
    signal,
  })
  if (!response.ok) await oauthFailure(response)
  const value = await readJson(response)
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['active', 'expires_at', 'scope']) ||
    value.active !== true ||
    typeof value.expires_at !== 'string' ||
    !Array.isArray(value.scope) ||
    value.scope.some(
      (scope) => typeof scope !== 'string' || !config.scopes.includes(scope),
    )
  ) {
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
  const expiresAt = Date.parse(value.expires_at)
  if (!Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== value.expires_at) {
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
  return { expiresAt: value.expires_at, scopes: value.scope }
}
