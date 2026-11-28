import { AppAuthorizationError, AuthErrorCode } from '../core/types.js'
import type { ResolvedAuthConfig } from '../core/config.js'
import { parseIdentity } from '../core/identity.js'
import type { SignedFetch } from './dpop.js'
import type { TokenGrant } from './storage.js'

export type FetchPort = typeof globalThis.fetch
const invalid = () => new AppAuthorizationError(AuthErrorCode.responseInvalid)

export function resourceRequest(input: RequestInfo | URL, init: RequestInit, apiOrigin: string): Request {
  try {
    const address: string = input instanceof Request ? Reflect.get(Request.prototype, 'url', input)
      : input instanceof URL ? input.href : input
    if (typeof address !== 'string' || address.trim() !== address) throw invalid()
    const hierarchy = address.split(/[?#]/u, 1)[0]
    if (/[\x00-\x1f\\]/u.test(hierarchy) || hierarchy.split('/').some((segment) => {
      const decoded = decodeURIComponent(segment)
      return /[\\/]/u.test(decoded) || /%[0-9a-f]{2}/iu.test(decoded) || decoded === '.' || decoded === '..'
    })) throw invalid()
    const url = new URL(address)
    if (url.origin !== apiOrigin || !url.pathname.startsWith('/v1/') || url.username || url.password) throw invalid()
    const headers = new Headers(input instanceof Request ? input.headers : undefined)
    for (const [name, value] of new Headers(init.headers)) headers.set(name, value)
    if (headers.has('authorization') || headers.has('dpop')) throw invalid()
    return new Request(input instanceof Request ? input : url.href, { ...init, headers, credentials: 'omit', redirect: 'error' })
  } catch { throw new AppAuthorizationError(AuthErrorCode.requestNotAllowed) }
}

async function readJson(response: Response) {
  try { return await response.json() } catch { throw invalid() }
}

async function oauthFailure(response: Response): Promise<never> {
  const body = await response.json().catch(() => null)
  const code = body?.error
  if (code === 'invalid_dpop_proof') throw new AppAuthorizationError(AuthErrorCode.invalidDpopProof)
  if (code === 'invalid_grant') throw new AppAuthorizationError(AuthErrorCode.oauthInvalidGrant)
  if (code === 'invalid_token') throw new AppAuthorizationError(AuthErrorCode.invalidToken)
  if (response.status >= 500 || code === 'temporarily_unavailable') throw new AppAuthorizationError(AuthErrorCode.serverUnavailable)
  throw new AppAuthorizationError(AuthErrorCode.oauthInvalidRequest)
}

export function oauthClient(config: ResolvedAuthConfig, signed: SignedFetch, now: () => number) {
  const form = (url: string, fields: Record<string, string>, key: CryptoKeyPair) => signed('as', key, new Request(url, {
    method: 'POST', body: new URLSearchParams({ client_id: config.clientId, ...fields }), signal: AbortSignal.timeout(10_000),
  }))

  async function token(fields: Record<string, string>, key: CryptoKeyPair, allowed: readonly string[]): Promise<TokenGrant> {
    const issuedAt = now()
    const response = await form(config.tokenUrl, { ...fields, resource: config.resource }, key)
    if (response.status !== 200) return oauthFailure(response)
    const data = await readJson(response)
    if (!data || data.token_type !== 'DPoP' ||
      typeof data.access_token !== 'string' || !/^[\x21-\x7e]+$/u.test(data.access_token) ||
      typeof data.refresh_token !== 'string' || !/^[\x21-\x7e]+$/u.test(data.refresh_token) ||
      data.refresh_token === fields.refresh_token ||
      !Number.isSafeInteger(data.expires_in) || data.expires_in <= 0 ||
      (data.scope !== undefined && typeof data.scope !== 'string')) throw invalid()
    const expires = new Date(issuedAt + data.expires_in * 1000)
    const scopes: string[] = data.scope ? data.scope.split(' ') : []
    if (!Number.isFinite(expires.getTime()) || scopes.some((scope) => !allowed.includes(scope))) throw invalid()
    return { accessToken: data.access_token, refreshToken: data.refresh_token, expiresAt: expires.toISOString(), scopes }
  }

  return {
    exchange: (code: string, verifier: string, key: CryptoKeyPair) => token({
      grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: config.redirectUri,
    }, key, config.scopes),
    rotate: (grant: TokenGrant, key: CryptoKeyPair) => token({
      grant_type: 'refresh_token', refresh_token: grant.refreshToken,
    }, key, grant.scopes),
    async revoke(grant: TokenGrant, key: CryptoKeyPair) {
      const response = await form(config.revokeUrl, { token: grant.refreshToken, token_type_hint: 'refresh_token' }, key)
      if (response.status !== 200) await oauthFailure(response)
    },
    async identity(grant: TokenGrant, key: CryptoKeyPair, signal?: AbortSignal) {
      const response = await signed('rs', key, new Request(config.identityUrl, { signal }), grant.accessToken)
      if (response.status === 401) {
        const body = await readJson(response)
        if (body?.error?.code === 'invalid_token') throw new AppAuthorizationError(AuthErrorCode.invalidToken)
        if (body?.error?.code === 'invalid_dpop_proof') throw new AppAuthorizationError(AuthErrorCode.invalidDpopProof)
        throw invalid()
      }
      if (response.status === 403) throw new AppAuthorizationError(AuthErrorCode.forbidden)
      if (response.status >= 500) throw new AppAuthorizationError(AuthErrorCode.serverUnavailable)
      if (response.status !== 200) throw invalid()
      const identity = parseIdentity(await readJson(response))
      if (!identity || identity.scopes.some((scope) => !grant.scopes.includes(scope))) throw invalid()
      return identity
    },
  }
}

export async function isInvalidToken(response: Response): Promise<boolean> {
  if (response.status !== 401) return false
  const body = await response.clone().json().catch(() => null)
  return body?.error?.code === 'invalid_token'
}
