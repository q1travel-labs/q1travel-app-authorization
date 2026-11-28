import { encodeBase64Url } from '../core/pkce.js'
import { AppAuthorizationError, AuthErrorCode } from '../core/types.js'

export const createProofKey = (): Promise<CryptoKeyPair> =>
  crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])

const utf8 = new TextEncoder()
const encode = (object: object) => encodeBase64Url(utf8.encode(JSON.stringify(object)))

async function proof(key: CryptoKeyPair, url: string, method: string, time: number, nonce?: string, token?: string) {
  const target = new URL(url)
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', key.publicKey)
  const header = encode({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty, crv, x, y } })
  const claims = encode({
    htm: method, htu: target.origin + target.pathname, iat: Math.floor(time / 1000),
    jti: crypto.randomUUID(), nonce,
    ath: token && encodeBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(token)))),
  })
  const input = header + '.' + claims
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, utf8.encode(input))
  return input + '.' + encodeBase64Url(new Uint8Array(signature))
}

async function challenged(response: Response, server: 'as' | 'rs'): Promise<boolean> {
  if (server === 'as') {
    if (response.status !== 400) return false
    const body = await response.clone().json().catch(() => null)
    return body?.error === 'use_dpop_nonce'
  }
  const challenge = response.headers.get('WWW-Authenticate') ?? ''
  return response.status === 401 && /^DPoP\s/i.test(challenge) &&
    /(?:^DPoP\s+|,\s*)error\s*=\s*"use_dpop_nonce"(?:\s*,|\s*$)/i.test(challenge)
}

export function createSignedFetch(fetch: typeof globalThis.fetch, now: () => number) {
  const nonces: Partial<Record<'as' | 'rs', string>> = {}
  return async (server: 'as' | 'rs', key: CryptoKeyPair, request: Request, accessToken?: string): Promise<Response> => {
    for (let attempt = 0; ; attempt++) {
      const headers = new Headers(request.headers)
      headers.set('DPoP', await proof(key, request.url, request.method, now(), nonces[server], accessToken))
      if (accessToken) headers.set('Authorization', 'DPoP ' + accessToken)
      let response: Response
      try {
        response = await fetch(request.clone(), { headers, credentials: 'omit', redirect: 'error', cache: 'no-store' })
      } catch {
        throw new AppAuthorizationError(AuthErrorCode.networkUnavailable)
      }
      const nonce = response.headers.get('DPoP-Nonce')
      if (nonce) nonces[server] = nonce
      if (!await challenged(response, server)) return response
      void response.body?.cancel().catch(() => undefined)
      if (!nonce || attempt > 0) throw new AppAuthorizationError(AuthErrorCode.nonceChallenge)
    }
  }
}

export type SignedFetch = ReturnType<typeof createSignedFetch>
