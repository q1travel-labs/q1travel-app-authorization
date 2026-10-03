import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { validateAuthorizationCallback } from '../src/core/callback.js'
import { createAuthorizationRequest } from '../src/core/pkce.js'
import { resolveAuthConfig } from '../src/core/config.js'

const bytes = Uint8Array.from({ length: 32 }, (_, index) => index)
const cryptoPort = {
  randomBytes: () => bytes,
  sha256: async (value: Uint8Array) =>
    Uint8Array.from(createHash('sha256').update(value).digest()),
}

const authConfig = {
  clientId: 'extension-client',
  redirectUri: 'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/callback',
  scopes: ['orders:read'],
  apiOrigin: 'http://127.0.0.1:3011',
  allowInsecureLoopback: true,
} as const

describe('authorization configuration', () => {
  it.each(['', '/'])('normalizes root pathPrefix %j to unprefixed endpoints', (pathPrefix) => {
    expect(resolveAuthConfig({ ...authConfig, pathPrefix })).toMatchObject({
      authorizeUrl: 'http://127.0.0.1:3011/app-authorizations/v1/authorize',
      tokenUrl: 'http://127.0.0.1:3011/app-authorizations/v1/token',
      revokeUrl: 'http://127.0.0.1:3011/app-authorizations/v1/revoke',
      sessionUrl: 'http://127.0.0.1:3011/app-authorizations/v1/session',
    })
  })

  it.each([
    'api',
    '/api/',
    '/api/../admin',
    '/api?debug=true',
    '/api#debug',
  ])('still rejects unsafe pathPrefix %j', (pathPrefix) => {
    expect(() => resolveAuthConfig({ ...authConfig, pathPrefix })).toThrowError(
      expect.objectContaining({ code: 'configuration_invalid' }),
    )
  })
})

describe('PKCE authorization request', () => {
  it('uses a 43-character URL-safe verifier and an S256 challenge', async () => {
    const request = await createAuthorizationRequest(
      {
        authorizeUrl: 'https://accounts.example.com/api/app-authorizations/v1/authorize',
        clientId: 'extension-client',
        redirectUri: 'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/callback',
        scopes: ['orders:read', 'orders:write'],
      },
      cryptoPort,
    )

    expect(request.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(request.state).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    const url = new URL(request.authorizationUrl)
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('code_challenge')).toBe(
      '6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A',
    )
    expect(url.searchParams.get('scope')).toBe('orders:read orders:write')
  })
})

describe('authorization callback validation', () => {
  const redirectUri =
    'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/callback'
  const state = 's'.repeat(43)

  it('rejects a callback with a different state', () => {
    expect(() =>
      validateAuthorizationCallback(
        `${redirectUri}?code=${'c'.repeat(43)}&state=${'x'.repeat(43)}`,
        redirectUri,
        state,
      ),
    ).toThrowError(expect.objectContaining({ code: 'state_mismatch' }))
  })

  it.each([
    `https://other.example.com/callback?code=${'c'.repeat(43)}&state=${state}`,
    `https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/other?code=${'c'.repeat(43)}&state=${state}`,
  ])('rejects a callback outside the exact redirect origin and path', (callback) => {
    expect(() =>
      validateAuthorizationCallback(callback, redirectUri, state),
    ).toThrowError(expect.objectContaining({ code: 'invalid_callback' }))
  })
})
