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
  authOrigin: 'http://localhost:3012',
  apiOrigin: 'http://127.0.0.1:3011',
  allowInsecureLoopback: true,
} as const

describe('authorization configuration', () => {
  it('requires distinct explicit origins for protocol and resource requests', () => {
    for (const field of ['authOrigin', 'apiOrigin'] as const) {
      for (const invalid of [undefined, '', 'https://example.test/path', 'https://example.test/',
        'https://user@example.test', 'https://example.test?q=1', 'https://example.test#x',
        'ftp://localhost', 'http://outside.test']) {
        expect(() => resolveAuthConfig({ ...authConfig, [field]: invalid })).toThrowError(
          expect.objectContaining({ code: 'configuration_invalid' }),
        )
      }
      expect(() => resolveAuthConfig({
        ...authConfig, authOrigin: 'https://connect.example.test', apiOrigin: 'https://api.example.test',
        [field]: 'http://localhost:3011', allowInsecureLoopback: false,
      })).toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
    }
    expect(() => resolveAuthConfig({ ...authConfig, authOrigin: authConfig.apiOrigin }))
      .toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
  })

  it.each(['authOrigin', 'apiOrigin'] as const)('rejects equivalent hosts for %s', (field) => {
    for (const host of ['api.example.test', 'api.example.test.', 'API.EXAMPLE.TEST', 'api.example.test:443']) {
      expect(() => resolveAuthConfig({
        ...authConfig, authOrigin: 'https://api.example.test', apiOrigin: 'https://api.example.test',
        [field]: 'https://' + host,
      })).toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
    }
    expect(() => resolveAuthConfig({ ...authConfig, [field]: 'https://distinct.example.test.' }))
      .toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
  })

  it('rejects a trailing dot on the registered web callback host', () => {
    expect(() => resolveAuthConfig({ ...authConfig, redirectUri: 'https://web.example.test./callback' }, true))
      .toThrowError(expect.objectContaining({ code: 'configuration_invalid' }))
  })

  it.each(['', '/'])('normalizes root pathPrefix %j to unprefixed endpoints', (pathPrefix) => {
    expect(resolveAuthConfig({ ...authConfig, pathPrefix })).toMatchObject({
      contextsUrl: 'http://localhost:3012/app-authorizations/v1/contexts',
      authorizeUrl: 'http://localhost:3012/app-authorizations/v1/authorize',
      tokenUrl: 'http://localhost:3012/app-authorizations/v1/token',
      revokeUrl: 'http://localhost:3012/app-authorizations/v1/revoke',
      sessionUrl: 'http://localhost:3012/app-authorizations/v1/session',
    })
  })

  it.each([
    'api',
    '/api/',
    '/api/../admin',
    '/./api',
    '/api/./admin',
    '/api/.',
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
    expect(request.codeChallenge).toBe('6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A')
    expect(request.codeChallenge).toBe(url.searchParams.get('code_challenge'))
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

describe('公开 OAuth 一致性', () => {
  it('Given 零 scope 登记 / When 生成请求 / Then 使用精确 resource 与授权码模式', async () => {
    const config = resolveAuthConfig({ ...authConfig, scopes: [] })
    const { authorizationUrl } = await createAuthorizationRequest(config, cryptoPort)
    const url = new URL(authorizationUrl)
    expect(url.origin + url.pathname).toBe(authConfig.authOrigin + '/oauth/authorize')
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('resource')).toBe(authConfig.apiOrigin + '/v1')
    expect(url.searchParams.has('scope')).toBe(false)
  })

  it('Given 已登记 issuer / When 接收带 iss 的成功回调 / Then 返回不透明授权码', () => {
    const state = 's'.repeat(43)
    const callback = new URL(authConfig.redirectUri)
    callback.search = new URLSearchParams({ code: 'issued-code', state, iss: authConfig.authOrigin }).toString()
    expect(validateAuthorizationCallback(callback.href, authConfig.redirectUri, state, authConfig.authOrigin)).toBe('issued-code')
  })
})
