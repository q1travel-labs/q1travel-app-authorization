import { createHash } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { createProofKey, createSignedFetch } from '../src/extension/dpop.js'
import { createAuthRuntimeWithDependencies } from '../src/extension/runtime.js'
import { AppAuthorizationError, AuthErrorCode } from '../src/core/types.js'
import errors from '../fixtures/errors.json'
import { createChromePort, jsonResponse } from './helpers/fakes.js'
import { browserPorts, callbackFor, config, grant, identity, inspectFetch } from './helpers/oauth.js'

function challenge(server: 'as' | 'rs', nonce: string) {
  return server === 'as' ? Response.json({ error: 'use_dpop_nonce' }, { status: 400, headers: { 'DPoP-Nonce': nonce } })
    : Response.json({ error: { code: 'use_dpop_nonce' } }, { status: 401, headers: {
      'DPoP-Nonce': nonce, 'WWW-Authenticate': 'DPoP algs="ES256", error="use_dpop_nonce"',
    } })
}

async function verifiedClaims(init: RequestInit | undefined) {
  const jwt = new Headers(init?.headers).get('DPoP')!
  const [header, payload, signature] = jwt.split('.')
  const jose = JSON.parse(Buffer.from(header, 'base64url').toString())
  expect(jose).toEqual({ typ: 'dpop+jwt', alg: 'ES256', jwk: {
    kty: 'EC', crv: 'P-256', x: expect.any(String), y: expect.any(String),
  } })
  const key = await crypto.subtle.importKey('jwk', jose.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
    Uint8Array.from(Buffer.from(signature, 'base64url')), new TextEncoder().encode(header + '.' + payload))).toBe(true)
  return JSON.parse(Buffer.from(payload, 'base64url').toString())
}

describe('DPoP', () => {
  it('Given AS 与 RS 分别挑战 / When 换码、回读、业务写和撤销 / Then 证明逐个可验且 nonce 隔离', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(challenge('as', 'as-1')).mockResolvedValueOnce(jsonResponse(grant))
      .mockResolvedValueOnce(challenge('rs', 'rs-1')).mockResolvedValueOnce(jsonResponse(identity))
      .mockResolvedValueOnce(challenge('rs', 'rs-2')).mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(new Response(null))
    const runtime = createAuthRuntimeWithDependencies(config, {
      ...browserPorts(), chrome: createChromePort().chrome, fetch: inspectFetch(fetch),
      now: () => 1_234_567, launcher: { launch: async (url) => callbackFor(url) },
    })
    await runtime.login()
    const target = config.apiOrigin + '/v1/variants?expand[]=data.product#fragment'
    await runtime.authorizedFetch(new Request(target, { method: 'POST', body: 'original body', headers: { 'X-Request': 'one' } }))
    await runtime.logout()
    const claims = await Promise.all(fetch.mock.calls.map(([, init]) => verifiedClaims(init)))
    expect(new Set(claims.map((claim) => claim.jti)).size).toBe(7)
    const digest = createHash('sha256').update(grant.access_token).digest('base64url')
    expect(claims.map(({ htm, htu, nonce, ath, iat }) => [htm, new URL(htu).pathname, nonce, ath, iat])).toEqual([
      ['POST', '/oauth/token', undefined, undefined, 1234], ['POST', '/oauth/token', 'as-1', undefined, 1234],
      ['GET', '/v1/identity', undefined, digest, 1234], ['GET', '/v1/identity', 'rs-1', digest, 1234],
      ['POST', '/v1/variants', 'rs-1', digest, 1234], ['POST', '/v1/variants', 'rs-2', digest, 1234],
      ['POST', '/oauth/revoke', 'as-1', undefined, 1234],
    ])
    expect(claims[4].htu).toBe(config.apiOrigin + '/v1/variants')
    for (const [, init] of fetch.mock.calls.slice(4, 6)) {
      expect(init?.body).toBe('original body')
      expect(new Headers(init?.headers).get('X-Request')).toBe('one')
      expect(new Headers(init?.headers).get('Authorization')).toBe('DPoP ' + grant.access_token)
    }
    expect(fetch.mock.calls[0][1]?.body).toBe(fetch.mock.calls[1][1]?.body)
  })

  it.each(['as', 'rs'] as const)('Given %s 连续挑战 / When 重签一次仍被拒 / Then 返回冻结错误且只发两次', async (server) => {
    const fetch = vi.fn(async () => challenge(server, crypto.randomUUID()))
    const send = createSignedFetch(fetch, Date.now)
    await expect(send(server, await createProofKey(), new Request(config.apiOrigin + '/v1/identity')))
      .rejects.toMatchObject(errors.use_dpop_nonce)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('Given 响应缺 nonce 或为其他鉴权错误 / When 检查响应 / Then 不重发', async () => {
    const key = await createProofKey()
    const request = new Request(config.authOrigin + '/oauth/token', { method: 'POST' })
    const fetch = vi.fn(async () => jsonResponse({ error: 'use_dpop_nonce' }, 400))
    await expect(createSignedFetch(fetch, Date.now)('as', key, request)).rejects.toMatchObject(errors.use_dpop_nonce)
    expect(fetch).toHaveBeenCalledOnce()
    fetch.mockResolvedValueOnce(challenge('as', 'as-only'))
    expect((await createSignedFetch(fetch, Date.now)('rs', key, request, grant.access_token)).status).toBe(400)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it.each([{ token_type: 'Bearer' }, { expires_in: 0 }, { expires_in: 2.5 }, { expires_in: '60' },
    { refresh_token: '' }, { scope: 'products:read' }])('Given 不合法的令牌响应 %j / When 登录 / Then 拒绝建立会话', async (changes) => {
    const runtime = createAuthRuntimeWithDependencies(config, { ...browserPorts(), chrome: createChromePort().chrome,
      fetch: async () => jsonResponse({ ...grant, ...changes }), launcher: { launch: async (url) => callbackFor(url) } })
    await expect(runtime.login()).rejects.toMatchObject(errors.response_invalid)
    expect(await runtime.restore()).toEqual({ status: 'signed-out' })
  })

  it('Given 错误目录 / When 四仓读取错误夹具 / Then 每个公开错误与序列化内容一致', () => {
    expect(Object.keys(errors).sort()).toEqual(Object.values(AuthErrorCode).sort())
    for (const code of Object.values(AuthErrorCode)) {
      const { message, retryable } = new AppAuthorizationError(code)
      expect(errors[code]).toEqual({ code, message, retryable })
    }
  })
})
