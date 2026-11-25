import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, it, vi } from 'vitest'
import { resolveAuthConfig } from '../src/core/config.js'
import { exchangeAuthorizationCode, revokeSession, verifyRemoteSession } from '../src/extension/http.js'
import { SESSION_STORAGE_KEY } from '../src/extension/storage.js'
import { contextTabHarness } from './helpers/contextTabFakes.js'
import { jsonResponse } from './helpers/fakes.js'

const config = {
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
  redirectUri: 'https://dashboard.q1lx.com/oauth-callback.html',
  clientId: 'q1travel-ozon-manager-store-v1',
  scopes: ['tools:ozon-manager:access'],
  pathPrefix: '',
}
const protocol = config.authOrigin + '/app-authorizations/v1'
const context = 'a'.repeat(42) + 'A'
const grant = { access_token: 't'.repeat(43), token_type: 'Bearer', expires_in: 28_800, scope: 'tools:ozon-manager:access' }
const session = { active: true, expires_at: new Date(28_801_000).toISOString(), scope: config.scopes }

it('binds the store context, callback and grant to their registered hosts', async () => {
  const h = contextTabHarness(undefined, config)
  const fetch = vi.fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(jsonResponse({
      statusCode: 201, message: 'success',
      data: { authorizationContext: context, expiresAt: new Date(601_000).toISOString() },
    }, 201))
    .mockResolvedValueOnce(jsonResponse(grant))
    .mockResolvedValueOnce(jsonResponse(session))
    .mockResolvedValueOnce(jsonResponse({ ok: true }))
    .mockResolvedValueOnce(new Response(null, { status: 200 }))
  const runtime = h.create({
    fetch,
    authorizationContextPort: {
      async prepare({ contextsUrl, clientId, redirectUri, state, codeChallenge, sourceTabId }) {
        expect(sourceTabId).toBe(7)
        const body = { clientId, redirectUri, state, codeChallenge, kind: 'ozon-client-id-v1', observedClientId: '123456' }
        const response = await fetch(contextsUrl, {
          method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' },
          credentials: 'omit', redirect: 'error',
        })
        return { token: (await response.json()).data.authorizationContext }
      },
      async assertCurrent({ token }) { expect(token).toBe(context) },
    },
  })

  const login = runtime.login()
  await h.started()
  const authorize = new URL(h.chrome.tabs.update.mock.calls[0][1].url!)
  expect(authorize.origin + authorize.pathname).toBe(protocol + '/authorize')
  expect(authorize.searchParams.get('client_id')).toBe('q1travel-ozon-manager-store-v1')
  expect(authorize.searchParams.get('scope')).toBe('tools:ozon-manager:access')
  expect(authorize.searchParams.get('redirect_uri')).toBe(config.redirectUri)
  expect(authorize.searchParams.get('authorization_context')).toBe(context)
  for (const origin of [config.apiOrigin, config.authOrigin]) {
    expect(await h.dispatch(undefined, { origin })).toBeUndefined()
  }
  expect(fetch).toHaveBeenCalledTimes(1)
  expect(await h.dispatch()).toEqual({ ok: true })
  expect(await login).toMatchObject({ status: 'authenticated' })
  expect(await runtime.verifySession()).toMatchObject({ status: 'authenticated' })
  const resource = config.apiOrigin + '/connected-apps/ozon/store-context'
  await runtime.authorizedFetch(resource, { redirect: 'follow' })
  expect(await runtime.logout()).toEqual({ status: 'signed-out' })

  expect(fetch.mock.calls.map(([url, init]) => [url, init?.method ?? 'GET'])).toEqual([
    [protocol + '/contexts', 'POST'], [protocol + '/token', 'POST'], [protocol + '/session', 'GET'],
    [resource, 'GET'], [protocol + '/revoke', 'POST'],
  ])
  for (const [, init] of fetch.mock.calls) expect(init).toMatchObject({ redirect: 'error', credentials: 'omit' })
  expect(fetch.mock.calls.map(([, init]) => new Headers(init?.headers).get('authorization'))).toEqual([
    null, null, 'Bearer ' + grant.access_token, 'Bearer ' + grant.access_token, null,
  ])
  const challenge = authorize.searchParams.get('code_challenge')
  const exchange = new URLSearchParams(String(fetch.mock.calls[1][1]?.body))
  expect(exchange.get('client_id')).toBe(config.clientId)
  expect(createHash('sha256').update(exchange.get('code_verifier')!).digest('base64url')).toBe(challenge)
  expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({
    clientId: config.clientId, redirectUri: config.redirectUri, state: authorize.searchParams.get('state'),
    codeChallenge: challenge, kind: 'ozon-client-id-v1', observedClientId: '123456',
  })
  expect(Object.fromEntries(new URLSearchParams(String(fetch.mock.calls[4][1]?.body)))).toEqual({
    client_id: config.clientId, token: grant.access_token, token_type_hint: 'access_token',
  })
})

it('requires exactly the registered token and session response fields', async () => {
  const resolved = resolveAuthConfig(config, true)
  for (const body of [{ ...grant, extra: true }, { ...grant, scope: undefined }]) {
    await expect(exchangeAuthorizationCode(async () => jsonResponse(body), resolved, 'code', 'verifier', 0))
      .rejects.toMatchObject({ code: 'response_invalid' })
  }
  for (const body of [{ ...session, extra: true }, { ...session, active: undefined }]) {
    await expect(verifyRemoteSession(async () => jsonResponse(body), resolved, grant.access_token))
      .rejects.toMatchObject({ code: 'response_invalid' })
  }
})

it('maps a refused HTTP redirect to network_unavailable without contacting its destination', async () => {
  const paths: string[] = []
  const server = createServer((req, res) => {
    paths.push(req.url!)
    res.writeHead(302, { location: '/destination', connection: 'close' }).end()
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    const origin = 'http://127.0.0.1:' + (server.address() as AddressInfo).port
    const otherOrigin = 'http://localhost:' + (server.address() as AddressInfo).port
    const local = { ...config, authOrigin: origin, apiOrigin: otherOrigin, allowInsecureLoopback: true }
    const resolved = resolveAuthConfig(local, true)
    const denied = { code: 'network_unavailable' }
    await expect(exchangeAuthorizationCode(fetch, resolved, 'code', 'verifier', 0)).rejects.toMatchObject(denied)
    await expect(verifyRemoteSession(fetch, resolved, grant.access_token)).rejects.toMatchObject(denied)
    await expect(revokeSession(fetch, resolved, grant.access_token)).rejects.toMatchObject(denied)

    const h = contextTabHarness(undefined, { ...local, apiOrigin: origin, authOrigin: otherOrigin })
    h.storage.values[SESSION_STORAGE_KEY] = {
      accessToken: grant.access_token, tokenType: 'Bearer', expiresAt: session.expires_at, scopes: config.scopes,
    }
    const runtime = h.create({ fetch, verifyOnStartup: false })
    await expect(runtime.authorizedFetch(origin + '/orders', { redirect: 'follow' })).rejects.toMatchObject(denied)
    expect(paths).toEqual([
      '/app-authorizations/v1/token', '/app-authorizations/v1/session', '/app-authorizations/v1/revoke', '/orders',
    ])
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  }
})
