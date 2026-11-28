import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, it, vi } from 'vitest'
import { resolveAuthConfig } from '../src/core/config.js'
import { oauthClient } from '../src/extension/http.js'
import { createProofKey, createSignedFetch } from '../src/extension/dpop.js'
import { identity, installationId, grant as tokenResponse } from './helpers/oauth.js'
import { contextTabHarness } from './helpers/contextTabFakes.js'
import { jsonResponse } from './helpers/fakes.js'

const config = {
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
  redirectUri: 'https://dashboard.q1lx.com/oauth-callback.html',
  clientId: 'q1travel-ozon-manager-store-v1',
  scopes: ['ozon_store_bindings:read'],
  installationId,
}
const protocol = config.authOrigin + '/oauth'
const context = 'a'.repeat(42) + 'A'
const grant = { ...tokenResponse, scope: config.scopes.join(' ') }
const session = { ...identity, scopes: config.scopes }

it('binds the store context, callback and grant to their registered hosts', async () => {
  const h = contextTabHarness(undefined, config)
  const fetch = vi.fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(jsonResponse({
      authorization_context: context, expires_at: 601,
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
        const body = { client_id: clientId, redirect_uri: redirectUri, state, code_challenge: codeChallenge, kind: 'ozon-client-id-v1', observed_client_id: '123456' }
        const response = await fetch(contextsUrl, {
          method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' },
          credentials: 'omit', redirect: 'error',
        })
        return { token: (await response.json()).authorization_context }
      },
      async assertCurrent({ token }) { expect(token).toBe(context) },
    },
  })

  const login = runtime.login()
  await h.started()
  const authorize = new URL(h.chrome.tabs.update.mock.calls[0][1].url!)
  expect(authorize.origin + authorize.pathname).toBe(protocol + '/authorize')
  expect(authorize.searchParams.get('client_id')).toBe('q1travel-ozon-manager-store-v1')
  expect(authorize.searchParams.get('scope')).toBe('ozon_store_bindings:read')
  expect(authorize.searchParams.get('redirect_uri')).toBe(config.redirectUri)
  expect(authorize.searchParams.get('authorization_context')).toBe(context)
  for (const origin of [config.apiOrigin, config.authOrigin]) {
    expect(await h.dispatch(undefined, { origin })).toBeUndefined()
  }
  expect(fetch).toHaveBeenCalledTimes(1)
  expect(await h.dispatch()).toEqual({ ok: true })
  expect(await login).toMatchObject({ status: 'authenticated' })
  expect(await runtime.restore()).toMatchObject({ status: 'authenticated' })
  const resource = config.apiOrigin + '/v1/store_contexts/current'
  await runtime.authorizedFetch(resource, { redirect: 'follow' })
  expect(await runtime.logout()).toEqual({ status: 'signed-out' })

  expect(fetch.mock.calls.map(([url, init]) => [url, init?.method ?? 'GET'])).toEqual([
    [protocol + '/contexts', 'POST'], [protocol + '/token', 'POST'], [config.apiOrigin + '/v1/identity', 'GET'],
    [resource, 'GET'], [protocol + '/revoke', 'POST'],
  ])
  for (const [, init] of fetch.mock.calls) expect(init).toMatchObject({ redirect: 'error', credentials: 'omit' })
  expect(fetch.mock.calls.map(([, init]) => new Headers(init?.headers).get('authorization'))).toEqual([
    null, null, 'DPoP ' + grant.access_token, 'DPoP ' + grant.access_token, null,
  ])
  const challenge = authorize.searchParams.get('code_challenge')
  const exchange = new URLSearchParams(String(fetch.mock.calls[1][1]?.body))
  expect(exchange.get('client_id')).toBe(config.clientId)
  expect(createHash('sha256').update(exchange.get('code_verifier')!).digest('base64url')).toBe(challenge)
  expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({
    client_id: config.clientId, redirect_uri: config.redirectUri, state: authorize.searchParams.get('state'),
    code_challenge: challenge, kind: 'ozon-client-id-v1', observed_client_id: '123456',
  })
  expect(Object.fromEntries(new URLSearchParams(String(fetch.mock.calls[4][1]?.body)))).toEqual({
    client_id: config.clientId, token: grant.refresh_token, token_type_hint: 'refresh_token',
  })
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
    const signed = createSignedFetch(fetch, Date.now)
    const client = oauthClient(resolved, signed, Date.now)
    const key = await createProofKey()
    const denied = { code: 'network_unavailable' }
    await expect(client.exchange('code', 'verifier', key)).rejects.toMatchObject(denied)
    const h = contextTabHarness(undefined, { ...local, apiOrigin: origin, authOrigin: otherOrigin })
    const stored = await h.seed()
    await expect(client.revoke(stored, key)).rejects.toMatchObject(denied)
    const runtime = h.create({ fetch, verifyOnStartup: false })
    await expect(runtime.authorizedFetch(origin + '/v1/orders', { redirect: 'follow' })).rejects.toMatchObject(denied)
    expect(paths).toEqual(['/oauth/token', '/oauth/revoke', '/v1/orders'])
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  }
})
