import { createHash } from 'node:crypto'
import { expect, it, vi } from 'vitest'
import { resolveAuthConfig } from '../src/core/config.js'
import { exchangeAuthorizationCode, verifyRemoteSession } from '../src/extension/http.js'
import { contextTabHarness } from './helpers/contextTabFakes.js'
import { jsonResponse } from './helpers/fakes.js'

const config = {
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
  redirectUri: 'https://dashboard.q1lx.com/oauth-callback.html',
  clientId: 'q1travel-ozon-manager-v2',
  scopes: ['pricing:preview'],
  pathPrefix: '',
}
const protocol = config.authOrigin + '/app-authorizations/v1'
const context = 'a'.repeat(42) + 'A'
const grant = { access_token: 't'.repeat(43), token_type: 'Bearer', expires_in: 28_800, scope: 'pricing:preview' }
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
