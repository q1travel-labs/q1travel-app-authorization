import { describe, expect, it, vi } from 'vitest'
import { createAuthFacadeWithDependencies } from '../src/extension/facade.js'
import { installRuntime } from '../src/extension/listener.js'
import { createAuthRuntimeWithDependencies } from '../src/extension/runtime.js'
import { browserPorts, callbackFor, config, grant, inspectFetch, oauthResponse } from './helpers/oauth.js'
import { createChromePort } from './helpers/fakes.js'

describe('extension UI facade', () => {
  it('returns session metadata without exposing credentials in messages or errors', async () => {
    const { chrome, sentMessages } = createChromePort()
    const runtime = installRuntime(createAuthRuntimeWithDependencies(config, {
      ...browserPorts(), chrome, launcher: { launch: async (url) => callbackFor(url) },
      fetch: inspectFetch(async (url) => oauthResponse(url, [])),
    }), chrome)
    const facade = createAuthFacadeWithDependencies({ chrome })

    await expect(facade.login()).resolves.toMatchObject({
      status: 'authenticated',
      identity: { scopes: [] },
    })
    const messages = JSON.stringify(sentMessages)
    for (const secret of [grant.access_token, grant.refresh_token, 'code_verifier', 'privateKey']) {
      expect(messages).not.toContain(secret)
    }
    expect(JSON.stringify(await runtime.restore())).not.toContain(grant.access_token)
  })

  it('fails closed when a runtime response contains an extra credential field', async () => {
    const { chrome } = createChromePort()
    chrome.runtime.sendMessage = async () => ({
      protocol: 'q1travel.app-authorization.v1',
      requestId: 'fixed-request',
      ok: true,
      session: { status: 'signed-out' },
      accessToken: 'must-not-cross-ui-boundary',
    })
    const facade = createAuthFacadeWithDependencies({
      chrome,
      createRequestId: () => 'fixed-request',
    })

    await expect(facade.restore()).rejects.toMatchObject({
      code: 'response_invalid',
    })
  })

  it('ignores session notifications from a different extension', () => {
    const { chrome, listeners } = createChromePort()
    const facade = createAuthFacadeWithDependencies({ chrome })
    const callback = vi.fn()
    facade.onSessionChange(callback)

    for (const listener of listeners) {
      listener(
        {
          type: 'q1travel.app-authorization.session-changed.v1',
          session: { status: 'signed-out' },
        },
        { id: 'different-extension' },
        () => undefined,
      )
    }

    expect(callback).not.toHaveBeenCalled()
  })

  it('ignores forged session notifications from a content script', () => {
    const { chrome, listeners } = createChromePort()
    const facade = createAuthFacadeWithDependencies({ chrome })
    const callback = vi.fn()
    facade.onSessionChange(callback)
    const contentSender = {
      id: chrome.runtime.id,
      tab: { id: 7 },
      url: 'https://storefront.example.com/item',
      origin: 'https://storefront.example.com',
    }

    for (const listener of listeners) {
      listener(
        {
          type: 'q1travel.app-authorization.session-changed.v1',
          session: {
            status: 'authenticated',
            expiresAt: '2026-09-20T08:00:00.000Z',
            scopes: ['orders:read'],
          },
        },
        contentSender,
        () => undefined,
      )
    }

    expect(callback).not.toHaveBeenCalled()
  })

  it('Given 内容脚本消息 / When 请求登录、刷新或任意 URL / Then 后台忽略且不出网', () => {
    const { chrome, listeners } = createChromePort()
    const fetch = vi.fn()
    installRuntime(createAuthRuntimeWithDependencies(config, { ...browserPorts(), chrome, fetch }), chrome)
    const sender = { id: chrome.runtime.id, tab: { id: 8 }, url: 'https://example.test/item', origin: 'https://example.test' }
    const reply = vi.fn()
    for (const action of ['login', 'restore', 'refresh', 'logout', 'getIdentity', 'authorizedFetch']) {
      for (const listener of listeners) {
        expect(listener({ protocol: 'q1travel.app-authorization.v1', requestId: 'one', action }, sender, reply)).toBeUndefined()
      }
    }
    expect(reply).not.toHaveBeenCalled()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('accepts requests from an extension options page opened in a tab', async () => {
    const { chrome, listeners } = createChromePort()
    const runtime = {
      ready: vi.fn(async () => undefined),
      login: vi.fn(async () => ({ status: 'signed-out' as const })),
      logout: vi.fn(async () => ({ status: 'signed-out' as const })),
      restore: vi.fn(async () => ({ status: 'signed-out' as const })),
      refresh: vi.fn(async () => ({ status: 'signed-out' as const })),
      getIdentity: vi.fn(async () => ({ status: 'signed-out' as const })),
      onSessionChange: vi.fn(() => () => undefined),
      authorizedFetch: vi.fn(),
    }
    installRuntime(runtime, chrome)
    const response = await new Promise<unknown>((resolve) => {
      for (const listener of listeners) {
        const keepChannel = listener(
          {
            protocol: 'q1travel.app-authorization.v1',
            requestId: 'options-request',
            action: 'restore',
          },
          {
            id: chrome.runtime.id,
            tab: { id: 7 },
            url: `chrome-extension://${chrome.runtime.id}/options.html`,
            origin: `chrome-extension://${chrome.runtime.id}`,
          },
          resolve,
        )
        if (keepChannel === true) return
      }
      resolve(undefined)
    })

    expect(response).toMatchObject({ ok: true, session: { status: 'signed-out' } })
  })
})
