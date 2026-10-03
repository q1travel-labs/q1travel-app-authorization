import { describe, expect, it, vi } from 'vitest'
import { createAuthFacadeWithDependencies } from '../src/extension/facade.js'
import { installRuntime } from '../src/extension/listener.js'
import { createAuthRuntimeWithDependencies } from '../src/extension/runtime.js'
import { createChromePort, jsonResponse } from './helpers/fakes.js'

const redirectUri =
  'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/callback'

describe('extension UI facade', () => {
  it('returns session metadata without exposing credentials in messages or errors', async () => {
    const { chrome, sentMessages } = createChromePort()
    const token = 'secret-access-token'.padEnd(43, 'x')
    let state = ''
    const runtime = installRuntime(createAuthRuntimeWithDependencies(
      {
        clientId: 'extension-client',
        redirectUri,
        scopes: ['orders:read'],
        apiOrigin: 'https://api.example.com',
      },
      {
        chrome,
        now: () => 1_000,
        launcher: {
          async launch(url) {
            state = new URL(url).searchParams.get('state') ?? ''
            return `${redirectUri}?code=${'c'.repeat(43)}&state=${state}`
          },
        },
        fetch: vi.fn(async () =>
          jsonResponse({
            access_token: token,
            token_type: 'Bearer',
            expires_in: 28_800,
            scope: 'orders:read',
          }),
        ),
      },
    ), chrome)
    const facade = createAuthFacadeWithDependencies({ chrome })

    await expect(facade.login()).resolves.toMatchObject({
      status: 'authenticated',
      scopes: ['orders:read'],
    })
    expect(JSON.stringify(sentMessages)).not.toContain(token)
    expect(JSON.stringify(await runtime.getSession())).not.toContain(token)
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

    await expect(facade.getSession()).rejects.toMatchObject({
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

  it('accepts requests from an extension options page opened in a tab', async () => {
    const { chrome, listeners } = createChromePort()
    const runtime = {
      ready: vi.fn(async () => undefined),
      login: vi.fn(async () => ({ status: 'signed-out' as const })),
      logout: vi.fn(async () => ({ status: 'signed-out' as const })),
      getSession: vi.fn(async () => ({ status: 'signed-out' as const })),
      verifySession: vi.fn(async () => ({ status: 'signed-out' as const })),
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
            action: 'getSession',
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
