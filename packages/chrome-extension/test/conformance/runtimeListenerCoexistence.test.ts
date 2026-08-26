import { describe, expect, it } from 'vitest'

import {
  createChromeAppAuthorizationRuntime,
  defineChromeAppAuthorizationOperations,
  type AppAuthorizationResult,
  type UiMessageSender,
} from '../../src/index'
import type { OperationRegistry } from '../../src/ui-facade/operationCatalog'
import {
  backgroundSnapshot,
  createBackgroundOnlyHarness,
} from './backgroundOnlyHarness'

const operations = {
  'stores.list': {
    allowedCallers: ['popup'],
    input: { type: 'null' },
    output: { type: 'number' },
  },
} as const satisfies OperationRegistry

const catalog = defineChromeAppAuthorizationOperations(operations)
const success = <T>(value: T): AppAuthorizationResult<T> => ({
  ok: true,
  value,
})

const createHarness = () => {
  const backgroundHarness = createBackgroundOnlyHarness()
  const runtime = createChromeAppAuthorizationRuntime({
    background: backgroundHarness.background,
    configure: {
      async configure() {
        return success(backgroundSnapshot)
      },
    },
    termination: {
      async logout() {
        return success({
          snapshot: backgroundSnapshot,
          cleanup: 'complete' as const,
        })
      },
      async revoke() {
        return success({
          snapshot: backgroundSnapshot,
          cleanup: 'complete' as const,
        })
      },
    },
    operationExecutor: {
      async execute() {
        return success(1)
      },
    },
    catalog,
    senderPolicy: {
      expectedExtensionId: 'abcdefghijklmnopabcdefghijklmnop',
      entryPaths: {
        popup: '/popup.html',
        options: '/options.html',
        'side-panel': '/side-panel.html',
      },
      managementCallers: ['popup'],
    },
  } as never)

  const popupSender: UiMessageSender = {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    frameId: 0,
    origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
    url: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/popup.html',
    tab: { id: 7, windowId: 3 },
  }
  const dispatch = async (
    message: unknown,
    sender: UiMessageSender = popupSender,
  ) => {
    const responses: unknown[] = []
    const returns = backgroundHarness.internalListeners.map((listener) =>
      listener(message, sender, (response) => responses.push(response)))
    await new Promise((resolve) => setTimeout(resolve, 0))
    return { responses, returns }
  }

  return { ...backgroundHarness, dispatch, popupSender, runtime }
}

describe('package-owned Task 3 and V2 listener coexistence', () => {
  it('composes the real runtime from low-level background-only ports', async () => {
    const harness = createHarness()

    expect(await harness.runtime.start()).toEqual(success(backgroundSnapshot))
    expect(await harness.runtime.status()).toEqual(success(backgroundSnapshot))
    expect(await harness.runtime.login()).toEqual(success({
      ...backgroundSnapshot,
      authorization: { kind: 'authorizing' },
      interaction: { phase: 'authorizing' },
    }))
    expect(harness.internalListeners).toHaveLength(2)
    expect(harness.externalListeners).toHaveLength(1)
    expect(harness.alarmListeners).toHaveLength(1)
    expect(harness.tabRemovedListeners).toHaveLength(1)
    expect(harness.calls).toContain('storage.trusted')
    expect(harness.calls).toContain('beginAuthorization')
    expect(harness.calls).toContain('tabs.navigate')
  })

  it('lets bootstrap and V2 listeners claim only their own messages', async () => {
    const harness = createHarness()
    await harness.runtime.login()

    const bootstrap = await harness.dispatch(
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
      {
        id: harness.chrome.runtime.id,
        frameId: 0,
        origin: `chrome-extension://${harness.chrome.runtime.id}`,
        url: harness.chrome.runtime.getURL('authorization-bootstrap.html'),
        tab: { id: 7, windowId: 3 },
      },
    )
    expect(bootstrap.returns).toEqual([true, undefined])
    expect(bootstrap.responses).toEqual([true])

    const v2 = await harness.dispatch({
      protocolVersion: 2,
      requestId: 'request-1',
      context: 'popup',
      operation: 'status',
      payload: null,
    })
    expect(v2.returns).toEqual([undefined, true])
    expect(v2.responses).toHaveLength(1)
    expect((v2.responses[0] as { protocolVersion: number }).protocolVersion)
      .toBe(2)
  })

  it('declines non-V2 messages synchronously but answers malformed marked V2', async () => {
    const harness = createHarness()

    expect(await harness.dispatch({ type: 'unrelated' })).toEqual({
      responses: [],
      returns: [undefined, undefined],
    })
    const malformed = await harness.dispatch({ protocolVersion: 2 })
    expect(malformed.returns).toEqual([undefined, true])
    expect(malformed.responses).toEqual([
      {
        protocolVersion: 2,
        requestId: 'invalid-request',
        result: {
          ok: false,
          error: {
            code: 'protocol_invalid',
            retry: 'never',
            message: 'Authorization protocol response was invalid.',
          },
        },
      },
    ])
  })
})
