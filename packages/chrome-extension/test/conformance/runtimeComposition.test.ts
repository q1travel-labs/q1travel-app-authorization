import { describe, expect, it } from 'vitest'

import {
  createChromeAppAuthorizationRuntime,
  createChromeAppAuthorizationUiFacade,
  defineChromeAppAuthorizationOperations,
  type AppAuthorizationResult,
  type AuthorizationSnapshotV2,
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
    input: {
      type: 'object',
      fields: { limit: { type: 'number' } },
    },
    output: {
      type: 'object',
      fields: { names: { type: 'array', items: { type: 'string' } } },
    },
  },
} as const satisfies OperationRegistry
const catalog = defineChromeAppAuthorizationOperations(operations)

const snapshot: AuthorizationSnapshotV2 = {
  profile: {
    profileId: 'browser-development',
    environment: 'development',
  },
  runtime: 'ready',
  authorization: { kind: 'signed-out', reason: 'never-authorized' },
  interaction: { phase: 'idle' },
}

const success = <T>(value: T): AppAuthorizationResult<T> => ({
  ok: true,
  value,
})

const createHarness = () => {
  const backgroundHarness = createBackgroundOnlyHarness()
  const { calls } = backgroundHarness
  const runtime = createChromeAppAuthorizationRuntime({
    background: backgroundHarness.background,
    configure: {
      async configure(configuration: { profileId: string }) {
        calls.push(`configure:${configuration.profileId}`)
        return success(snapshot)
      },
    },
    termination: {
      async logout() {
        calls.push('logout')
        return success({ snapshot, cleanup: 'complete' as const })
      },
      async revoke() {
        calls.push('revoke')
        return success({ snapshot, cleanup: 'complete' as const })
      },
    },
    operationExecutor: {
      async execute(operationId, input) {
        calls.push(`execute:${operationId}:${JSON.stringify(input)}`)
        return success({ names: ['One', 'Two'] })
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
  })
  const sender: UiMessageSender = {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    frameId: 0,
    url: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/popup.html',
  }
  const facade = createChromeAppAuthorizationUiFacade({
    context: 'popup',
    catalog,
    async sendMessage(message) {
      return await dispatchMessage(message, sender)
    },
  })
  const dispatchMessage = async (
    message: unknown,
    messageSender = sender,
  ): Promise<unknown> => await new Promise((resolve, reject) => {
    let claimed = false
    for (const dispatcher of backgroundHarness.internalListeners) {
      if (dispatcher(message, messageSender, resolve) === true) claimed = true
    }
    if (!claimed) reject(new Error('message was not claimed'))
  })
  return {
    calls,
    facade,
    runtime,
    sender,
    dispatch: dispatchMessage,
  }
}

describe('Task 3 runtime composition and V2 UI dispatch', () => {
  it('runs the exact public lifecycle through Task 3 and explicit ports', async () => {
    const harness = createHarness()

    expect(Object.keys(harness.runtime).sort()).toEqual([
      'authorizedFetch',
      'configure',
      'focusAuthorization',
      'login',
      'logout',
      'revoke',
      'start',
      'status',
    ])
    expect(await harness.runtime.configure({ profileId: 'development' })).toEqual(
      success(snapshot),
    )
    expect(await harness.runtime.start()).toEqual(success(backgroundSnapshot))
    expect(await harness.facade.status()).toEqual(success(backgroundSnapshot))
    expect((await harness.facade.login()).ok).toBe(true)
    expect((await harness.facade.focusAuthorization()).ok).toBe(true)
    expect((await harness.facade.logout()).ok).toBe(true)
    expect((await harness.facade.revoke()).ok).toBe(true)
    expect(
      await harness.facade.authorizedFetch({
        operationId: 'stores.list',
        input: { limit: 2 },
      }),
    ).toEqual(success({ names: ['One', 'Two'] }))
    expect(harness.calls).toContain('configure:development')
    expect(harness.calls).toContain('beginAuthorization')
    expect(harness.calls).toContain('logout')
    expect(harness.calls).toContain('revoke')
    expect(harness.calls).toContain('execute:stores.list:{"limit":2}')
  })

  it('fails an unknown runtime Operation before calling the executor', async () => {
    const harness = createHarness()

    const result = await harness.runtime.authorizedFetch({
      operationId: 'https://attacker.invalid/arbitrary-fetch',
      input: { authorization: 'Bearer private-token' },
    } as never)

    expect(result).toEqual({
      ok: false,
      error: {
        code: 'operation_not_allowed',
        retry: 'never',
        message: 'Authorization operation is not allowed.',
      },
    })
    expect(harness.calls.some((call) => call.startsWith('execute:'))).toBe(false)
  })

  it('enforces sender identity, top frame, exact path and operation callers', async () => {
    const harness = createHarness()
    const request = {
      protocolVersion: 2,
      requestId: 'request-1',
      context: 'popup',
      operation: 'authorizedFetch',
      payload: { operationId: 'stores.list', input: { limit: 2 } },
    }

    for (const sender of [
      { ...harness.sender, id: 'wrong-extension' },
      { ...harness.sender, frameId: 1 },
      { ...harness.sender, url: `${harness.sender.url}?unexpected=true` },
    ]) {
      expect(await harness.dispatch(request, sender)).toEqual({
        protocolVersion: 2,
        requestId: 'request-1',
        result: {
          ok: false,
          error: {
            code: 'operation_not_allowed',
            retry: 'never',
            message: 'Authorization operation is not allowed.',
          },
        },
      })
    }
    expect(harness.calls.some((call) => call.startsWith('execute:'))).toBe(false)
  })

  it('rejects a declared context not allowed by the Operation catalog', async () => {
    const harness = createHarness()
    const result = await harness.dispatch(
      {
        protocolVersion: 2,
        requestId: 'request-2',
        context: 'options',
        operation: 'authorizedFetch',
        payload: { operationId: 'stores.list', input: { limit: 2 } },
      },
      {
        id: harness.sender.id,
        frameId: 0,
        url: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/options.html',
      },
    )

    expect(result).toEqual({
      protocolVersion: 2,
      requestId: 'request-2',
      result: {
        ok: false,
        error: {
          code: 'operation_not_allowed',
          retry: 'never',
          message: 'Authorization operation is not allowed.',
        },
      },
    })
    expect(harness.calls.some((call) => call.startsWith('execute:'))).toBe(false)
  })
})
