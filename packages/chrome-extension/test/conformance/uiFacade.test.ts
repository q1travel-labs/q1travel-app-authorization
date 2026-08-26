import { describe, expect, it } from 'vitest'

import {
  createChromeAppAuthorizationUiFacade,
  defineChromeAppAuthorizationOperations,
  type AppAuthorizationResult,
  type AuthorizationSnapshotV2,
  type LocalTerminationOutcome,
  type UiFacade,
} from '../../src/index'
import { parseUiRequestV2 } from '../../src/ui-facade/protocol'
import type { OperationRegistry } from '../../src/ui-facade/operationCatalog'

const operations = {
  'stores.list': {
    allowedCallers: ['popup', 'side-panel'],
    input: {
      type: 'object',
      fields: { cursor: { type: 'null' } },
    },
    output: {
      type: 'object',
      fields: { stores: { type: 'number' } },
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
  authorization: {
    kind: 'authorized',
    expiresAt: '2026-08-26T12:00:00.000Z',
    sessionRevision: 'revision-7',
  },
  interaction: { phase: 'idle' },
}

const termination: LocalTerminationOutcome = {
  snapshot: {
    ...snapshot,
    authorization: { kind: 'signed-out', reason: 'logged-out' },
  },
  cleanup: 'complete',
}

const success = <T>(value: T): AppAuthorizationResult<T> => ({
  ok: true,
  value,
})

describe('V2 UI facade', () => {
  it('exposes only the six UI-safe methods and sends closed V2 requests', async () => {
    const requests: unknown[] = []
    const facade: UiFacade<typeof operations, 'popup'> =
      createChromeAppAuthorizationUiFacade({
      context: 'popup',
      catalog,
      async sendMessage(message) {
        requests.push(message)
        const request = parseUiRequestV2(message, catalog)
        if (request === null) throw new Error('request was not V2')
        const value =
          request.operation === 'logout' || request.operation === 'revoke'
            ? termination
            : request.operation === 'authorizedFetch'
              ? { stores: 3 }
              : snapshot
        return {
          protocolVersion: 2,
          requestId: request.requestId,
          result: { ok: true, value },
        }
      },
    })

    expect(Object.keys(facade).sort()).toEqual([
      'authorizedFetch',
      'focusAuthorization',
      'login',
      'logout',
      'revoke',
      'status',
    ])

    await facade.status()
    await facade.login()
    await facade.focusAuthorization()
    await facade.logout()
    await facade.revoke()
    await facade.authorizedFetch({
      operationId: 'stores.list',
      input: { cursor: null },
    })

    if (false) {
      // @ts-expect-error Operation IDs must come from the compiled catalog.
      await facade.authorizedFetch({ operationId: 'arbitrary.fetch', input: null })
      await facade.authorizedFetch({
        operationId: 'stores.list',
        // @ts-expect-error Catalog inputs cannot add transport or credential fields.
        input: { cursor: null, url: 'https://attacker.invalid' },
      })
    }

    expect(
      requests.map((request) => {
        const parsed = request as Record<string, unknown>
        return {
          keys: Object.keys(parsed).sort(),
          operation: parsed.operation,
          payload: parsed.payload,
          protocolVersion: parsed.protocolVersion,
          requestIdIsOpaque: typeof parsed.requestId === 'string' &&
            parsed.requestId.length > 0,
        }
      }),
    ).toEqual([
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'status',
        payload: null,
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'login',
        payload: null,
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'focusAuthorization',
        payload: null,
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'logout',
        payload: null,
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'revoke',
        payload: null,
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
      {
        keys: ['context', 'operation', 'payload', 'protocolVersion', 'requestId'],
        operation: 'authorizedFetch',
        payload: { operationId: 'stores.list', input: { cursor: null } },
        protocolVersion: 2,
        requestIdIsOpaque: true,
      },
    ])
  })

  it.each([
    ['wrong protocol version', { protocolVersion: 1 }],
    ['unknown action', { operation: 'getAccessToken' }],
    ['unknown request field', { unexpected: true }],
  ])('rejects a request with %s', (_name, change) => {
    expect(
      parseUiRequestV2({
        protocolVersion: 2,
        requestId: 'request-1',
        context: 'popup',
        operation: 'status',
        payload: null,
        ...change,
      }, catalog),
    ).toBeNull()
  })

  it.each([
    [
      'wrong protocol version',
      {
        protocolVersion: 1,
        requestId: 'request-id',
        result: { ok: true, value: snapshot },
      },
    ],
    [
      'unknown envelope field',
      {
        protocolVersion: 2,
        requestId: 'request-id',
        result: { ok: true, value: snapshot },
        accessToken: 'must-not-pass',
      },
    ],
    [
      'unknown result field',
      {
        protocolVersion: 2,
        requestId: 'request-id',
        result: { ok: true, value: snapshot, state: 'must-not-pass' },
      },
    ],
    [
      'invalid snapshot schema',
      {
        protocolVersion: 2,
        requestId: 'request-id',
        result: {
          ok: true,
          value: { ...snapshot, codeVerifier: 'must-not-pass' },
        },
      },
    ],
  ])('fails closed for a response with %s', async (_name, response) => {
    const facade = createChromeAppAuthorizationUiFacade({
      context: 'popup',
      catalog,
      async sendMessage(message) {
        return {
          ...response,
          requestId: (message as { requestId: string }).requestId,
        }
      },
    })

    expect(await facade.status()).toEqual({
      ok: false,
      error: {
        code: 'protocol_invalid',
        retry: 'never',
        message: 'Authorization protocol response was invalid.',
      },
    })
  })

  it('normalizes a transport rejection without exposing its detail', async () => {
    const facade = createChromeAppAuthorizationUiFacade({
      context: 'side-panel',
      catalog,
      async sendMessage() {
        throw new Error('bearer=private-detail')
      },
    })

    expect(await facade.status()).toEqual({
      ok: false,
      error: {
        code: 'runtime_unavailable',
        retry: 'safe',
        message: 'Authorization runtime is unavailable.',
      },
    })
  })

  it('normalizes a protocol failure message without exposing its detail', async () => {
    const facade = createChromeAppAuthorizationUiFacade({
      context: 'options',
      catalog,
      async sendMessage(message) {
        return {
          protocolVersion: 2,
          requestId: (message as { requestId: string }).requestId,
          result: {
            ok: false,
            error: {
              code: 'runtime_unavailable',
              retry: 'safe',
              message: 'bearer=private-detail',
            },
          },
        }
      },
    })

    expect(await facade.status()).toEqual({
      ok: false,
      error: {
        code: 'runtime_unavailable',
        retry: 'safe',
        message: 'Authorization runtime is unavailable.',
      },
    })
  })

  it('rejects a raw Response returned for an Operation', async () => {
    const facade = createChromeAppAuthorizationUiFacade({
      context: 'popup',
      catalog,
      async sendMessage(message) {
        return {
          protocolVersion: 2,
          requestId: (message as { requestId: string }).requestId,
          result: { ok: true, value: new Response('private response') },
        }
      },
    })

    expect(
      await facade.authorizedFetch({
        operationId: 'stores.list',
        input: { cursor: null },
      }),
    ).toEqual({
      ok: false,
      error: {
        code: 'protocol_invalid',
        retry: 'never',
        message: 'Authorization protocol response was invalid.',
      },
    })
  })

  it('rejects hostile response envelopes without invoking accessors', async () => {
    let getterCalls = 0
    const getterResponse = {
      protocolVersion: 2,
      requestId: 'replaced-by-transport',
    } as Record<PropertyKey, unknown>
    Object.defineProperty(getterResponse, 'result', {
      enumerable: true,
      get() {
        getterCalls += 1
        return { ok: true, value: snapshot }
      },
    })
    const symbolResponse = {
      protocolVersion: 2,
      requestId: 'replaced-by-transport',
      result: { ok: true, value: snapshot },
      [Symbol('hidden')]: true,
    }
    const hiddenResponse = {
      protocolVersion: 2,
      requestId: 'replaced-by-transport',
      result: { ok: true, value: snapshot },
    }
    Object.defineProperty(hiddenResponse, 'hidden', { value: true })
    const pollutedResponse = Object.assign(
      Object.create({ polluted: true }),
      {
        protocolVersion: 2,
        requestId: 'replaced-by-transport',
        result: { ok: true, value: snapshot },
      },
    )

    for (const hostile of [
      getterResponse,
      symbolResponse,
      hiddenResponse,
      pollutedResponse,
      new Proxy({}, { ownKeys() { throw new Error('proxy trap') } }),
    ]) {
      const facade = createChromeAppAuthorizationUiFacade({
        context: 'popup',
        catalog,
        async sendMessage(message) {
          const requestId = (message as { requestId: string }).requestId
          const descriptor = Object.getOwnPropertyDescriptor(hostile, 'requestId')
          if (descriptor?.writable) hostile.requestId = requestId
          return hostile
        },
      })

      expect(await facade.status()).toEqual({
        ok: false,
        error: {
          code: 'protocol_invalid',
          retry: 'never',
          message: 'Authorization protocol response was invalid.',
        },
      })
    }
    expect(getterCalls).toBe(0)
  })

  it('returns a fresh response snapshot detached from later transport mutation', async () => {
    const transportSnapshot = structuredClone(snapshot)
    const facade = createChromeAppAuthorizationUiFacade({
      context: 'popup',
      catalog,
      async sendMessage(message) {
        return {
          protocolVersion: 2,
          requestId: (message as { requestId: string }).requestId,
          result: { ok: true, value: transportSnapshot },
        }
      },
    })

    const result = await facade.status()
    transportSnapshot.profile!.profileId = 'mutated-after-parse'
    expect(result).toEqual(success(snapshot))
  })
})
