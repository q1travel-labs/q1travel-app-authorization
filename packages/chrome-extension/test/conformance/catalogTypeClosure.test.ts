import { describe, expect, it } from 'vitest'

import {
  createChromeAppAuthorizationRuntime,
  createChromeAppAuthorizationUiFacade,
  defineChromeAppAuthorizationOperations,
  type ChromeAppAuthorizationRuntimeDependencies,
  type OperationRegistry,
} from '../../src/index'

const operations = {
  'stores.list': {
    allowedCallers: ['popup'],
    input: {
      type: 'object',
      fields: { limit: { type: 'number' } },
    },
    output: {
      type: 'object',
      fields: { total: { type: 'number' } },
    },
  },
  'connection.ready': {
    allowedCallers: ['options'],
    input: { type: 'null' },
    output: { type: 'boolean' },
  },
} as const satisfies OperationRegistry

const catalog = defineChromeAppAuthorizationOperations(operations)

describe('public Operation catalog type closure', () => {
  it('rejects raw registries at both public factories at runtime', () => {
    expect(() => createChromeAppAuthorizationUiFacade({
      context: 'popup',
      catalog: operations,
      async sendMessage() {
        throw new Error('must not be reached')
      },
    } as never)).toThrow(TypeError)

    expect(() => createChromeAppAuthorizationRuntime({
      catalog: operations,
    } as never)).toThrow(TypeError)
  })

  it('keeps callable operation IDs closed to the facade context', () => {
    const optionsFacade = createChromeAppAuthorizationUiFacade({
      context: 'options',
      catalog,
      async sendMessage() {
        throw new Error('type-only test')
      },
    })

    if (false) {
      // @ts-expect-error A raw registry is not a package-compiled catalog.
      createChromeAppAuthorizationUiFacade({ context: 'popup', catalog: operations, async sendMessage() {} })
      // @ts-expect-error A popup-only operation is absent from an options facade.
      void optionsFacade.authorizedFetch({ operationId: 'stores.list', input: { limit: 1 } })
      void optionsFacade.authorizedFetch({
        operationId: 'connection.ready',
        input: null,
      })
      const unsafeRuntimeDependencies: ChromeAppAuthorizationRuntimeDependencies<
        unknown,
        typeof operations
      > = {
        background: null as never,
        configure: null as never,
        termination: null as never,
        operationExecutor: null as never,
        // @ts-expect-error The runtime also requires the package brand.
        catalog: operations,
        senderPolicy: null as never,
      }
      createChromeAppAuthorizationRuntime(unsafeRuntimeDependencies)
    }
  })

  it.each([
    [
      'a URL operation ID',
      {
        'https://attacker.invalid/fetch': operations['stores.list'],
      },
    ],
    [
      'a credential-shaped schema field',
      {
        'stores.list': {
          ...operations['stores.list'],
          input: {
            type: 'object',
            fields: { accessToken: { type: 'string' } },
          },
        },
      },
    ],
  ])('fails closed while compiling %s', (_name, unsafe) => {
    expect(() => defineChromeAppAuthorizationOperations(
      unsafe as OperationRegistry,
    )).toThrow(TypeError)
  })
})
