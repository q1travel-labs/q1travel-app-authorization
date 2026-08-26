import { describe, expect, it } from 'vitest'

import {
  createOperationCatalog,
  type OperationRegistry,
} from '../../src/ui-facade/operationCatalog'

const registry = {
  'stores.list': {
    allowedCallers: ['popup', 'side-panel'],
    input: {
      type: 'object',
      fields: {
        cursor: { type: 'string' },
        limit: { type: 'number' },
      },
    },
    output: {
      type: 'object',
      fields: {
        names: { type: 'array', items: { type: 'string' } },
        total: { type: 'number' },
      },
    },
  },
  'connection.ready': {
    allowedCallers: ['options'],
    input: { type: 'null' },
    output: { type: 'boolean' },
  },
} as const satisfies OperationRegistry

describe('catalog-driven Operations', () => {
  it('decodes exact input and output through the registered schemas', () => {
    const catalog = createOperationCatalog(registry)
    expect(catalog).not.toBeNull()
    if (catalog === null) return
    const input = { cursor: 'next-page', limit: 25 }
    const output = { names: ['One', 'Two'], total: 2 }

    const parsedInput = catalog.parseInput('stores.list', input)
    const parsedOutput = catalog.parseOutput('stores.list', output)
    input.cursor = 'mutated'
    output.names[0] = 'mutated'

    expect(parsedInput).toEqual({
      ok: true,
      value: { cursor: 'next-page', limit: 25 },
    })
    expect(parsedOutput).toEqual({
      ok: true,
      value: { names: ['One', 'Two'], total: 2 },
    })
  })

  it.each([
    ['an unknown operation ID', 'unknown.action', { cursor: 'x', limit: 1 }],
    ['a URL as operation ID', 'https://attacker.invalid/fetch', null],
    [
      'an extra input field',
      'stores.list',
      { cursor: 'x', limit: 1, header: 'private' },
    ],
    ['a wrong input type', 'stores.list', { cursor: 'x', limit: '1' }],
    [
      'a serialized authorization header',
      'stores.list',
      { cursor: 'x', limit: 1, authorization: 'Bearer private-token' },
    ],
  ])('rejects %s', (_name, operationId, input) => {
    const catalog = createOperationCatalog(registry)
    expect(catalog?.parseInput(operationId, input)).toEqual({ ok: false })
  })

  it.each([
    ['an extra output field', { names: [], total: 0, url: '/private' }],
    [
      'serialized raw response metadata',
      { names: [], total: 0, headers: { authorization: 'private' } },
    ],
    ['a bearer-shaped output', { names: ['Bearer private-token'], total: 1 }],
    ['a wrong output type', { names: [], total: '0' }],
  ])('rejects %s', (_name, output) => {
    const catalog = createOperationCatalog(registry)
    expect(catalog?.parseOutput('stores.list', output)).toEqual({ ok: false })
  })

  it('enforces each registered operation caller set', () => {
    const catalog = createOperationCatalog(registry)

    expect(catalog?.allows('stores.list', 'popup')).toBe(true)
    expect(catalog?.allows('stores.list', 'options')).toBe(false)
    expect(catalog?.allows('connection.ready', 'options')).toBe(true)
    expect(catalog?.allows('unknown.action', 'options')).toBe(false)
  })

  it('rejects an accessor in registry configuration without invoking it', () => {
    let reads = 0
    const hostile = Object.create(null) as Record<string, unknown>
    Object.defineProperty(hostile, 'stores.list', {
      enumerable: true,
      get() {
        reads += 1
        return registry['stores.list']
      },
    })

    expect(createOperationCatalog(hostile as OperationRegistry)).toBeNull()
    expect(reads).toBe(0)
  })
})
