import { describe, expect, it } from 'vitest'

import { parseUiData } from '../../src/ui-facade/data'

describe('hardened UI data parsing', () => {
  it('copies accepted plain data so later transport mutation cannot change it', () => {
    const input = { items: [{ name: 'before' }] }

    const parsed = parseUiData(input)
    input.items[0].name = 'after'
    input.items.push({ name: 'later' })

    expect(parsed).toEqual({ items: [{ name: 'before' }] })
    expect(parsed).not.toBe(input)
    expect((parsed as { items: unknown[] }).items).not.toBe(input.items)
  })

  it('rejects an accessor without invoking it', () => {
    let reads = 0
    const input = Object.create(null) as Record<string, unknown>
    Object.defineProperty(input, 'value', {
      enumerable: true,
      get() {
        reads += 1
        return 'private'
      },
    })

    expect(parseUiData(input)).toBeNull()
    expect(reads).toBe(0)
  })

  it.each([
    [
      'a non-enumerable field',
      () => {
        const value = { visible: true }
        Object.defineProperty(value, 'hidden', {
          enumerable: false,
          value: 'private',
        })
        return value
      },
    ],
    [
      'a symbol field',
      () => ({ visible: true, [Symbol('hidden')]: 'private' }),
    ],
    [
      'a polluted prototype',
      () => Object.assign(Object.create({ polluted: true }), { visible: true }),
    ],
    [
      'a poison constructor field',
      () => {
        const value = Object.create(null) as Record<string, unknown>
        Object.defineProperty(value, 'constructor', {
          enumerable: true,
          value: 'private',
        })
        return value
      },
    ],
    [
      'a poison prototype field',
      () => {
        const value = Object.create(null) as Record<string, unknown>
        value.prototype = 'private'
        return value
      },
    ],
    [
      'a poison __proto__ field',
      () => {
        const value = Object.create(null) as Record<string, unknown>
        value.__proto__ = 'private'
        return value
      },
    ],
  ])('rejects %s', (_name, createValue) => {
    expect(parseUiData(createValue())).toBeNull()
  })

  it('rejects a proxy whose reflection trap fails closed', () => {
    const input = new Proxy({}, {
      ownKeys() {
        throw new Error('private proxy detail')
      },
    })

    expect(parseUiData(input)).toBeNull()
  })

  it.each([
    ['object breadth', Object.fromEntries(
      Array.from({ length: 65 }, (_, index) => [`key${index}`, index]),
    )],
    ['array length', Array.from({ length: 257 }, (_, index) => index)],
    ['string length', 'x'.repeat(8_193)],
    ['string byte size', '界'.repeat(5_500)],
    ['depth', Array.from({ length: 18 }).reduce<unknown>(
      (value) => [value],
      null,
    )],
  ])('rejects data over the %s budget', (_name, input) => {
    expect(parseUiData(input)).toBeNull()
  })

  it.each([
    ['a URL', { endpoint: 'https://attacker.invalid/private' }],
    ['an authorization header', { authorization: 'Bearer private-token' }],
    ['a bearer-shaped string', { value: 'Bearer private-token' }],
    ['a callback material key', { state: 'private-state' }],
  ])('rejects %s from UI data', (_name, input) => {
    expect(parseUiData(input)).toBeNull()
  })
})
