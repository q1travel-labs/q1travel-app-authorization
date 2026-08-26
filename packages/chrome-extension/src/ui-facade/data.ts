export type UiData =
  | null
  | boolean
  | number
  | string
  | UiData[]
  | { [key: string]: UiData }

export type UiDataParseResult =
  | { ok: true; value: UiData }
  | { ok: false }

export const readExactDataProperties = (
  value: unknown,
  expected: readonly string[],
): Record<string, unknown> | null => {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return null
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null
    const keys = Reflect.ownKeys(value)
    if (
      keys.length !== expected.length ||
      keys.some((key) => typeof key !== 'string') ||
      expected.some((key) => !keys.includes(key))
    ) {
      return null
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const copy: Record<string, unknown> = Object.create(null)
    for (const key of expected) {
      const descriptor = descriptors[key]
      if (
        poisonKeys.has(key) ||
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, 'value')
      ) {
        return null
      }
      copy[key] = descriptor.value
    }
    return copy
  } catch {
    return null
  }
}

const MAX_DEPTH = 16
const MAX_NODES = 2_048
const MAX_TOTAL_KEYS = 1_024
const MAX_OBJECT_KEYS = 64
const MAX_ARRAY_LENGTH = 256
const MAX_STRING_LENGTH = 8_192
const MAX_STRING_BYTES = 16_384
const MAX_TOTAL_STRING_BYTES = 65_536

const poisonKeys = new Set(['__proto__', 'prototype', 'constructor'])
const forbiddenKeys = new Set([
  'url',
  'headers',
  'authorization',
  'accesstoken',
  'token',
  'bearer',
  'code',
  'state',
  'verifier',
  'codeverifier',
  'callback',
  'redirect',
  'redirecturi',
  'tokenendpoint',
  'rawresponse',
])

const forbiddenString =
  /(?:\b(?:https?|chrome-extension):\/\/|\bbearer\s+\S+|\beyJ[\w-]+\.[\w-]+\.[\w-]+)/i

interface ParseBudget {
  nodes: number
  keys: number
  stringBytes: number
  seen: WeakSet<object>
}

const normalizeKey = (key: string): string =>
  key.replace(/[-_]/g, '').toLowerCase()

const keyIsAllowed = (key: string): boolean =>
  !poisonKeys.has(key) && !forbiddenKeys.has(normalizeKey(key))

const parseValue = (
  value: unknown,
  budget: ParseBudget,
  depth: number,
): UiData | undefined => {
  budget.nodes += 1
  if (budget.nodes > MAX_NODES || depth > MAX_DEPTH) return undefined
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined
  }
  if (typeof value === 'string') {
    if (value.length > MAX_STRING_LENGTH || forbiddenString.test(value)) {
      return undefined
    }
    const bytes = new TextEncoder().encode(value).byteLength
    budget.stringBytes += bytes
    return bytes <= MAX_STRING_BYTES &&
      budget.stringBytes <= MAX_TOTAL_STRING_BYTES
      ? value
      : undefined
  }
  if (typeof value !== 'object' || budget.seen.has(value)) return undefined
  budget.seen.add(value)

  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_LENGTH) return undefined
    const keys = Reflect.ownKeys(value)
    if (
      keys.some((key) => typeof key !== 'string') ||
      keys.length !== value.length + 1 ||
      keys.at(-1) !== 'length'
    ) {
      return undefined
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const copy: UiData[] = []
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, 'value')
      ) {
        return undefined
      }
      const item = parseValue(descriptor.value, budget, depth + 1)
      if (item === undefined) return undefined
      copy.push(item)
    }
    return copy
  }

  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return undefined
  const keys = Reflect.ownKeys(value)
  if (
    keys.length > MAX_OBJECT_KEYS ||
    keys.some((key) => typeof key !== 'string')
  ) {
    return undefined
  }
  budget.keys += keys.length
  if (budget.keys > MAX_TOTAL_KEYS) return undefined
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const copy: Record<string, UiData> = Object.create(null)
  for (const key of keys as string[]) {
    const descriptor = descriptors[key]
    if (
      !keyIsAllowed(key) ||
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')
    ) {
      return undefined
    }
    const item = parseValue(descriptor.value, budget, depth + 1)
    if (item === undefined) return undefined
    copy[key] = item
  }
  return copy
}

export const parseUiDataResult = (value: unknown): UiDataParseResult => {
  try {
    const parsed = parseValue(
      value,
      { nodes: 0, keys: 0, stringBytes: 0, seen: new WeakSet() },
      0,
    )
    return parsed === undefined ? { ok: false } : { ok: true, value: parsed }
  } catch {
    return { ok: false }
  }
}

export const parseUiData = (value: unknown): UiData | null => {
  const parsed = parseUiDataResult(value)
  return parsed.ok ? parsed.value : null
}
