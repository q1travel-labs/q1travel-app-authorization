import {
  parseUiDataResult,
  type UiData,
  type UiDataParseResult,
} from './data.js'
import type { UiContext } from '../publicTypes.js'

export type UiDataSchema =
  | { readonly type: 'null' }
  | { readonly type: 'boolean' }
  | { readonly type: 'number' }
  | { readonly type: 'string' }
  | { readonly type: 'array'; readonly items: UiDataSchema }
  | {
      readonly type: 'object'
      readonly fields: Readonly<Record<string, UiDataSchema>>
    }

export interface OperationDefinition<
  Input extends UiDataSchema = UiDataSchema,
  Output extends UiDataSchema = UiDataSchema,
> {
  readonly allowedCallers: readonly UiContext[]
  readonly input: Input
  readonly output: Output
}

export type OperationRegistry = Readonly<
  Record<string, OperationDefinition>
>

export type InferUiSchema<Schema extends UiDataSchema> =
  Schema extends { readonly type: 'null' } ? null
    : Schema extends { readonly type: 'boolean' } ? boolean
      : Schema extends { readonly type: 'number' } ? number
        : Schema extends { readonly type: 'string' } ? string
          : Schema extends {
              readonly type: 'array'
              readonly items: infer Item extends UiDataSchema
            } ? InferUiSchema<Item>[]
            : Schema extends {
                readonly type: 'object'
                readonly fields: infer Fields extends Readonly<
                  Record<string, UiDataSchema>
                >
              } ? { [Key in keyof Fields]: InferUiSchema<Fields[Key]> }
              : never

export type OperationId<Registry extends OperationRegistry> =
  Extract<keyof Registry, string>

export type CallerOperationId<
  Registry extends OperationRegistry,
  Context extends UiContext,
> = {
  [Id in OperationId<Registry>]: Context extends
    Registry[Id]['allowedCallers'][number] ? Id : never
}[OperationId<Registry>]

export type OperationInput<
  Registry extends OperationRegistry,
  Id extends OperationId<Registry>,
> = InferUiSchema<Registry[Id]['input']>

export type OperationOutput<
  Registry extends OperationRegistry,
  Id extends OperationId<Registry>,
> = InferUiSchema<Registry[Id]['output']>

export type OperationInvocation<
  Registry extends OperationRegistry,
  Id extends OperationId<Registry> = OperationId<Registry>,
> = {
  operationId: Id
  input: OperationInput<Registry, Id>
}

export type CallerOperationInvocation<
  Registry extends OperationRegistry,
  Context extends UiContext,
  Id extends CallerOperationId<Registry, Context> = CallerOperationId<
    Registry,
    Context
  >,
> = OperationInvocation<Registry, Id>

export type OperationParseResult<Value> =
  | { ok: true; value: Value }
  | { ok: false }

export interface OperationCatalog<Registry extends OperationRegistry> {
  has(operationId: unknown): operationId is OperationId<Registry>
  allows(operationId: unknown, context: UiContext): boolean
  parseInput<Id extends OperationId<Registry>>(
    operationId: Id,
    input: unknown,
  ): OperationParseResult<OperationInput<Registry, Id>>
  parseInput(
    operationId: unknown,
    input: unknown,
  ): OperationParseResult<UiData>
  parseOutput<Id extends OperationId<Registry>>(
    operationId: Id,
    output: unknown,
  ): OperationParseResult<OperationOutput<Registry, Id>>
  parseOutput(
    operationId: unknown,
    output: unknown,
  ): OperationParseResult<UiData>
}

const compiledCatalogBrand: unique symbol = Symbol('CompiledOperationCatalog')

export interface CompiledOperationCatalog<Registry extends OperationRegistry>
  extends OperationCatalog<Registry> {
  readonly [compiledCatalogBrand]: Registry
}

const packageCatalogs = new WeakSet<object>()

interface CompiledOperation {
  allowedCallers: ReadonlySet<UiContext>
  input: UiDataSchema
  output: UiDataSchema
}

const contexts = new Set<UiContext>(['popup', 'options', 'side-panel'])
const operationIdPattern = /^[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z0-9]+)*$/
const poisonKeys = new Set(['__proto__', 'prototype', 'constructor'])
const forbiddenFieldKeys = new Set([
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

const normalizeKey = (key: string): string =>
  key.replace(/[-_]/g, '').toLowerCase()

const readConfigurationObject = (
  value: unknown,
  maxKeys: number,
): Record<string, unknown> | null => {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return null
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null
    const keys = Reflect.ownKeys(value)
    if (
      keys.length > maxKeys ||
      keys.some((key) => typeof key !== 'string')
    ) {
      return null
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const copy: Record<string, unknown> = Object.create(null)
    for (const key of keys as string[]) {
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

const hasExactKeys = (
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean => {
  const actual = Reflect.ownKeys(value)
  return actual.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key))
}

const readConfigurationArray = (value: unknown): unknown[] | null => {
  try {
    if (!Array.isArray(value) || value.length > 16) return null
    const keys = Reflect.ownKeys(value)
    if (keys.length !== value.length + 1 || keys.at(-1) !== 'length') {
      return null
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const copy: unknown[] = []
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)]
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, 'value')
      ) {
        return null
      }
      copy.push(descriptor.value)
    }
    return copy
  } catch {
    return null
  }
}

const compileSchema = (value: unknown, depth = 0): UiDataSchema | null => {
  if (depth > 16) return null
  const schema = readConfigurationObject(value, 2)
  if (schema === null || typeof schema.type !== 'string') return null
  if (
    schema.type === 'null' ||
    schema.type === 'boolean' ||
    schema.type === 'number' ||
    schema.type === 'string'
  ) {
    return hasExactKeys(schema, ['type']) ? { type: schema.type } : null
  }
  if (schema.type === 'array') {
    if (!hasExactKeys(schema, ['type', 'items'])) return null
    const items = compileSchema(schema.items, depth + 1)
    return items === null ? null : { type: 'array', items }
  }
  if (schema.type !== 'object' || !hasExactKeys(schema, ['type', 'fields'])) {
    return null
  }
  const fields = readConfigurationObject(schema.fields, 64)
  if (fields === null) return null
  const compiledFields: Record<string, UiDataSchema> = Object.create(null)
  for (const [key, field] of Object.entries(fields)) {
    if (
      poisonKeys.has(key) ||
      forbiddenFieldKeys.has(normalizeKey(key))
    ) {
      return null
    }
    const compiled = compileSchema(field, depth + 1)
    if (compiled === null) return null
    compiledFields[key] = compiled
  }
  return { type: 'object', fields: Object.freeze(compiledFields) }
}

const decodeSchema = (
  schema: UiDataSchema,
  value: UiData,
): UiDataParseResult => {
  if (schema.type === 'null') {
    return value === null ? { ok: true, value: null } : { ok: false }
  }
  if (schema.type === 'boolean') {
    return typeof value === 'boolean' ? { ok: true, value } : { ok: false }
  }
  if (schema.type === 'number') {
    return typeof value === 'number' ? { ok: true, value } : { ok: false }
  }
  if (schema.type === 'string') {
    return typeof value === 'string' ? { ok: true, value } : { ok: false }
  }
  if (schema.type === 'array') {
    if (!Array.isArray(value)) return { ok: false }
    const copy: UiData[] = []
    for (const item of value) {
      const decoded = decodeSchema(schema.items, item)
      if (!decoded.ok) return decoded
      copy.push(decoded.value)
    }
    return { ok: true, value: copy }
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return { ok: false }
  }
  const expected = Object.keys(schema.fields)
  const actual = Object.keys(value)
  if (
    actual.length !== expected.length ||
    expected.some((key) => !Object.hasOwn(value, key))
  ) {
    return { ok: false }
  }
  const copy: Record<string, UiData> = Object.create(null)
  for (const key of expected) {
    const decoded = decodeSchema(schema.fields[key], value[key])
    if (!decoded.ok) return decoded
    copy[key] = decoded.value
  }
  return { ok: true, value: copy }
}

export const createOperationCatalog = <Registry extends OperationRegistry>(
  registry: Registry,
): OperationCatalog<Registry> | null => {
  const definitions = readConfigurationObject(registry, 64)
  if (definitions === null || Object.keys(definitions).length === 0) return null
  const compiled: Record<string, CompiledOperation> = Object.create(null)
  for (const [operationId, candidate] of Object.entries(definitions)) {
    if (
      operationId.length > 128 ||
      !operationIdPattern.test(operationId)
    ) {
      return null
    }
    const definition = readConfigurationObject(candidate, 3)
    if (
      definition === null ||
      !hasExactKeys(definition, ['allowedCallers', 'input', 'output'])
    ) {
      return null
    }
    const callers = readConfigurationArray(definition.allowedCallers)
    const input = compileSchema(definition.input)
    const output = compileSchema(definition.output)
    if (
      callers === null ||
      callers.length === 0 ||
      callers.some((caller) => !contexts.has(caller as UiContext)) ||
      new Set(callers).size !== callers.length ||
      input === null ||
      output === null
    ) {
      return null
    }
    compiled[operationId] = Object.freeze({
      allowedCallers: new Set(callers as UiContext[]),
      input,
      output,
    })
  }

  const definitionFor = (operationId: unknown): CompiledOperation | null =>
    typeof operationId === 'string' && Object.hasOwn(compiled, operationId)
      ? compiled[operationId]
      : null
  const parse = (
    operationId: unknown,
    value: unknown,
    side: 'input' | 'output',
  ): OperationParseResult<UiData> => {
    const definition = definitionFor(operationId)
    if (definition === null) return { ok: false }
    const data = parseUiDataResult(value)
    if (!data.ok) return data
    return decodeSchema(definition[side], data.value)
  }

  return Object.freeze({
    has(operationId: unknown): operationId is OperationId<Registry> {
      return definitionFor(operationId) !== null
    },
    allows(operationId: unknown, context: UiContext): boolean {
      return definitionFor(operationId)?.allowedCallers.has(context) ?? false
    },
    parseInput(operationId: unknown, input: unknown) {
      return parse(operationId, input, 'input')
    },
    parseOutput(operationId: unknown, output: unknown) {
      return parse(operationId, output, 'output')
    },
  }) as OperationCatalog<Registry>
}

export const defineChromeAppAuthorizationOperations = <
  const Registry extends OperationRegistry,
>(registry: Registry): CompiledOperationCatalog<Registry> => {
  const catalog = createOperationCatalog(registry)
  if (catalog === null) {
    throw new TypeError('Authorization Operation registry is invalid.')
  }
  packageCatalogs.add(catalog)
  return catalog as CompiledOperationCatalog<Registry>
}

export const isCompiledOperationCatalog = <
  Registry extends OperationRegistry,
>(value: unknown): value is CompiledOperationCatalog<Registry> =>
  typeof value === 'object' && value !== null && packageCatalogs.has(value)
