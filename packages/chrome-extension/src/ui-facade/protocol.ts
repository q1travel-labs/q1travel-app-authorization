import type {
  AppAuthorizationFailure,
  AppAuthorizationFailureCode,
  AppAuthorizationResult,
  AuthorizationSnapshotV2,
  LocalTerminationOutcome,
  UiContext,
} from '../publicTypes.js'
import {
  parseUiDataResult,
  readExactDataProperties,
  type UiData,
} from './data.js'
import type {
  OperationCatalog,
  OperationId,
  OperationRegistry,
} from './operationCatalog.js'

export type UiOperation =
  | 'status'
  | 'login'
  | 'focusAuthorization'
  | 'logout'
  | 'revoke'
  | 'authorizedFetch'

export interface ParsedUiRequestV2<Registry extends OperationRegistry> {
  protocolVersion: 2
  requestId: string
  context: UiContext
  operation: UiOperation
  payload: null | {
    operationId: OperationId<Registry>
    input: UiData
  }
}

export type ValueDecoder<Value> = (
  value: unknown,
) => { ok: true; value: Value } | { ok: false }

export type UiRequestParseResult<Registry extends OperationRegistry> =
  | { ok: true; value: ParsedUiRequestV2<Registry> }
  | {
      ok: false
      requestId: string
      error: 'protocol_invalid' | 'operation_not_allowed'
    }

const failureCodes = new Set<AppAuthorizationFailureCode>([
  'configuration_invalid',
  'runtime_not_ready',
  'runtime_unavailable',
  'interaction_in_progress',
  'interaction_denied',
  'callback_invalid',
  'protocol_invalid',
  'network_unavailable',
  'grant_expired',
  'grant_invalidated',
  'grant_forbidden',
  'revocation_pending',
  'operation_not_allowed',
  'response_invalid',
])

const failureRetries: Record<
  AppAuthorizationFailureCode,
  readonly AppAuthorizationFailure['retry'][]
> = {
  configuration_invalid: ['never'],
  runtime_not_ready: ['safe'],
  runtime_unavailable: ['safe'],
  interaction_in_progress: ['never'],
  interaction_denied: ['explicit-user-action'],
  callback_invalid: ['never'],
  protocol_invalid: ['never'],
  network_unavailable: ['never', 'safe'],
  grant_expired: ['explicit-user-action'],
  grant_invalidated: ['explicit-user-action'],
  grant_forbidden: ['never'],
  revocation_pending: ['explicit-user-action'],
  operation_not_allowed: ['never'],
  response_invalid: ['never'],
}

const failureMessages: Record<AppAuthorizationFailureCode, string> = {
  configuration_invalid: 'Authorization configuration is invalid.',
  runtime_not_ready: 'Authorization runtime is not ready.',
  runtime_unavailable: 'Authorization runtime is unavailable.',
  interaction_in_progress: 'Authorization interaction is already in progress.',
  interaction_denied: 'Authorization interaction was denied.',
  callback_invalid: 'Authorization callback was invalid.',
  protocol_invalid: 'Authorization protocol response was invalid.',
  network_unavailable: 'Authorization network operation is unavailable.',
  grant_expired: 'Authorization grant has expired.',
  grant_invalidated: 'Authorization grant was invalidated.',
  grant_forbidden: 'Authorization grant does not allow this operation.',
  revocation_pending: 'Authorization revocation is pending.',
  operation_not_allowed: 'Authorization operation is not allowed.',
  response_invalid: 'Authorization operation response was invalid.',
}

const contexts = new Set<UiContext>(['popup', 'options', 'side-panel'])
const operations = new Set<UiOperation>([
  'status',
  'login',
  'focusAuthorization',
  'logout',
  'revoke',
  'authorizedFetch',
])

const parseString = (value: unknown): string | null => {
  const parsed = parseUiDataResult(value)
  return parsed.ok && typeof parsed.value === 'string'
    ? parsed.value
    : null
}

export const authorizationFailure = (
  code: AppAuthorizationFailureCode,
  retry = failureRetries[code][0],
): AppAuthorizationResult<never> => ({
  ok: false,
  error: { code, retry, message: failureMessages[code] },
})

const parseFailure = (value: unknown): AppAuthorizationFailure | null => {
  const failure = readExactDataProperties(value, ['code', 'retry', 'message'])
  if (
    failure === null ||
    !failureCodes.has(failure.code as AppAuthorizationFailureCode) ||
    typeof failure.retry !== 'string' ||
    parseString(failure.message) === null
  ) {
    return null
  }
  const code = failure.code as AppAuthorizationFailureCode
  const retry = failure.retry as AppAuthorizationFailure['retry']
  if (!failureRetries[code].includes(retry)) return null
  return { code, retry, message: failureMessages[code] }
}

const parseProfile = (
  value: unknown,
): AuthorizationSnapshotV2['profile'] | undefined => {
  if (value === null) return null
  const profile = readExactDataProperties(value, ['profileId', 'environment'])
  const profileId = profile === null ? null : parseString(profile.profileId)
  if (
    profile === null ||
    profileId === null ||
    (profile.environment !== 'development' &&
      profile.environment !== 'production')
  ) {
    return undefined
  }
  return { profileId, environment: profile.environment }
}

const parseAuthorization = (
  value: unknown,
): AuthorizationSnapshotV2['authorization'] | null => {
  const kindOnly = readExactDataProperties(value, ['kind'])
  if (kindOnly?.kind === 'authorizing') return { kind: 'authorizing' }

  const signedOut = readExactDataProperties(value, ['kind', 'reason'])
  if (
    signedOut?.kind === 'signed-out' &&
    [
      'never-authorized',
      'logged-out',
      'expired',
      'revoked',
      'invalidated',
    ].includes(String(signedOut.reason))
  ) {
    return {
      kind: 'signed-out',
      reason: signedOut.reason as 'never-authorized',
    }
  }

  const authorized = readExactDataProperties(value, [
    'kind',
    'expiresAt',
    'sessionRevision',
  ])
  const expiresAt = authorized === null ? null : parseString(authorized.expiresAt)
  const revision = authorized === null
    ? null
    : parseString(authorized.sessionRevision)
  if (
    authorized?.kind === 'authorized' &&
    expiresAt !== null &&
    Number.isFinite(Date.parse(expiresAt)) &&
    revision !== null
  ) {
    return { kind: 'authorized', expiresAt, sessionRevision: revision }
  }

  const pending = readExactDataProperties(value, ['kind', 'sessionRevision'])
  const pendingRevision = pending === null
    ? null
    : parseString(pending.sessionRevision)
  return pending?.kind === 'revocation-pending' && pendingRevision !== null
    ? { kind: 'revocation-pending', sessionRevision: pendingRevision }
    : null
}

const parseInteraction = (
  value: unknown,
): AuthorizationSnapshotV2['interaction'] | null => {
  const active = readExactDataProperties(value, ['phase'])
  if (
    active !== null &&
    ['idle', 'opening', 'authorizing', 'exchanging'].includes(
      String(active.phase),
    )
  ) {
    return { phase: active.phase as 'idle' }
  }
  const terminal = readExactDataProperties(value, ['phase', 'occurredAt'])
  const occurredAt = terminal === null ? null : parseString(terminal.occurredAt)
  if (
    terminal !== null &&
    ['cancelled', 'expired', 'failed'].includes(String(terminal.phase)) &&
    occurredAt !== null &&
    Number.isFinite(Date.parse(occurredAt))
  ) {
    return { phase: terminal.phase as 'failed', occurredAt }
  }
  return null
}

export const parseAuthorizationSnapshotV2: ValueDecoder<
  AuthorizationSnapshotV2
> = (value) => {
  const snapshot = readExactDataProperties(value, [
    'profile',
    'runtime',
    'authorization',
    'interaction',
  ])
  if (snapshot === null) return { ok: false }
  const profile = parseProfile(snapshot.profile)
  const authorization = parseAuthorization(snapshot.authorization)
  const interaction = parseInteraction(snapshot.interaction)
  if (
    profile === undefined ||
    authorization === null ||
    interaction === null ||
    ![
      'unconfigured',
      'configured',
      'starting',
      'ready',
      'degraded',
      'failed',
    ].includes(String(snapshot.runtime))
  ) {
    return { ok: false }
  }
  return {
    ok: true,
    value: {
      profile,
      runtime: snapshot.runtime as AuthorizationSnapshotV2['runtime'],
      authorization,
      interaction,
    },
  }
}

export const parseLocalTerminationOutcome: ValueDecoder<
  LocalTerminationOutcome
> = (value) => {
  const outcome = readExactDataProperties(value, ['snapshot', 'cleanup'])
  if (
    outcome === null ||
    (outcome.cleanup !== 'complete' && outcome.cleanup !== 'incomplete')
  ) {
    return { ok: false }
  }
  const snapshot = parseAuthorizationSnapshotV2(outcome.snapshot)
  return snapshot.ok
    ? { ok: true, value: { snapshot: snapshot.value, cleanup: outcome.cleanup } }
    : { ok: false }
}

export const parseAppAuthorizationResult = <Value>(
  value: unknown,
  decodeValue: ValueDecoder<Value>,
): AppAuthorizationResult<Value> | null => {
  const success = readExactDataProperties(value, ['ok', 'value'])
  if (success?.ok === true) {
    const decoded = decodeValue(success.value)
    return decoded.ok ? { ok: true, value: decoded.value } : null
  }
  const failure = readExactDataProperties(value, ['ok', 'error'])
  if (failure?.ok !== false) return null
  const error = parseFailure(failure.error)
  return error === null ? null : { ok: false, error }
}

export const parseUiRequestEnvelopeV2 = <Registry extends OperationRegistry>(
  value: unknown,
  catalog: OperationCatalog<Registry>,
): UiRequestParseResult<Registry> => {
  const request = readExactDataProperties(value, [
    'protocolVersion',
    'requestId',
    'context',
    'operation',
    'payload',
  ])
  const requestId = request === null ? null : parseString(request.requestId)
  if (
    request === null ||
    request.protocolVersion !== 2 ||
    requestId === null ||
    !contexts.has(request.context as UiContext) ||
    !operations.has(request.operation as UiOperation)
  ) {
    return {
      ok: false,
      requestId: requestId ?? 'invalid-request',
      error: 'protocol_invalid',
    }
  }
  const context = request.context as UiContext
  const operation = request.operation as UiOperation
  if (operation !== 'authorizedFetch') {
    return request.payload === null
      ? {
          ok: true,
          value: {
            protocolVersion: 2,
            requestId,
            context,
            operation,
            payload: null,
          },
        }
      : { ok: false, requestId, error: 'protocol_invalid' }
  }
  const payload = readExactDataProperties(request.payload, [
    'operationId',
    'input',
  ])
  if (payload === null || !catalog.has(payload.operationId)) {
    return { ok: false, requestId, error: 'operation_not_allowed' }
  }
  const input = catalog.parseInput(payload.operationId, payload.input)
  return input.ok
    ? {
        ok: true,
        value: {
          protocolVersion: 2,
          requestId,
          context,
          operation,
          payload: { operationId: payload.operationId, input: input.value },
        },
      }
    : { ok: false, requestId, error: 'operation_not_allowed' }
}

export const parseUiRequestV2 = <Registry extends OperationRegistry>(
  value: unknown,
  catalog: OperationCatalog<Registry>,
): ParsedUiRequestV2<Registry> | null => {
  const parsed = parseUiRequestEnvelopeV2(value, catalog)
  return parsed.ok ? parsed.value : null
}

export const parseUiResponseV2 = <Value>(
  value: unknown,
  requestId: string,
  decodeValue: ValueDecoder<Value>,
): AppAuthorizationResult<Value> | null => {
  const response = readExactDataProperties(value, [
    'protocolVersion',
    'requestId',
    'result',
  ])
  if (
    response === null ||
    response.protocolVersion !== 2 ||
    response.requestId !== requestId
  ) {
    return null
  }
  return parseAppAuthorizationResult(response.result, decodeValue)
}

export const createUiResponseV2 = <Value>(
  requestId: string,
  result: AppAuthorizationResult<Value>,
): {
  protocolVersion: 2
  requestId: string
  result: AppAuthorizationResult<Value>
} => ({ protocolVersion: 2, requestId, result })
