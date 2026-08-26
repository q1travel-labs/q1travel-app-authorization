import type {
  AppAuthorizationResult,
  AuthorizationSnapshotV2,
  LocalTerminationOutcome,
  UiContext,
} from '../publicTypes.js'
import {
  isCompiledOperationCatalog,
  type CallerOperationId,
  type CallerOperationInvocation,
  type CompiledOperationCatalog,
  type OperationOutput,
  type OperationRegistry,
} from './operationCatalog.js'
import {
  authorizationFailure,
  parseAuthorizationSnapshotV2,
  parseLocalTerminationOutcome,
  parseUiResponseV2,
  type UiOperation,
  type ValueDecoder,
} from './protocol.js'

export interface UiFacade<
  Registry extends OperationRegistry,
  Context extends UiContext,
> {
  status(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  login(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  focusAuthorization(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  logout(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
  revoke(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
  authorizedFetch<Id extends CallerOperationId<Registry, Context>>(
    operation: CallerOperationInvocation<Registry, Context, Id>,
  ): Promise<AppAuthorizationResult<OperationOutput<Registry, Id>>>
}

export interface UiTransport<
  Registry extends OperationRegistry,
  Context extends UiContext,
> {
  context: Context
  catalog: CompiledOperationCatalog<Registry>
  sendMessage(message: unknown): Promise<unknown>
}

export const createChromeAppAuthorizationUiFacade = <
  Registry extends OperationRegistry,
  const Context extends UiContext,
>(
  transport: UiTransport<Registry, Context>,
): UiFacade<Registry, Context> => {
  if (!isCompiledOperationCatalog<Registry>(transport.catalog)) {
    throw new TypeError('Authorization Operation registry is invalid.')
  }
  const catalog = transport.catalog

  const request = async <Value>(
    operation: UiOperation,
    payload: unknown,
    decodeValue: ValueDecoder<Value>,
  ): Promise<AppAuthorizationResult<Value>> => {
    const requestId = globalThis.crypto.randomUUID()
    let response: unknown
    try {
      response = await transport.sendMessage({
        protocolVersion: 2,
        requestId,
        context: transport.context,
        operation,
        payload,
      })
    } catch {
      return authorizationFailure('runtime_unavailable')
    }
    return parseUiResponseV2(response, requestId, decodeValue) ??
      authorizationFailure('protocol_invalid')
  }

  return Object.freeze({
    status: async () => await request(
      'status',
      null,
      parseAuthorizationSnapshotV2,
    ),
    login: async () => await request(
      'login',
      null,
      parseAuthorizationSnapshotV2,
    ),
    focusAuthorization: async () => await request(
      'focusAuthorization',
      null,
      parseAuthorizationSnapshotV2,
    ),
    logout: async () => await request(
      'logout',
      null,
      parseLocalTerminationOutcome,
    ),
    revoke: async () => await request(
      'revoke',
      null,
      parseLocalTerminationOutcome,
    ),
    authorizedFetch: async <Id extends CallerOperationId<Registry, Context>>(
      operation: CallerOperationInvocation<Registry, Context, Id>,
    ) => {
      const input = catalog.parseInput(operation.operationId, operation.input)
      if (!input.ok) return authorizationFailure('operation_not_allowed')
      return await request<OperationOutput<Registry, Id>>(
        'authorizedFetch',
        { operationId: operation.operationId, input: input.value },
        (candidate) => catalog.parseOutput(operation.operationId, candidate),
      )
    },
  })
}
