import type {
  AppAuthorizationResult,
  AuthorizationSnapshotV2,
  LocalTerminationOutcome,
  UiContext,
} from '../publicTypes.js'
import { BackgroundRuntime as Task3BackgroundRuntime } from '../background-runtime/runtime.js'
import { createAuthorizationCoordinator } from '../background-runtime/authorizationCoordinator.js'
import { installChromeAppAuthorizationListeners } from '../chrome-adapter/listenerInstaller.js'
import { createSessionTransactionRepository } from '../chrome-adapter/sessionRepository.js'
import { createTabCoordinator } from '../chrome-adapter/tabCoordinator.js'
import { readExactDataProperties } from '../ui-facade/data.js'
import {
  isCompiledOperationCatalog,
  type CompiledOperationCatalog,
  type OperationId,
  type OperationInvocation,
  type OperationOutput,
  type OperationRegistry,
} from '../ui-facade/operationCatalog.js'
import {
  authorizationFailure,
  createUiResponseV2,
  parseAppAuthorizationResult,
  parseAuthorizationSnapshotV2,
  parseLocalTerminationOutcome,
  parseUiRequestEnvelopeV2,
  type ValueDecoder,
} from '../ui-facade/protocol.js'
import type {
  BackgroundOnlyMessageSender,
  BackgroundOnlyRuntimeResources,
} from './backgroundOnly.js'

export interface ConfigurePort<Configuration> {
  configure(
    configuration: Configuration,
  ): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
}

export interface TerminationPort {
  logout(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
  revoke(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
}

export interface OperationExecutor<Registry extends OperationRegistry> {
  execute(
    operationId: OperationId<Registry>,
    input: unknown,
  ): Promise<AppAuthorizationResult<unknown>>
}

export type UiMessageSender = BackgroundOnlyMessageSender

export type UiRequestDispatcher = (
  message: unknown,
  sender: UiMessageSender,
  sendResponse: (response: unknown) => void,
) => true | void

export interface SenderPolicy {
  expectedExtensionId: string
  entryPaths: Readonly<Record<UiContext, string>>
  managementCallers: readonly UiContext[]
}

export interface ChromeAppAuthorizationRuntimeDependencies<
  Configuration,
  Registry extends OperationRegistry,
> {
  background: BackgroundOnlyRuntimeResources
  configure: ConfigurePort<Configuration>
  termination: TerminationPort
  operationExecutor: OperationExecutor<Registry>
  catalog: CompiledOperationCatalog<Registry>
  senderPolicy: SenderPolicy
}

export interface BackgroundRuntime<
  Configuration,
  Registry extends OperationRegistry,
> {
  configure(
    configuration: Configuration,
  ): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  start(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  status(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  login(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  focusAuthorization(): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>>
  logout(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
  revoke(): Promise<AppAuthorizationResult<LocalTerminationOutcome>>
  authorizedFetch<Id extends OperationId<Registry>>(
    operation: OperationInvocation<Registry, Id>,
  ): Promise<AppAuthorizationResult<OperationOutput<Registry, Id>>>
}

const uiContexts = new Set<UiContext>(['popup', 'options', 'side-panel'])
const managementOperations = new Set([
  'login',
  'focusAuthorization',
  'logout',
  'revoke',
])

interface CompiledSenderPolicy {
  expectedExtensionId: string
  entryPaths: Readonly<Record<UiContext, string>>
  managementCallers: ReadonlySet<UiContext>
}

const readDataArray = (value: unknown): unknown[] | null => {
  try {
    if (!Array.isArray(value) || value.length > 3) return null
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

const compileSenderPolicy = (value: unknown): CompiledSenderPolicy | null => {
  const policy = readExactDataProperties(value, [
    'expectedExtensionId',
    'entryPaths',
    'managementCallers',
  ])
  const entryPaths = policy === null
    ? null
    : readExactDataProperties(policy.entryPaths, [
        'popup',
        'options',
        'side-panel',
      ])
  const callers = policy === null ? null : readDataArray(policy.managementCallers)
  if (
    policy === null ||
    entryPaths === null ||
    callers === null ||
    typeof policy.expectedExtensionId !== 'string' ||
    !/^[a-p]{32}$/.test(policy.expectedExtensionId) ||
    callers.some((context) => !uiContexts.has(context as UiContext)) ||
    new Set(callers).size !== callers.length
  ) {
    return null
  }
  const paths = Object.create(null) as Record<UiContext, string>
  for (const context of uiContexts) {
    const path = entryPaths[context]
    if (
      typeof path !== 'string' ||
      !/^\/[A-Za-z0-9/_-]+\.html$/.test(path)
    ) {
      return null
    }
    paths[context] = path
  }
  return {
    expectedExtensionId: policy.expectedExtensionId,
    entryPaths: Object.freeze(paths),
    managementCallers: new Set(callers as UiContext[]),
  }
}

const senderField = (sender: unknown, field: string): unknown => {
  try {
    if (typeof sender !== 'object' || sender === null) return undefined
    const descriptor = Object.getOwnPropertyDescriptor(sender, field)
    return descriptor !== undefined &&
      descriptor.enumerable &&
      Object.hasOwn(descriptor, 'value')
      ? descriptor.value
      : undefined
  } catch {
    return undefined
  }
}

const senderIsAllowed = (
  sender: unknown,
  context: UiContext,
  policy: CompiledSenderPolicy,
): boolean =>
  senderField(sender, 'id') === policy.expectedExtensionId &&
  senderField(sender, 'frameId') === 0 &&
  senderField(sender, 'url') ===
    `chrome-extension://${policy.expectedExtensionId}${policy.entryPaths[context]}`

export const createChromeAppAuthorizationRuntime = <
  Configuration,
  Registry extends OperationRegistry,
>(
  dependencies: ChromeAppAuthorizationRuntimeDependencies<
    Configuration,
    Registry
  >,
): BackgroundRuntime<Configuration, Registry> => {
  const catalog = dependencies.catalog
  const senderPolicy = compileSenderPolicy(dependencies.senderPolicy)
  if (!isCompiledOperationCatalog<Registry>(catalog) || senderPolicy === null) {
    throw new TypeError('Authorization runtime configuration is invalid.')
  }
  const transactions = createSessionTransactionRepository(
    dependencies.background.chrome.storage,
  )
  const tabs = createTabCoordinator({
    chrome: dependencies.background.chrome,
    transactions,
    now: dependencies.background.profile.now,
    authorizationUrl: dependencies.background.profile.authorizationUrl,
  })
  const coordinator = createAuthorizationCoordinator({
    transactions,
    tabs,
    alarms: dependencies.background.chrome.alarms,
    state: dependencies.background.state,
    crypto: dependencies.background.crypto,
    callbackOrigin: dependencies.background.profile.callbackOrigin,
    callbackPath: dependencies.background.profile.callbackPath,
    now: dependencies.background.profile.now,
    beginAuthorization: dependencies.background.profile.beginAuthorization,
    exchange: dependencies.background.profile.exchange,
  })
  const background = new Task3BackgroundRuntime(
    coordinator,
    transactions.ready(),
  )

  const runResultPort = async <Value>(
    invoke: () => Promise<unknown>,
    decoder: ValueDecoder<Value>,
  ): Promise<AppAuthorizationResult<Value>> => {
    try {
      const result = parseAppAuthorizationResult(await invoke(), decoder)
      return result ?? authorizationFailure('protocol_invalid')
    } catch {
      return authorizationFailure('runtime_unavailable')
    }
  }
  const runBackground = async (
    invoke: () => Promise<unknown>,
  ): Promise<AppAuthorizationResult<AuthorizationSnapshotV2>> => {
    try {
      const snapshot = parseAuthorizationSnapshotV2(await invoke())
      return snapshot.ok
        ? { ok: true, value: snapshot.value }
        : authorizationFailure('protocol_invalid')
    } catch {
      return authorizationFailure('runtime_unavailable')
    }
  }
  const runOperation = async <Id extends OperationId<Registry>>(
    operationId: Id,
    inputValue: unknown,
  ): Promise<AppAuthorizationResult<OperationOutput<Registry, Id>>> => {
    const input = catalog.parseInput(operationId, inputValue)
    if (!input.ok) return authorizationFailure('operation_not_allowed')
    return await runResultPort(
      async () => await dependencies.operationExecutor.execute(
        operationId,
        input.value,
      ),
      (output) => catalog.parseOutput(operationId, output),
    )
  }

  const runtime: BackgroundRuntime<Configuration, Registry> = Object.freeze({
    configure: async (configuration: Configuration) => await runResultPort(
      async () => await dependencies.configure.configure(configuration),
      parseAuthorizationSnapshotV2,
    ),
    start: async () => await runBackground(
      async () => await background.start(),
    ),
    status: async () => await runBackground(
      async () => await background.status(),
    ),
    login: async () => await runBackground(
      async () => await background.login(),
    ),
    focusAuthorization: async () => await runBackground(
      async () => await background.focusAuthorization(),
    ),
    logout: async () => await runResultPort(
      async () => await dependencies.termination.logout(),
      parseLocalTerminationOutcome,
    ),
    revoke: async () => await runResultPort(
      async () => await dependencies.termination.revoke(),
      parseLocalTerminationOutcome,
    ),
    authorizedFetch: async <Id extends OperationId<Registry>>(
      operation: OperationInvocation<Registry, Id>,
    ) => await runOperation(operation.operationId, operation.input),
  })

  const dispatchV2 = async (message: unknown, sender: UiMessageSender) => {
    const request = parseUiRequestEnvelopeV2(message, catalog)
    if (!request.ok) {
      return createUiResponseV2(
        request.requestId,
        authorizationFailure(request.error),
      )
    }
    const { context, operation, payload, requestId } = request.value
    const permitted = senderIsAllowed(sender, context, senderPolicy) &&
      (operation === 'status' ||
        (managementOperations.has(operation) &&
          senderPolicy.managementCallers.has(context)) ||
        (operation === 'authorizedFetch' &&
          payload !== null &&
          catalog.allows(payload.operationId, context)))
    if (!permitted) {
      return createUiResponseV2(
        requestId,
        authorizationFailure('operation_not_allowed'),
      )
    }
    if (operation === 'status') {
      return createUiResponseV2(requestId, await runtime.status())
    }
    if (operation === 'login') {
      return createUiResponseV2(requestId, await runtime.login())
    }
    if (operation === 'focusAuthorization') {
      return createUiResponseV2(requestId, await runtime.focusAuthorization())
    }
    if (operation === 'logout') {
      return createUiResponseV2(requestId, await runtime.logout())
    }
    if (operation === 'revoke') {
      return createUiResponseV2(requestId, await runtime.revoke())
    }
    if (payload === null) {
      return createUiResponseV2(
        requestId,
        authorizationFailure('protocol_invalid'),
      )
    }
    return createUiResponseV2(
      requestId,
      await runOperation(payload.operationId, payload.input),
    )
  }

  const hasOwnV2Marker = (message: unknown): boolean => {
    try {
      if (typeof message !== 'object' || message === null) return false
      const descriptor = Object.getOwnPropertyDescriptor(
        message,
        'protocolVersion',
      )
      return descriptor !== undefined &&
        descriptor.enumerable === true &&
        Object.hasOwn(descriptor, 'value') &&
        descriptor.value === 2
    } catch {
      return false
    }
  }
  const v2Listener: UiRequestDispatcher = (message, sender, sendResponse) => {
    if (!hasOwnV2Marker(message)) return
    void dispatchV2(message, sender).then(
      (response) => {
        try {
          sendResponse(response)
        } catch {
          // The sender may close while the async runtime operation completes.
        }
      },
      () => {
        try {
          sendResponse(createUiResponseV2(
            'invalid-request',
            authorizationFailure('runtime_unavailable'),
          ))
        } catch {
          // The sender may close while the async runtime operation completes.
        }
      },
    )
    return true
  }

  installChromeAppAuthorizationListeners(
    dependencies.background.chrome,
    background,
  )
  dependencies.background.chrome.runtime.onMessage.addListener(v2Listener)

  return runtime
}
