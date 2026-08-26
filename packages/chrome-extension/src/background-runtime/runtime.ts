import type { ChromeMessageSenderPort } from '../chrome-adapter/ports.js'
import { EXTERNAL_CALLBACK_MESSAGE_TYPE } from '../chrome-adapter/externalCallback.js'
import { BOOTSTRAP_MESSAGE_TYPE } from '../chrome-adapter/tabCoordinator.js'
import type { AuthorizationSnapshotV2 } from '../core/contracts.js'
import type { AuthorizationCoordinator } from './authorizationCoordinator.js'

export type RuntimeAuthorizationCoordinator = Pick<
  AuthorizationCoordinator,
  | 'login'
  | 'status'
  | 'focusAuthorization'
  | 'handleBootstrapReport'
  | 'handleExternalCallback'
  | 'runPostResponseCleanup'
  | 'handleAlarm'
  | 'handleTabRemoved'
>

export class BackgroundRuntime {
  constructor(
    private readonly coordinator: RuntimeAuthorizationCoordinator,
    private readonly readiness: Promise<void>,
  ) {}

  async start(): Promise<AuthorizationSnapshotV2> {
    await this.readiness
    return await this.coordinator.status()
  }

  async status(): Promise<AuthorizationSnapshotV2> {
    await this.readiness
    return await this.coordinator.status()
  }

  async login(): Promise<AuthorizationSnapshotV2> {
    await this.readiness
    return await this.coordinator.login()
  }

  async focusAuthorization(): Promise<AuthorizationSnapshotV2> {
    await this.readiness
    return await this.coordinator.focusAuthorization()
  }

  readonly handleInternalMessage = (
    message: unknown,
    sender: ChromeMessageSenderPort,
    sendResponse: (response: unknown) => void,
  ): true | void => {
    if (!hasMessageType(message, BOOTSTRAP_MESSAGE_TYPE)) return
    void this.readiness
      .then(() => this.coordinator.handleBootstrapReport(message, sender))
      .then(
        (response) => respondSafely(sendResponse, response),
        () => respondSafely(sendResponse, false),
      )
    return true
  }

  readonly handleExternalMessage = (
    message: unknown,
    sender: ChromeMessageSenderPort,
    sendResponse: (response: unknown) => void,
  ): true | void => {
    if (!hasMessageType(message, EXTERNAL_CALLBACK_MESSAGE_TYPE)) return
    void this.readiness
      .then(() => this.coordinator.handleExternalCallback(message, sender))
      .then(async (response) => {
        respondSafely(sendResponse, response)
        await this.coordinator.runPostResponseCleanup().catch(() => undefined)
      }, () => {
        respondSafely(sendResponse, {
          ok: false,
          error: 'connectionFailed',
        })
      })
      .catch(() => undefined)
    return true
  }

  readonly handleTabRemoved = (tabId: number): void => {
    void this.readiness
      .then(() => this.coordinator.handleTabRemoved(tabId))
      .catch(() => undefined)
  }

  readonly handleAlarm = (alarm: { name: string }): void => {
    void this.readiness
      .then(() => this.coordinator.handleAlarm(alarm))
      .catch(() => undefined)
  }
}

const hasMessageType = (message: unknown, expected: string): boolean =>
  typeof message === 'object' &&
  message !== null &&
  !Array.isArray(message) &&
  (message as Record<string, unknown>).type === expected

const respondSafely = (
  sendResponse: (response: unknown) => void,
  response: unknown,
): void => {
  try {
    sendResponse(response)
  } catch {
    // The sender may have disconnected while the durable result was committed.
  }
}
