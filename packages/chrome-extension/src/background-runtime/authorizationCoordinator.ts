import {
  TOKEN_EXCHANGE_TIMEOUT_MS,
  validateExternalCallbackMessage,
} from '../chrome-adapter/externalCallback.js'
import type { ChromeMessageSenderPort } from '../chrome-adapter/ports.js'
import type {
  CreateOpeningTransactionInput,
  SessionTransactionRepository,
  TabTransactionV1,
} from '../chrome-adapter/sessionRepository.js'
import { createOpeningTransaction } from '../chrome-adapter/sessionRepository.js'
import type { TabCoordinator } from '../chrome-adapter/tabCoordinator.js'
import type {
  AuthorizationGrantMetadata,
  AuthorizationSnapshotV2,
  CoreCryptoPort,
  PreparedAuthorization,
} from '../core/contracts.js'
import { reconcileAuthorizationState } from '../core/reconcile.js'

export const AUTHORIZATION_TRANSACTION_ALARM =
  'q1travel.appAuthorization.transactionDeadline.v1'

export interface StoredAuthorizationGrant extends AuthorizationGrantMetadata {
  accessToken: string
}

export interface AuthorizationStatePort {
  readSnapshot(): Promise<AuthorizationSnapshotV2>
  saveSnapshot(snapshot: AuthorizationSnapshotV2): Promise<void>
  readGrant(): Promise<StoredAuthorizationGrant | null>
  saveGrant(grant: StoredAuthorizationGrant): Promise<void>
}

export interface AuthorizationAlarmPort {
  create(name: string, input: { when: number }): Promise<void>
  clear(name: string): Promise<boolean>
}

export interface BeginAuthorizationResult
  extends Omit<CreateOpeningTransactionInput, 'prepared' | 'now'> {
  prepared: PreparedAuthorization
}

export interface CreateAuthorizationCoordinatorInput {
  transactions: SessionTransactionRepository
  tabs: TabCoordinator
  alarms: AuthorizationAlarmPort
  state: AuthorizationStatePort
  crypto: CoreCryptoPort
  callbackOrigin: string
  callbackPath: string
  now(): number
  beginAuthorization(): Promise<BeginAuthorizationResult>
  exchange(input: {
    code: string
    codeVerifier: string
    redirectUri: string
    signal: AbortSignal
  }): Promise<StoredAuthorizationGrant>
}

export type ExternalCallbackResponse =
  | { ok: true }
  | { ok: false; error: 'callbackRejected' | 'connectionFailed' }

export interface AuthorizationCoordinator {
  login(): Promise<AuthorizationSnapshotV2>
  status(): Promise<AuthorizationSnapshotV2>
  focusAuthorization(): Promise<AuthorizationSnapshotV2>
  handleExternalCallback(
    message: unknown,
    sender: ChromeMessageSenderPort,
  ): Promise<ExternalCallbackResponse>
  runPostResponseCleanup(): Promise<void>
  handleBootstrapReport(
    message: unknown,
    sender: ChromeMessageSenderPort,
  ): Promise<boolean>
  handleAlarm(alarm: { name: string }): Promise<void>
  handleTabRemoved(tabId: number): Promise<void>
}

const flights = new Map<string, Promise<void>>()
const ACTIVE_TRANSACTION_FLIGHT = 'active-authorization-transaction'

const serialize = async <T>(
  transactionId: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const previous = flights.get(transactionId) ?? Promise.resolve()
  let release!: () => void
  const current = new Promise<void>((resolve) => {
    release = resolve
  })
  const queued = previous.catch(() => undefined).then(() => current)
  flights.set(transactionId, queued)
  await previous.catch(() => undefined)
  try {
    return await operation()
  } finally {
    release()
    if (flights.get(transactionId) === queued) flights.delete(transactionId)
  }
}

const activeSnapshot = (
  snapshot: AuthorizationSnapshotV2,
  phase: 'opening' | 'authorizing' | 'exchanging',
): AuthorizationSnapshotV2 => ({
  ...snapshot,
  authorization: { kind: 'authorizing' },
  interaction: { phase },
})

const terminalSnapshot = (
  snapshot: AuthorizationSnapshotV2,
  phase: 'cancelled' | 'expired' | 'failed',
  now: number,
): AuthorizationSnapshotV2 => ({
  ...snapshot,
  authorization:
    snapshot.authorization.kind === 'authorized'
      ? snapshot.authorization
      : { kind: 'signed-out', reason: 'never-authorized' },
  interaction: { phase, occurredAt: new Date(now).toISOString() },
})

const authorizedSnapshot = (
  snapshot: AuthorizationSnapshotV2,
  grant: AuthorizationGrantMetadata,
): AuthorizationSnapshotV2 => ({
  ...snapshot,
  authorization: {
    kind: 'authorized',
    expiresAt: grant.expiresAt,
    sessionRevision: grant.sessionRevision,
  },
  interaction: { phase: 'idle' },
})

const grantIsValid = (
  grant: StoredAuthorizationGrant | null,
  now: number,
): grant is StoredAuthorizationGrant =>
  grant !== null &&
  Number.isFinite(now) &&
  Date.parse(grant.expiresAt) > now

export const createAuthorizationCoordinator = (
  input: CreateAuthorizationCoordinatorInput,
): AuthorizationCoordinator => {
  const saveSnapshotIfChanged = async (
    current: AuthorizationSnapshotV2,
    next: AuthorizationSnapshotV2,
  ): Promise<void> => {
    if (JSON.stringify(current) !== JSON.stringify(next)) {
      await input.state.saveSnapshot(next)
    }
  }

  const exchangeWithTimeout = async (
    code: string,
    transaction: TabTransactionV1,
  ): Promise<StoredAuthorizationGrant> => {
    const abort = new AbortController()
    return await new Promise((resolve, reject) => {
      let settled = false
      const finish = (
        complete: () => void,
      ): void => {
        if (settled) return
        settled = true
        clearTimeout(timeout)
        complete()
      }
      const timeout = setTimeout(() => {
        abort.abort()
        finish(() => reject(new Error('Token exchange timed out')))
      }, TOKEN_EXCHANGE_TIMEOUT_MS)
      void Promise.resolve()
        .then(() =>
          input.exchange({
            code,
            codeVerifier: transaction.codeVerifier,
            redirectUri: transaction.redirectUri,
            signal: abort.signal,
          }),
        )
        .then(
          (grant) => finish(() => resolve(grant)),
          (error: unknown) => finish(() => reject(error)),
        )
    })
  }

  const clearTransactionStorage = async (): Promise<void> => {
    await input.alarms.clear(AUTHORIZATION_TRANSACTION_ALARM)
    await input.transactions.remove()
  }

  const cleanupTransaction = async (
    transaction: TabTransactionV1,
  ): Promise<boolean> => {
    const completion = await input.tabs.complete(transaction)
    if (completion === 'retry') return false
    await clearTransactionStorage()
    return true
  }

  const reconcile = async (
    performCleanup = true,
  ): Promise<{
    snapshot: AuthorizationSnapshotV2
    transaction: TabTransactionV1 | null
    cleanupPending: TabTransactionV1 | null
  }> => {
    const now = input.now()
    const [snapshot, grant, transaction] = await Promise.all([
      input.state.readSnapshot(),
      input.state.readGrant(),
      input.transactions.loadStored(),
    ])
    if (transaction === null) {
      if (grantIsValid(grant, now)) {
        const authorized = authorizedSnapshot(snapshot, grant)
        await saveSnapshotIfChanged(snapshot, authorized)
        return {
          snapshot: authorized,
          transaction: null,
          cleanupPending: null,
        }
      }
      if (
        snapshot.interaction.phase === 'opening' ||
        snapshot.interaction.phase === 'authorizing' ||
        snapshot.interaction.phase === 'exchanging'
      ) {
        const failed = terminalSnapshot(snapshot, 'failed', now)
        await saveSnapshotIfChanged(snapshot, failed)
        return { snapshot: failed, transaction: null, cleanupPending: null }
      }
      return { snapshot, transaction: null, cleanupPending: null }
    }

    const reconciled = reconcileAuthorizationState({
      snapshot,
      grant,
      transaction: {
        phase: transaction.phase,
        createdAt: transaction.createdAt,
      },
      now: new Date(now).toISOString(),
    })
    if (reconciled.transaction === null) {
      await saveSnapshotIfChanged(snapshot, reconciled.snapshot)
      const cleaned =
        performCleanup && (await cleanupTransaction(transaction))
      return {
        snapshot: reconciled.snapshot,
        transaction: null,
        cleanupPending: cleaned ? null : transaction,
      }
    }

    if (transaction.phase === 'exchanging') {
      const failed = terminalSnapshot(snapshot, 'failed', now)
      await saveSnapshotIfChanged(snapshot, failed)
      const cleaned =
        performCleanup && (await cleanupTransaction(transaction))
      return {
        snapshot: failed,
        transaction: null,
        cleanupPending: cleaned ? null : transaction,
      }
    }
    if (Date.parse(transaction.expiresAt) <= now) {
      const expired = terminalSnapshot(snapshot, 'expired', now)
      await saveSnapshotIfChanged(snapshot, expired)
      const cleaned =
        performCleanup && (await cleanupTransaction(transaction))
      return {
        snapshot: expired,
        transaction: null,
        cleanupPending: cleaned ? null : transaction,
      }
    }
    return { snapshot, transaction, cleanupPending: null }
  }

  const failCompletion = async (
    transaction: TabTransactionV1,
  ): Promise<void> => {
    const [snapshot, grant] = await Promise.all([
      input.state.readSnapshot(),
      input.state.readGrant(),
    ])
    if (grantIsValid(grant, input.now())) {
      await saveSnapshotIfChanged(
        snapshot,
        authorizedSnapshot(snapshot, grant),
      )
    } else {
      await saveSnapshotIfChanged(
        snapshot,
        terminalSnapshot(snapshot, 'failed', input.now()),
      )
    }
  }

  return {
    async status() {
      return await serialize(
        ACTIVE_TRANSACTION_FLIGHT,
        async () => (await reconcile()).snapshot,
      )
    },

    async login() {
      return await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const current = await reconcile()
        if (current.cleanupPending !== null) return current.snapshot
        if (current.transaction !== null) {
          await input.tabs.focus(current.transaction)
          return current.snapshot
        }

        const beginning = await input.beginAuthorization()
        const opening = createOpeningTransaction({
          ...beginning,
          now: input.now(),
        })
        await input.transactions.save(opening)
        try {
          await input.alarms.create(AUTHORIZATION_TRANSACTION_ALARM, {
            when: Date.parse(opening.expiresAt),
          })
          const snapshot = activeSnapshot(current.snapshot, 'opening')
          await input.state.saveSnapshot(snapshot)
          const opened = await input.tabs.open(
            opening,
            beginning.prepared.authorizeUrl,
          )
          const authorizing = activeSnapshot(snapshot, 'authorizing')
          try {
            await input.state.saveSnapshot(authorizing)
          } catch (error) {
            await cleanupTransaction(opened)
            throw error
          }
          return authorizing
        } catch (error) {
          try {
            const retained = await input.transactions.loadStored()
            if (retained === null || retained.authTabId === null) {
              await input.transactions.remove().catch(() => undefined)
              await input.alarms
                .clear(AUTHORIZATION_TRANSACTION_ALARM)
                .catch(() => undefined)
            }
          } catch {
            // Without the sealed binding, cleanup must not guess a tab id.
          }
          try {
            const [snapshot, grant] = await Promise.all([
              input.state.readSnapshot(),
              input.state.readGrant(),
            ])
            await input.state.saveSnapshot(
              grantIsValid(grant, input.now())
                ? authorizedSnapshot(snapshot, grant)
                : terminalSnapshot(snapshot, 'failed', input.now()),
            )
          } catch {
            // Preserve the initiating fault; the next action reconciles storage.
          }
          throw error
        }
      })
    },

    async focusAuthorization() {
      return await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const current = await reconcile()
        if (current.transaction === null) return current.snapshot
        const focusResult = await input.tabs.focus(current.transaction)
        if (focusResult !== 'missing') return current.snapshot
        const expired = terminalSnapshot(
          current.snapshot,
          'expired',
          input.now(),
        )
        await input.state.saveSnapshot(expired)
        await clearTransactionStorage()
        return expired
      })
    },

    async handleBootstrapReport(message, sender) {
      return await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const stored = await input.transactions.loadStored()
        if (stored === null) return false
        const current = await reconcile()
        if (current.transaction === null) return false
        return await input.tabs.handleBootstrapReport(message, sender)
      })
    },

    async handleExternalCallback(message, sender) {
      return await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const candidate = await input.transactions.loadStored()
        if (candidate === null) {
          await reconcile(false)
          return { ok: false, error: 'callbackRejected' }
        }
        const current = await reconcile(false)
        if (current.transaction === null) {
          return { ok: false, error: 'callbackRejected' }
        }
        if (current.transaction.phase !== 'authorizing') {
          return { ok: false, error: 'callbackRejected' }
        }
        const validated = validateExternalCallbackMessage(
          {
            message,
            sender,
            transaction: current.transaction,
            callbackOrigin: input.callbackOrigin,
            callbackPath: input.callbackPath,
            now: input.now(),
          },
          input.crypto,
        )
        if (!validated.ok) {
          return { ok: false, error: 'callbackRejected' }
        }

        if (validated.value.kind === 'denied') {
          try {
            const cancelled = terminalSnapshot(
              current.snapshot,
              'cancelled',
              input.now(),
            )
            await input.state.saveSnapshot(cancelled)
            return { ok: true }
          } catch {
            return { ok: false, error: 'connectionFailed' }
          }
        }

        const exchanging: TabTransactionV1 = {
          ...current.transaction,
          phase: 'exchanging',
          authTabId: current.transaction.authTabId,
        }
        try {
          await input.transactions.save(exchanging)
          await input.state.saveSnapshot(
            activeSnapshot(current.snapshot, 'exchanging'),
          )
          const grant = await exchangeWithTimeout(
            validated.value.code,
            exchanging,
          )
          await input.state.saveGrant(grant)
          await input.state.saveSnapshot(
            authorizedSnapshot(current.snapshot, grant),
          )
          return { ok: true }
        } catch {
          try {
            await failCompletion(exchanging)
          } catch {
            // The next public action repeats reconciliation from sealed state.
          }
          return { ok: false, error: 'connectionFailed' }
        }
      })
    },

    async runPostResponseCleanup() {
      await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        await reconcile()
      })
    },

    async handleAlarm(alarm) {
      if (alarm.name !== AUTHORIZATION_TRANSACTION_ALARM) return
      await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const stored = await input.transactions.loadStored()
        if (stored === null) return
        const current = await reconcile()
        if (current.transaction === null) return
        if (Date.parse(current.transaction.expiresAt) > input.now()) return
        const expired = terminalSnapshot(
          current.snapshot,
          'expired',
          input.now(),
        )
        await input.state.saveSnapshot(expired)
        await cleanupTransaction(current.transaction)
      })
    },

    async handleTabRemoved(tabId) {
      await serialize(ACTIVE_TRANSACTION_FLIGHT, async () => {
        const stored = await input.transactions.loadStored()
        if (stored === null || stored.authTabId !== tabId) return
        const current = await reconcile(false)
        if (current.cleanupPending?.authTabId === tabId) {
          await clearTransactionStorage()
          return
        }
        if (
          current.transaction === null ||
          current.transaction.authTabId !== tabId
        ) {
          return
        }
        const cancelled = terminalSnapshot(
          current.snapshot,
          'cancelled',
          input.now(),
        )
        await input.state.saveSnapshot(cancelled)
        await clearTransactionStorage()
      })
    },
  }
}
