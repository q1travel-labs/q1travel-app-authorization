import type {
  ChromeMessageSenderPort,
  ChromeTabCoordinationPort,
} from './ports.js'
import type {
  SessionTransactionRepository,
  TabTransactionV1,
} from './sessionRepository.js'

export const AUTHORIZATION_BOOTSTRAP_PATH = 'authorization-bootstrap.html'
export const BOOTSTRAP_RETRY_DELAYS_MS = [
  0, 250, 500, 1_000, 2_000, 4_000,
] as const

export const BOOTSTRAP_MESSAGE_TYPE = 'q1travel.extensionAuth.bootstrap.v1'

export interface TabCoordinator {
  open(
    transaction: TabTransactionV1,
    authorizeUrl: string,
  ): Promise<AuthorizingTabTransactionV1>
  handleBootstrapReport(
    message: unknown,
    sender: ChromeMessageSenderPort,
  ): Promise<boolean>
  focus(
    transaction: TabTransactionV1,
  ): Promise<'focused' | 'missing' | 'failed'>
  complete(
    transaction: TabTransactionV1,
  ): Promise<'closed' | 'missing' | 'retry'>
}

type AuthorizingTabTransactionV1 = TabTransactionV1 & {
  phase: 'authorizing'
  authTabId: number
}

export interface CreateTabCoordinatorInput {
  chrome: ChromeTabCoordinationPort
  transactions: SessionTransactionRepository
  now(): number
  authorizationUrl(transaction: TabTransactionV1): Promise<string>
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const isExactBootstrapMessage = (message: unknown): boolean =>
  isRecord(message) &&
  Object.keys(message).length === 1 &&
  message.type === BOOTSTRAP_MESSAGE_TYPE

const cleanupAfterFailure = async (
  input: CreateTabCoordinatorInput,
  transaction: TabTransactionV1,
  authTabId: number | null,
  cause: unknown,
): Promise<never> => {
  const cleanupErrors: unknown[] = []
  if (authTabId !== null) {
    try {
      await input.chrome.tabs.remove(authTabId)
    } catch (error) {
      cleanupErrors.push(error)
      try {
        const stored = await input.transactions.loadStored()
        if (stored?.authTabId !== authTabId) {
          await input.transactions.save({
            ...transaction,
            phase: 'opening',
            authTabId,
          })
        }
      } catch (bindingError) {
        cleanupErrors.push(bindingError)
      }
      throw new AggregateError(
        [cause, ...cleanupErrors],
        'Tab cleanup failed',
      )
    }
  }
  try {
    await input.transactions.remove()
  } catch (error) {
    cleanupErrors.push(error)
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError([cause, ...cleanupErrors], 'Tab cleanup failed')
  }
  throw cause
}

const authorizing = (
  transaction: TabTransactionV1,
  authTabId: number,
): AuthorizingTabTransactionV1 => ({
  ...transaction,
  phase: 'authorizing',
  authTabId,
})

export const createTabCoordinator = (
  input: CreateTabCoordinatorInput,
): TabCoordinator => {
  const bootstrapUrl = input.chrome.runtime.getURL(AUTHORIZATION_BOOTSTRAP_PATH)
  const extensionOrigin = `chrome-extension://${input.chrome.runtime.id}`

  const bindAndNavigate = async (
    transaction: TabTransactionV1,
    authTabId: number,
    bind: boolean,
    preparedAuthorizeUrl?: string,
  ): Promise<AuthorizingTabTransactionV1> => {
    try {
      if (bind) {
        await input.transactions.save({
          ...transaction,
          phase: 'opening',
          authTabId,
        })
      }
      const active = authorizing(transaction, authTabId)
      await input.transactions.save(active)
      const authorizeUrl =
        preparedAuthorizeUrl ?? (await input.authorizationUrl(active))
      await input.chrome.tabs.update(authTabId, { url: authorizeUrl })
      return active
    } catch (error) {
      return await cleanupAfterFailure(input, transaction, authTabId, error)
    }
  }

  return {
    async open(transaction, authorizeUrl) {
      if (transaction.phase !== 'opening') {
        throw new Error('Authorization tab can open only once')
      }
      let created
      try {
        created = await input.chrome.tabs.create({
          url: bootstrapUrl,
          windowId: transaction.sourceWindowId,
          openerTabId: transaction.sourceTabId,
          active: true,
        })
      } catch (error) {
        return await cleanupAfterFailure(input, transaction, null, error)
      }
      if (
        typeof created.id !== 'number' ||
        !Number.isInteger(created.id) ||
        created.id < 0
      ) {
        return await cleanupAfterFailure(
          input,
          transaction,
          null,
          new Error('Created authorization tab has no id'),
        )
      }
      return await bindAndNavigate(transaction, created.id, true, authorizeUrl)
    },

    async handleBootstrapReport(message, sender) {
      if (
        !isExactBootstrapMessage(message) ||
        sender.id !== input.chrome.runtime.id ||
        sender.frameId !== 0 ||
        sender.origin !== extensionOrigin ||
        sender.url !== bootstrapUrl ||
        typeof sender.tab?.id !== 'number' ||
        !Number.isInteger(sender.tab.id) ||
        sender.tab.id < 0
      ) {
        return false
      }

      const now = input.now()
      const transaction = await input.transactions.loadStored()
      if (
        transaction === null ||
        transaction.phase === 'exchanging' ||
        !Number.isFinite(now) ||
        Date.parse(transaction.expiresAt) <= now
      ) {
        return false
      }
      const authTabId = sender.tab.id
      if (
        transaction.authTabId !== null &&
        transaction.authTabId !== authTabId
      ) {
        return false
      }

      if (transaction.phase === 'authorizing') {
        try {
          const authorizeUrl = await input.authorizationUrl(transaction)
          await input.chrome.tabs.update(authTabId, { url: authorizeUrl })
          return true
        } catch (error) {
          return await cleanupAfterFailure(
            input,
            transaction,
            authTabId,
            error,
          )
        }
      }
      await bindAndNavigate(
        transaction,
        authTabId,
        transaction.authTabId === null,
      )
      return true
    },

    async focus(transaction) {
      if (transaction.authTabId === null) return 'missing'
      let tab
      try {
        tab = await input.chrome.tabs.get(transaction.authTabId)
      } catch {
        return 'failed'
      }
      if (tab === null) return 'missing'
      if (typeof tab.windowId !== 'number') return 'failed'
      try {
        await input.chrome.tabs.update(transaction.authTabId, { active: true })
        await input.chrome.windows.update(tab.windowId, { focused: true })
        return 'focused'
      } catch {
        return 'failed'
      }
    },

    async complete(transaction) {
      if (transaction.authTabId === null) return 'missing'
      const authTabId = transaction.authTabId
      let authTab
      try {
        authTab = await input.chrome.tabs.get(authTabId)
      } catch {
        return 'retry'
      }
      if (authTab === null) return 'missing'

      if (
        authTab.active === true &&
        authTab.windowId === transaction.sourceWindowId
      ) {
        let focused = false
        try {
          focused = (await input.chrome.windows.get(authTab.windowId)).focused
        } catch {
          focused = false
        }
        if (focused) {
          try {
            const source = await input.chrome.tabs.get(transaction.sourceTabId)
            if (source?.windowId === transaction.sourceWindowId) {
              await input.chrome.tabs.update(transaction.sourceTabId, {
                active: true,
              })
              await input.chrome.windows.update(transaction.sourceWindowId, {
                focused: true,
              })
            }
          } catch {
            // A missing source tab never changes which auth tab may be closed.
          }
        }
      }

      try {
        await input.chrome.tabs.remove(authTabId)
        return 'closed'
      } catch {
        return 'retry'
      }
    },
  }
}

export const reportBootstrapWithRetry = async (
  report: () => Promise<boolean>,
  wait: (delayMs: number) => Promise<void>,
): Promise<boolean> => {
  for (const [index, delay] of BOOTSTRAP_RETRY_DELAYS_MS.entries()) {
    if (index > 0) await wait(delay)
    try {
      if (await report()) return true
    } catch {
      // A worker wake-up failure is retried only by the bounded schedule.
    }
  }
  return false
}
