import {
  validateWebCallback,
  type ValidatedWebCallback,
} from '../core/callback.js'
import type { CoreCryptoPort } from '../core/contracts.js'
import type { ChromeMessageSenderPort } from './ports.js'
import type { TabTransactionV1 } from './sessionRepository.js'

export const WEB_MESSAGE_TIMEOUT_MS = 20_000
export const TOKEN_EXCHANGE_TIMEOUT_MS = 15_000
export const SERVER_AUTHORIZATION_CODE_LIFETIME_MS = 60_000
export const EXTERNAL_CALLBACK_MESSAGE_TYPE =
  'q1travel.extensionAuth.callback.v1'

export interface ValidateExternalCallbackInput {
  message: unknown
  sender: ChromeMessageSenderPort
  transaction: TabTransactionV1
  callbackOrigin: string
  callbackPath: string
  now: number
}

export type ExternalCallbackValidation =
  | { ok: true; value: ValidatedWebCallback }
  | { ok: false; error: 'callback_invalid' }

export type ExternalCallbackWebResponse =
  | { ok: true }
  | { ok: false; error: 'callbackRejected' | 'connectionFailed' }

const rejected = (): ExternalCallbackValidation => ({
  ok: false,
  error: 'callback_invalid',
})

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const hasExactKeys = (
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean => {
  const keys = Object.keys(value)
  return (
    keys.length === expected.length &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  )
}

const parseWebResponse = (value: unknown): ExternalCallbackWebResponse => {
  if (!isRecord(value)) return { ok: false, error: 'connectionFailed' }
  if (hasExactKeys(value, ['ok']) && value.ok === true) return { ok: true }
  if (
    hasExactKeys(value, ['ok', 'error']) &&
    value.ok === false &&
    (value.error === 'callbackRejected' || value.error === 'connectionFailed')
  ) {
    return { ok: false, error: value.error }
  }
  return { ok: false, error: 'connectionFailed' }
}

const messageCallbackUrl = (message: unknown, redirectUri: string): string | null => {
  if (!isRecord(message) || message.type !== EXTERNAL_CALLBACK_MESSAGE_TYPE) {
    return null
  }
  const query = new URLSearchParams()
  if (
    message.result === 'approved' &&
    hasExactKeys(message, ['type', 'result', 'code', 'state']) &&
    typeof message.code === 'string' &&
    typeof message.state === 'string'
  ) {
    query.set('code', message.code)
    query.set('state', message.state)
  } else if (
    message.result === 'denied' &&
    hasExactKeys(message, ['type', 'result', 'error', 'state']) &&
    message.error === 'access_denied' &&
    typeof message.state === 'string'
  ) {
    query.set('error', message.error)
    query.set('state', message.state)
  } else {
    return null
  }
  return `${redirectUri}?${query.toString()}`
}

export const validateExternalCallbackMessage = (
  input: ValidateExternalCallbackInput,
  crypto: CoreCryptoPort,
): ExternalCallbackValidation => {
  if (
    input.transaction.phase !== 'authorizing' ||
    input.transaction.authTabId !== input.sender.tab?.id ||
    input.sender.frameId !== 0 ||
    input.sender.origin !== input.callbackOrigin ||
    input.sender.url !== `${input.callbackOrigin}${input.callbackPath}` ||
    !Number.isFinite(input.now) ||
    Date.parse(input.transaction.expiresAt) <= input.now ||
    input.transaction.redirectUri !==
      `${input.callbackOrigin}${input.callbackPath}`
  ) {
    return rejected()
  }

  const callbackUrl = messageCallbackUrl(
    input.message,
    input.transaction.redirectUri,
  )
  if (callbackUrl === null) return rejected()
  return validateWebCallback(
    {
      callbackUrl,
      redirectUri: input.transaction.redirectUri,
      expectedState: input.transaction.state,
      consumedAuthorizationCodes: [],
    },
    crypto,
  )
}

export const sendExternalCallbackWithTimeout = async (
  send: () => Promise<unknown>,
): Promise<ExternalCallbackWebResponse> =>
  await new Promise((resolve) => {
    let settled = false
    const finish = (response: ExternalCallbackWebResponse): void => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      resolve(response)
    }
    const timeout = setTimeout(
      () => finish({ ok: false, error: 'connectionFailed' }),
      WEB_MESSAGE_TIMEOUT_MS,
    )
    void Promise.resolve()
      .then(send)
      .then(
        (value) => finish(parseWebResponse(value)),
        () => finish({ ok: false, error: 'connectionFailed' }),
      )
  })
