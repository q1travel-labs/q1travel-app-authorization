import type { CoreCryptoPort } from './contracts.js'

const STATE_PATTERN = /^[A-Za-z0-9_-]{43}$/u
const MAX_AUTHORIZATION_CODE_LENGTH = 4096
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/u

export interface ValidateWebCallbackInput {
  callbackUrl: string
  redirectUri: string
  expectedState: string
  consumedAuthorizationCodes: readonly string[]
}

export type ValidatedWebCallback =
  | { kind: 'approved'; code: string }
  | { kind: 'denied' }

export type WebCallbackValidation =
  | { ok: true; value: ValidatedWebCallback }
  | { ok: false; error: 'callback_invalid' }

const rejected = (): WebCallbackValidation => ({
  ok: false,
  error: 'callback_invalid',
})

const hasExactKeys = (
  entries: readonly (readonly [string, string])[],
  expected: readonly string[],
): boolean =>
  entries.length === expected.length &&
  expected.every(
    (key) => entries.filter(([candidate]) => candidate === key).length === 1,
  )

export const validateWebCallback = (
  input: ValidateWebCallbackInput,
  crypto: CoreCryptoPort,
): WebCallbackValidation => {
  let callback: URL
  let redirect: URL
  try {
    callback = new URL(input.callbackUrl)
    redirect = new URL(input.redirectUri)
  } catch {
    return rejected()
  }

  if (
    redirect.search !== '' ||
    redirect.hash !== '' ||
    callback.origin !== redirect.origin ||
    callback.pathname !== redirect.pathname ||
    callback.username !== '' ||
    callback.password !== '' ||
    callback.hash !== ''
  ) {
    return rejected()
  }

  const entries = [...callback.searchParams.entries()]
  const callbackState = callback.searchParams.get('state')
  let stateMatches = false
  try {
    stateMatches =
      callbackState !== null &&
      crypto.timingSafeEqual(callbackState, input.expectedState)
  } catch {
    return rejected()
  }
  if (
    callbackState === null ||
    !STATE_PATTERN.test(callbackState) ||
    !stateMatches
  ) {
    return rejected()
  }

  if (hasExactKeys(entries, ['error', 'state'])) {
    return callback.searchParams.get('error') === 'access_denied'
      ? { ok: true, value: { kind: 'denied' } }
      : rejected()
  }

  if (!hasExactKeys(entries, ['code', 'state'])) return rejected()

  const code = callback.searchParams.get('code')
  const codeWasConsumed =
    code !== null && input.consumedAuthorizationCodes.includes(code)
  if (
    code === null ||
    code.length === 0 ||
    code.length > MAX_AUTHORIZATION_CODE_LENGTH ||
    CONTROL_CHARACTER_PATTERN.test(code) ||
    codeWasConsumed
  ) {
    return rejected()
  }

  return { ok: true, value: { kind: 'approved', code } }
}
