import { AppAuthorizationError, AuthErrorCode } from './types.js'

const OPAQUE_PATTERN = /^[A-Za-z0-9_-]{43}$/u

const exactKeys = (url: URL, expected: readonly string[]): boolean => {
  const entries = [...url.searchParams.keys()]
  return entries.length === expected.length &&
    expected.every((key) => entries.filter((candidate) => candidate === key).length === 1)
}

export const validateAuthorizationCallback = (
  callbackUrl: string,
  redirectUri: string,
  expectedState: string,
): string => {
  let callback: URL
  let redirect: URL
  try {
    callback = new URL(callbackUrl)
    redirect = new URL(redirectUri)
  } catch {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  if (
    callback.origin !== redirect.origin ||
    callback.pathname !== redirect.pathname ||
    callback.username !== '' ||
    callback.password !== '' ||
    callback.hash !== ''
  ) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  const state = callback.searchParams.get('state')
  if (state === null || !OPAQUE_PATTERN.test(state) || state !== expectedState) {
    throw new AppAuthorizationError(AuthErrorCode.stateMismatch)
  }
  if (exactKeys(callback, ['error', 'state'])) {
    throw new AppAuthorizationError(
      callback.searchParams.get('error') === 'access_denied'
        ? AuthErrorCode.authorizationDenied
        : AuthErrorCode.oauthInvalidRequest,
    )
  }
  if (!exactKeys(callback, ['code', 'state'])) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  const code = callback.searchParams.get('code')
  if (code === null || !OPAQUE_PATTERN.test(code)) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  return code
}
