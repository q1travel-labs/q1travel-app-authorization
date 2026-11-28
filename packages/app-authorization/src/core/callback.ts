import { AppAuthorizationError, AuthErrorCode } from './types.js'

const STATE_PATTERN = /^[\x20-\x7e]{1,512}$/u

const exactKeys = (url: URL, expected: readonly string[]): boolean => {
  const entries = [...url.searchParams.keys()]
  return entries.length === expected.length &&
    expected.every((key) => entries.filter((candidate) => candidate === key).length === 1)
}

export const validateAuthorizationCallback = (
  callbackUrl: string,
  redirectUri: string,
  expectedState: string,
  issuer: string,
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
    callbackUrl.split('?')[0] !== redirectUri || callbackUrl.includes('#') ||
    callback.origin !== redirect.origin ||
    callback.pathname !== redirect.pathname ||
    callback.username !== '' ||
    callback.password !== '' ||
    callback.hash !== ''
  ) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  const state = callback.searchParams.get('state')
  if (state === null || !STATE_PATTERN.test(state) || state !== expectedState) {
    throw new AppAuthorizationError(AuthErrorCode.stateMismatch)
  }
  if (callback.searchParams.get('iss') !== issuer) throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  if (exactKeys(callback, ['error', 'state', 'iss'])) {
    throw new AppAuthorizationError(
      callback.searchParams.get('error') === 'access_denied'
        ? AuthErrorCode.authorizationDenied
        : AuthErrorCode.oauthInvalidRequest,
    )
  }
  if (!exactKeys(callback, ['code', 'state', 'iss'])) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  const code = callback.searchParams.get('code')
  if (code === null || !/^[\x20-\x7e]+$/u.test(code)) {
    throw new AppAuthorizationError(AuthErrorCode.invalidCallback)
  }
  return code
}
