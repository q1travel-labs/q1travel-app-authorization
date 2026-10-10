import { AppAuthorizationError, AuthErrorCode } from '../core/types.js'

export interface AuthorizationContextPort {
  prepare(input: {
    readonly clientId: string
    readonly redirectUri: string
    readonly state: string
    readonly codeChallenge: string
    readonly sourceTabId?: number
  }): Promise<{ readonly token: string }>
  assertCurrent(input: {
    readonly token: string
    readonly phase: 'beforeExchange' | 'beforeSessionCommit'
  }): Promise<void>
}

export const isAuthorizationContextToken = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value)

export const prepareAuthorizationContext = async (
  port: AuthorizationContextPort,
  input: Parameters<AuthorizationContextPort['prepare']>[0],
): Promise<string> => {
  try {
    const result = await port.prepare(input)
    if (!result || typeof result !== 'object' || Array.isArray(result) ||
      Reflect.ownKeys(result).length !== 1 || !Object.hasOwn(result, 'token')) throw new Error('Invalid context.')
    const token = result.token
    if (!isAuthorizationContextToken(token)) throw new Error('Invalid context.')
    return token
  } catch {
    throw new AppAuthorizationError(AuthErrorCode.interactionFailed)
  }
}

export const assertAuthorizationContext = async (
  port: AuthorizationContextPort,
  token: unknown,
  phase: 'beforeExchange' | 'beforeSessionCommit',
): Promise<void> => {
  try {
    if (!isAuthorizationContextToken(token)) throw new Error('Invalid context.')
    await port.assertCurrent({ token, phase })
  } catch {
    throw new AppAuthorizationError(AuthErrorCode.interactionFailed)
  }
}
