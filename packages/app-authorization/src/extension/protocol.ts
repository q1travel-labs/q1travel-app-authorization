import {
  AppAuthorizationError,
  AuthErrorCode,
  type AuthSession,
} from '../core/types.js'

export const AUTH_PROTOCOL = 'q1travel.app-authorization.v1'
export const SESSION_CHANGED = 'q1travel.app-authorization.session-changed.v1'

export type AuthAction = 'login' | 'logout' | 'getSession' | 'verifySession'

export interface AuthRequest {
  readonly protocol: typeof AUTH_PROTOCOL
  readonly requestId: string
  readonly action: AuthAction
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
const exactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const keys = Object.keys(value)
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

export const parseRequest = (value: unknown): AuthRequest | null => {
  if (!isRecord(value) || !exactKeys(value, ['protocol', 'requestId', 'action'])) return null
  if (
    value.protocol !== AUTH_PROTOCOL ||
    typeof value.requestId !== 'string' ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(value.requestId) ||
    !['login', 'logout', 'getSession', 'verifySession'].includes(String(value.action))
  ) return null
  return value as unknown as AuthRequest
}

export const parseSession = (value: unknown): AuthSession | null => {
  if (!isRecord(value) || typeof value.status !== 'string') return null
  if (value.status === 'signed-out' && exactKeys(value, ['status'])) return { status: 'signed-out' }
  if (
    value.status === 'authenticated' &&
    exactKeys(value, ['status', 'expiresAt', 'scopes']) &&
    typeof value.expiresAt === 'string' &&
    Number.isFinite(Date.parse(value.expiresAt)) &&
    Array.isArray(value.scopes) &&
    value.scopes.every((scope) => typeof scope === 'string')
  ) {
    return {
      status: 'authenticated',
      expiresAt: value.expiresAt,
      scopes: [...value.scopes],
    }
  }
  return null
}

export const serializeError = (error: unknown) => {
  const safe = error instanceof AppAuthorizationError
    ? error
    : new AppAuthorizationError(AuthErrorCode.runtimeUnavailable)
  return { code: safe.code, message: safe.message, retryable: safe.retryable }
}
