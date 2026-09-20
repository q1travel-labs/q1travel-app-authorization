import {
  AppAuthorizationError,
  AuthErrorCode,
  type AuthSession,
} from '../core/types.js'
import type { ChromePort, RuntimeMessageListener } from './ports.js'
import {
  AUTH_PROTOCOL,
  SESSION_CHANGED,
  parseSession,
  type AuthAction,
} from './protocol.js'
import { isTrustedExtensionSender } from './sender.js'

export interface AuthFacade {
  login(): Promise<AuthSession>
  logout(): Promise<AuthSession>
  getSession(): Promise<AuthSession>
  verifySession(): Promise<AuthSession>
  onSessionChange(callback: (session: AuthSession) => void): () => void
}

interface AuthFacadeDependencies {
  readonly chrome: ChromePort
  readonly createRequestId?: () => string
}

const getChrome = (): ChromePort => {
  const value = (globalThis as typeof globalThis & { chrome?: ChromePort }).chrome
  if (!value) throw new AppAuthorizationError(AuthErrorCode.runtimeUnavailable)
  return value
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
const exactKeys = (value: Record<string, unknown>, expected: readonly string[]) => {
  const keys = Object.keys(value)
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

export const createAuthFacade = (): AuthFacade =>
  createAuthFacadeWithDependencies({ chrome: getChrome() })

export const createAuthFacadeWithDependencies = (
  options: AuthFacadeDependencies,
): AuthFacade => {
  const chrome = options.chrome
  const createRequestId = options.createRequestId ?? (() => globalThis.crypto.randomUUID())
  const request = async (action: AuthAction): Promise<AuthSession> => {
    const requestId = createRequestId()
    let response: unknown
    try {
      response = await chrome.runtime.sendMessage({ protocol: AUTH_PROTOCOL, requestId, action })
    } catch {
      throw new AppAuthorizationError(AuthErrorCode.runtimeUnavailable)
    }
    if (!isRecord(response) || response.protocol !== AUTH_PROTOCOL || response.requestId !== requestId) {
      throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
    }
    if (response.ok === true && exactKeys(response, ['protocol', 'requestId', 'ok', 'session'])) {
      const session = parseSession(response.session)
      if (session) return session
    }
    if (
      response.ok === false &&
      exactKeys(response, ['protocol', 'requestId', 'ok', 'error']) &&
      isRecord(response.error) &&
      exactKeys(response.error, ['code', 'message', 'retryable']) &&
      typeof response.error.code === 'string'
    ) {
      const codes = new Set(Object.values(AuthErrorCode))
      if (codes.has(response.error.code as never)) {
        throw new AppAuthorizationError(response.error.code as never)
      }
    }
    throw new AppAuthorizationError(AuthErrorCode.responseInvalid)
  }
  const onSessionChange = (callback: (session: AuthSession) => void) => {
    const listener: RuntimeMessageListener = (message, sender) => {
      if (!isTrustedExtensionSender(sender, chrome.runtime.id)) return
      if (!isRecord(message) || !exactKeys(message, ['type', 'session'])) return
      if (message.type !== SESSION_CHANGED) return
      const session = parseSession(message.session)
      if (session) callback(session)
    }
    chrome.runtime.onMessage.addListener(listener)
    return () => chrome.runtime.onMessage.removeListener(listener)
  }
  return Object.freeze({
    login: () => request('login'),
    logout: () => request('logout'),
    getSession: () => request('getSession'),
    verifySession: () => request('verifySession'),
    onSessionChange,
  })
}
