export const AuthErrorCode = Object.freeze({
  configurationInvalid: 'configuration_invalid',
  interactionCancelled: 'interaction_cancelled',
  interactionFailed: 'interaction_failed',
  authorizationDenied: 'authorization_denied',
  invalidCallback: 'invalid_callback',
  stateMismatch: 'state_mismatch',
  networkUnavailable: 'network_unavailable',
  oauthInvalidRequest: 'oauth_invalid_request',
  oauthInvalidGrant: 'oauth_invalid_grant',
  invalidToken: 'invalid_token',
  serverUnavailable: 'server_unavailable',
  responseInvalid: 'response_invalid',
  storageUnavailable: 'storage_unavailable',
  sessionExpired: 'session_expired',
  sessionRevoked: 'session_revoked',
  forbidden: 'forbidden',
  revocationUnconfirmed: 'revocation_unconfirmed',
  requestNotAllowed: 'request_not_allowed',
  runtimeUnavailable: 'runtime_unavailable',
} as const)

export type AuthErrorCode =
  (typeof AuthErrorCode)[keyof typeof AuthErrorCode]

const ERROR_DETAILS: Readonly<
  Record<AuthErrorCode, { message: string; retryable: boolean }>
> = Object.freeze({
  configuration_invalid: { message: 'Authorization configuration is invalid.', retryable: false },
  interaction_cancelled: { message: 'Authorization was cancelled.', retryable: true },
  interaction_failed: { message: 'Authorization interaction failed.', retryable: true },
  authorization_denied: { message: 'Authorization was denied.', retryable: true },
  invalid_callback: { message: 'Authorization callback is invalid.', retryable: false },
  state_mismatch: { message: 'Authorization state did not match.', retryable: false },
  network_unavailable: { message: 'The network is unavailable.', retryable: true },
  oauth_invalid_request: { message: 'The authorization request was rejected.', retryable: false },
  oauth_invalid_grant: { message: 'The authorization grant is invalid or expired.', retryable: true },
  invalid_token: { message: 'The access token is invalid or expired.', retryable: true },
  server_unavailable: { message: 'The authorization service is unavailable.', retryable: true },
  response_invalid: { message: 'The authorization response is invalid.', retryable: true },
  storage_unavailable: { message: 'Secure session storage is unavailable.', retryable: true },
  session_expired: { message: 'The authorization session expired.', retryable: true },
  session_revoked: { message: 'The authorization session was revoked.', retryable: true },
  forbidden: { message: 'The requested operation is not permitted.', retryable: false },
  revocation_unconfirmed: { message: 'Remote revocation could not be confirmed.', retryable: true },
  request_not_allowed: { message: 'The request target is not allowed.', retryable: false },
  runtime_unavailable: { message: 'The authorization runtime is unavailable.', retryable: true },
})

export class AppAuthorizationError extends Error {
  readonly code: AuthErrorCode
  readonly retryable: boolean

  constructor(code: AuthErrorCode) {
    const detail = ERROR_DETAILS[code]
    super(detail.message)
    this.name = 'AppAuthorizationError'
    this.code = code
    this.retryable = detail.retryable
  }
}

export interface AuthenticatedSession {
  readonly status: 'authenticated'
  readonly expiresAt: string
  readonly scopes: readonly string[]
}

export type AuthSession =
  | { readonly status: 'signed-out' }
  | AuthenticatedSession

export interface AuthConfig {
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly apiOrigin: string
  readonly pathPrefix?: string
  readonly allowInsecureLoopback?: boolean
}

export interface ResolvedAuthConfig {
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly apiOrigin: string
  readonly authorizeUrl: string
  readonly tokenUrl: string
  readonly revokeUrl: string
  readonly sessionUrl: string
}

const CLIENT_ID_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/u
const SCOPE_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/u
const PATH_PREFIX_PATTERN = /^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?$/u

const invalidConfiguration = (): never => {
  throw new AppAuthorizationError(AuthErrorCode.configurationInvalid)
}

const parseUrl = (value: string): URL => {
  try {
    return new URL(value)
  } catch {
    return invalidConfiguration()
  }
}

export const resolveAuthConfig = (config: AuthConfig): ResolvedAuthConfig => {
  if (!config || typeof config !== 'object') invalidConfiguration()
  if (!CLIENT_ID_PATTERN.test(config.clientId)) invalidConfiguration()
  if (
    !Array.isArray(config.scopes) ||
    config.scopes.length === 0 ||
    config.scopes.some((scope) => !SCOPE_PATTERN.test(scope)) ||
    new Set(config.scopes).size !== config.scopes.length
  ) {
    invalidConfiguration()
  }

  const redirect = parseUrl(config.redirectUri)
  const api = parseUrl(config.apiOrigin)
  if (
    redirect.protocol !== 'https:' ||
    !/^[a-p]{32}\.chromiumapp\.org$/u.test(redirect.hostname) ||
    redirect.port !== '' ||
    redirect.username !== '' ||
    redirect.password !== '' ||
    redirect.search !== '' ||
    redirect.hash !== '' ||
    redirect.pathname === '/' ||
    redirect.toString() !== config.redirectUri
  ) {
    invalidConfiguration()
  }
  const loopback = api.hostname === '127.0.0.1' || api.hostname === 'localhost'
  if (
    (api.protocol !== 'https:' && !(config.allowInsecureLoopback === true && loopback && api.protocol === 'http:')) ||
    api.username !== '' ||
    api.password !== '' ||
    api.pathname !== '/' ||
    api.search !== '' ||
    api.hash !== '' ||
    api.origin !== config.apiOrigin
  ) {
    invalidConfiguration()
  }
  const pathPrefix = config.pathPrefix ?? '/api'
  if (!PATH_PREFIX_PATTERN.test(pathPrefix) || pathPrefix.endsWith('/')) {
    invalidConfiguration()
  }
  const base = `${api.origin}${pathPrefix}/app-authorizations/v1`
  return Object.freeze({
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scopes: Object.freeze([...config.scopes]),
    apiOrigin: api.origin,
    authorizeUrl: `${base}/authorize`,
    tokenUrl: `${base}/token`,
    revokeUrl: `${base}/revoke`,
    sessionUrl: `${base}/session`,
  })
}
