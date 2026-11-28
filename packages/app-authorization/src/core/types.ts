export const AuthErrorCode = Object.freeze({
  nonceChallenge: 'use_dpop_nonce',
  reauthorizationRequired: 'reauthorization_required',
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
  use_dpop_nonce: { message: 'The server requires a fresh DPoP nonce.', retryable: false },
  reauthorization_required: { message: 'Sign in again to authorize this installation.', retryable: false },
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

export interface AuthIdentity {
  readonly object: 'identity'
  readonly principal_type: 'user'
  readonly user: string
  readonly organization: string
  readonly scopes: readonly string[]
  readonly store_ids: readonly string[] | null
}

export interface AuthenticatedSession {
  readonly status: 'authenticated'
  readonly expiresAt: string
  readonly identity: AuthIdentity
}

export type AuthSession =
  | { readonly status: 'signed-out' }
  | AuthenticatedSession
