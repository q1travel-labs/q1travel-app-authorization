export type RuntimePhase =
  | 'unconfigured'
  | 'configured'
  | 'starting'
  | 'ready'
  | 'degraded'
  | 'failed'

export type SignedOutReason =
  | 'never-authorized'
  | 'logged-out'
  | 'expired'
  | 'revoked'
  | 'invalidated'

export interface AuthorizationSnapshotV2 {
  profile: null | {
    profileId: string
    environment: 'development' | 'production'
  }
  runtime: RuntimePhase
  authorization:
    | { kind: 'signed-out'; reason: SignedOutReason }
    | { kind: 'authorizing' }
    | { kind: 'authorized'; expiresAt: string; sessionRevision: string }
    | { kind: 'revocation-pending'; sessionRevision: string }
  interaction:
    | { phase: 'idle' }
    | { phase: 'opening' | 'authorizing' | 'exchanging' }
    | { phase: 'cancelled' | 'expired' | 'failed'; occurredAt: string }
}

export type AppAuthorizationFailureCode =
  | 'configuration_invalid'
  | 'runtime_not_ready'
  | 'runtime_unavailable'
  | 'interaction_in_progress'
  | 'interaction_denied'
  | 'callback_invalid'
  | 'protocol_invalid'
  | 'network_unavailable'
  | 'grant_expired'
  | 'grant_invalidated'
  | 'grant_forbidden'
  | 'revocation_pending'
  | 'operation_not_allowed'
  | 'response_invalid'

export interface AppAuthorizationFailure {
  code: AppAuthorizationFailureCode
  retry: 'never' | 'safe' | 'explicit-user-action'
  message: string
}

export type AppAuthorizationResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: AppAuthorizationFailure }

export interface LocalTerminationOutcome {
  snapshot: AuthorizationSnapshotV2
  cleanup: 'complete' | 'incomplete'
}

export type UiContext = 'popup' | 'options' | 'side-panel'
