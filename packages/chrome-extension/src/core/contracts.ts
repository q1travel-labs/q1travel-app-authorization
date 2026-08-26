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

export type AuthorizationState =
  | { kind: 'signed-out'; reason: SignedOutReason }
  | { kind: 'authorizing' }
  | { kind: 'authorized'; expiresAt: string; sessionRevision: string }
  | { kind: 'revocation-pending'; sessionRevision: string }

export type AuthorizationInteractionV2 =
  | { phase: 'idle' }
  | { phase: 'opening' | 'authorizing' | 'exchanging' }
  | { phase: 'cancelled' | 'expired' | 'failed'; occurredAt: string }

export interface AuthorizationSnapshotV2 {
  profile: null | {
    profileId: string
    environment: 'development' | 'production'
  }
  runtime: RuntimePhase
  authorization: AuthorizationState
  interaction: AuthorizationInteractionV2
}

export interface CoreCryptoPort {
  randomBytes(length: 32): Uint8Array
  sha256(value: Uint8Array): Promise<Uint8Array>
  timingSafeEqual(left: string, right: string): boolean
}

export interface AuthorizationPreparationProfile {
  authorizeUrl: string
  clientId: string
  redirectUri: string
  scopes: readonly string[]
}

export interface PreparedAuthorization {
  state: string
  codeVerifier: string
  authorizeUrl: string
}

export interface AuthorizationTransactionState {
  phase: 'opening' | 'authorizing' | 'exchanging'
  createdAt: string
}

export interface AuthorizationGrantMetadata {
  expiresAt: string
  sessionRevision: string
}

