import type {
  AuthorizationGrantMetadata,
  AuthorizationSnapshotV2,
  AuthorizationTransactionState,
} from './contracts.js'

export interface ReconcileAuthorizationStateInput {
  snapshot: AuthorizationSnapshotV2
  grant: AuthorizationGrantMetadata | null
  transaction: AuthorizationTransactionState | null
  now: string
}

export interface ReconciledAuthorizationState {
  snapshot: AuthorizationSnapshotV2
  transaction: AuthorizationTransactionState | null
}

const isTerminalInteraction = (
  interaction: AuthorizationSnapshotV2['interaction'],
): interaction is Extract<
  AuthorizationSnapshotV2['interaction'],
  { occurredAt: string }
> =>
  interaction.phase === 'cancelled' ||
  interaction.phase === 'expired' ||
  interaction.phase === 'failed'

export const reconcileAuthorizationState = (
  input: ReconcileAuthorizationStateInput,
): ReconciledAuthorizationState => {
  const now = Date.parse(input.now)
  if (
    input.grant !== null &&
    Number.isFinite(now) &&
    Date.parse(input.grant.expiresAt) > now
  ) {
    return {
      snapshot: {
        ...input.snapshot,
        authorization: {
          kind: 'authorized',
          expiresAt: input.grant.expiresAt,
          sessionRevision: input.grant.sessionRevision,
        },
        interaction: { phase: 'idle' },
      },
      transaction: null,
    }
  }

  if (
    input.transaction !== null &&
    isTerminalInteraction(input.snapshot.interaction) &&
    Date.parse(input.snapshot.interaction.occurredAt) >=
      Date.parse(input.transaction.createdAt)
  ) {
    return { snapshot: input.snapshot, transaction: null }
  }

  return { snapshot: input.snapshot, transaction: input.transaction }
}
