import { describe, expect, it } from 'vitest'

import authorityFixture from './fixtures/chrome-app-authorization-client.v2.json'
import authorityFixtureText from './fixtures/chrome-app-authorization-client.v2.json?raw'
import { validateWebCallback } from '../../src/core/callback'
import type {
  AuthorizationPreparationProfile,
  AuthorizationSnapshotV2,
  CoreCryptoPort,
} from '../../src/core/contracts'
import { prepareAuthorization } from '../../src/core/pkce'
import { reconcileAuthorizationState } from '../../src/core/reconcile'

const coreSources = import.meta.glob<string>('../../src/core/**/*.ts', {
  query: '?raw',
  import: 'default',
  eager: true,
})

const profile: AuthorizationPreparationProfile = {
  authorizeUrl: 'https://accounts.example.test/app-authorizations/v1/authorize',
  clientId: 'browser-client-v2',
  redirectUri: 'https://web.example.test/apps/extension-auth/callback/client-v2',
  scopes: ['catalog:read', 'orders:manage'],
}

const state = 's'.repeat(43)
const authorizationCode = 'c'.repeat(43)

const cryptoForCallback: CoreCryptoPort = {
  randomBytes() {
    throw new Error('callback validation must not request randomness')
  },
  async sha256() {
    throw new Error('callback validation must not hash')
  },
  timingSafeEqual(left, right) {
    return left.length === right.length && left === right
  },
}

const readySignedOutSnapshot: AuthorizationSnapshotV2 = {
  profile: { profileId: 'client-v2-development', environment: 'development' },
  runtime: 'ready',
  authorization: { kind: 'signed-out', reason: 'never-authorized' },
  interaction: { phase: 'authorizing' },
}

describe('V2 authority fixture', () => {
  it('matches the independently recorded API artifact SHA-256', async () => {
    const digest = await globalThis.crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(authorityFixtureText),
    )
    const actual = [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('')

    expect(actual).toBe(
      '53aa8afc262a9d96c7b6eed2414f99d40124b67069ae00cb8793f9eb2ec09d1e',
    )
    expect(authorityFixture.contractVersion).toBe(
      'chrome-app-authorization-client.v2',
    )
    expect(authorityFixture.packageName).toBe(
      '@q1travel/app-authorization-chrome-extension',
    )
  })
})

describe('PKCE preparation', () => {
  it('prepares fresh state, verifier and the hand-checked S256 challenge', async () => {
    const generated = [
      Uint8Array.from({ length: 32 }, (_, index) => index),
      Uint8Array.from({ length: 32 }, (_, index) => index + 32),
    ]
    const crypto: CoreCryptoPort = {
      randomBytes(length) {
        expect(length).toBe(32)
        const value = generated.shift()
        if (!value) throw new Error('unexpected random request')
        return value
      },
      async sha256(value) {
        return new Uint8Array(
          await globalThis.crypto.subtle.digest(
            'SHA-256',
            Uint8Array.from(value),
          ),
        )
      },
      timingSafeEqual() {
        throw new Error('preparation must not compare callback state')
      },
    }

    const result = await prepareAuthorization(profile, crypto)
    const authorizeUrl = new URL(result.authorizeUrl)

    expect(result.state).toBe(
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    )
    expect(result.codeVerifier).toBe(
      'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
    )
    expect([...authorizeUrl.searchParams.entries()]).toEqual([
      ['client_id', 'browser-client-v2'],
      [
        'redirect_uri',
        'https://web.example.test/apps/extension-auth/callback/client-v2',
      ],
      ['state', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'],
      ['scope', 'catalog:read orders:manage'],
      ['code_challenge', 'zwkx4Wi0nph1A8rxivb-JTtrPYKoEAjD6OHuZ8fI3FU'],
      ['code_challenge_method', 'S256'],
    ])
  })

  it('keeps core source free of platform and consumer dependencies', () => {
    expect(Object.keys(coreSources).sort()).toEqual([
      '../../src/core/callback.ts',
      '../../src/core/contracts.ts',
      '../../src/core/pkce.ts',
      '../../src/core/reconcile.ts',
    ])

    for (const [sourcePath, sourceText] of Object.entries(coreSources)) {
      for (const forbidden of authorityFixture.mustExtractCore
        .forbiddenCorePatterns) {
        expect(sourceText, `${sourcePath}: ${forbidden.id}`).not.toMatch(
          new RegExp(forbidden.pattern, forbidden.flags),
        )
      }
    }
  })

  it.each([
    [
      'an unknown preset query',
      'https://accounts.example.test/app-authorizations/v1/authorize?audience=unexpected',
    ],
    [
      'repeated preset standard fields',
      'https://accounts.example.test/app-authorizations/v1/authorize?client_id=first&client_id=second',
    ],
    [
      'a fragment',
      'https://accounts.example.test/app-authorizations/v1/authorize#unexpected',
    ],
    [
      'an empty query delimiter',
      'https://accounts.example.test/app-authorizations/v1/authorize?',
    ],
    [
      'an empty fragment delimiter',
      'https://accounts.example.test/app-authorizations/v1/authorize#',
    ],
    [
      'credentials',
      'https://username:password@accounts.example.test/app-authorizations/v1/authorize',
    ],
  ])('rejects %s before requesting authorization secrets', async (_name, authorizeUrl) => {
    let randomnessRequested = false
    const crypto: CoreCryptoPort = {
      randomBytes() {
        randomnessRequested = true
        return new Uint8Array(32)
      },
      async sha256() {
        throw new Error('invalid endpoint must not hash')
      },
      timingSafeEqual() {
        throw new Error('preparation must not compare callback state')
      },
    }

    await expect(
      prepareAuthorization({ ...profile, authorizeUrl }, crypto),
    ).rejects.toThrow()
    expect(randomnessRequested).toBe(false)
  })
})

describe('strict callback validation', () => {
  const validate = (
    callbackUrl: string,
    overrides: Partial<{
      expectedState: string
      redirectUri: string
      consumedAuthorizationCodes: readonly string[]
    }> = {},
  ) =>
    validateWebCallback(
      {
        callbackUrl,
        expectedState: overrides.expectedState ?? state,
        redirectUri: overrides.redirectUri ?? profile.redirectUri,
        consumedAuthorizationCodes:
          overrides.consumedAuthorizationCodes ?? [],
      },
      cryptoForCallback,
    )

  it('accepts only the exact successful callback shape', () => {
    expect(
      validate(`${profile.redirectUri}?code=${authorizationCode}&state=${state}`),
    ).toEqual({ ok: true, value: { kind: 'approved', code: authorizationCode } })
  })

  it('accepts a non-empty opaque authorization code without freezing its encoding', () => {
    const opaqueCode = 'opaque-code.2026/alpha+beta='

    expect(
      validate(
        `${profile.redirectUri}?code=${encodeURIComponent(opaqueCode)}&state=${state}`,
      ),
    ).toEqual({ ok: true, value: { kind: 'approved', code: opaqueCode } })
  })

  it.each([
    ['a control character', 'opaque%0Acode'],
    ['an overlarge value', encodeURIComponent('x'.repeat(4097))],
  ])('rejects an opaque authorization code containing %s', (_name, encodedCode) => {
    expect(
      validate(`${profile.redirectUri}?code=${encodedCode}&state=${state}`),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })

  it('accepts only the exact denied callback shape', () => {
    expect(
      validate(`${profile.redirectUri}?error=access_denied&state=${state}`),
    ).toEqual({ ok: true, value: { kind: 'denied' } })
  })

  it.each([
    ['missing code', `?state=${state}`],
    ['missing state', `?code=${authorizationCode}`],
    ['duplicate field', `?code=${authorizationCode}&code=${authorizationCode}&state=${state}`],
    ['extra field', `?code=${authorizationCode}&state=${state}&source=unexpected`],
    ['unknown denial', `?error=temporarily_unavailable&state=${state}`],
  ])('rejects a %s', (_name, query) => {
    expect(validate(`${profile.redirectUri}${query}`)).toEqual({
      ok: false,
      error: 'callback_invalid',
    })
  })

  it('rejects the wrong state through the timing-safe port', () => {
    expect(
      validate(`${profile.redirectUri}?code=${authorizationCode}&state=${'x'.repeat(43)}`),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })

  it('rejects a callback from the wrong redirect', () => {
    expect(
      validate(
        `https://other.example.test/apps/extension-auth/callback/client-v2?code=${authorizationCode}&state=${state}`,
      ),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })

  it('rejects an already consumed authorization code', () => {
    expect(
      validate(`${profile.redirectUri}?code=${authorizationCode}&state=${state}`, {
        consumedAuthorizationCodes: [authorizationCode],
      }),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })

  it('keeps opaque code replay membership out of the state comparison port', () => {
    const newCode = 'é'
    const comparisons: Array<readonly [string, string]> = []
    const stateOnlyCrypto: CoreCryptoPort = {
      ...cryptoForCallback,
      timingSafeEqual(left, right) {
        comparisons.push([left, right])
        if (left !== state || right !== state) {
          throw new Error('code replay must not use state comparison')
        }
        return true
      },
    }
    const callbackUrl =
      `${profile.redirectUri}?code=${encodeURIComponent(newCode)}&state=${state}`

    expect(
      validateWebCallback(
        {
          callbackUrl,
          expectedState: state,
          redirectUri: profile.redirectUri,
          consumedAuthorizationCodes: ['a'],
        },
        stateOnlyCrypto,
      ),
    ).toEqual({ ok: true, value: { kind: 'approved', code: newCode } })
    expect(
      validateWebCallback(
        {
          callbackUrl,
          expectedState: state,
          redirectUri: profile.redirectUri,
          consumedAuthorizationCodes: [newCode],
        },
        stateOnlyCrypto,
      ),
    ).toEqual({ ok: false, error: 'callback_invalid' })
    expect(comparisons).toEqual([
      [state, state],
      [state, state],
    ])
  })

  it('fails closed when the timing-safe adapter throws', () => {
    const throwingCrypto: CoreCryptoPort = {
      ...cryptoForCallback,
      timingSafeEqual() {
        throw new Error('controlled adapter failure')
      },
    }

    expect(() =>
      validateWebCallback(
        {
          callbackUrl: `${profile.redirectUri}?code=${authorizationCode}&state=${state}`,
          expectedState: state,
          redirectUri: profile.redirectUri,
          consumedAuthorizationCodes: [],
        },
        throwingCrypto,
      ),
    ).not.toThrow()
    expect(
      validateWebCallback(
        {
          callbackUrl: `${profile.redirectUri}?code=${authorizationCode}&state=${state}`,
          expectedState: state,
          redirectUri: profile.redirectUri,
          consumedAuthorizationCodes: [],
        },
        throwingCrypto,
      ),
    ).toEqual({ ok: false, error: 'callback_invalid' })
  })
})

describe('state reconciliation precedence', () => {
  it('lets a valid grant dominate a stale transaction', () => {
    expect(
      reconcileAuthorizationState({
        snapshot: readySignedOutSnapshot,
        grant: {
          expiresAt: '2026-08-26T12:30:00.000Z',
          sessionRevision: 'revision-7',
        },
        transaction: {
          phase: 'authorizing',
          createdAt: '2026-08-26T12:00:00.000Z',
        },
        now: '2026-08-26T12:10:00.000Z',
      }),
    ).toEqual({
      snapshot: {
        ...readySignedOutSnapshot,
        authorization: {
          kind: 'authorized',
          expiresAt: '2026-08-26T12:30:00.000Z',
          sessionRevision: 'revision-7',
        },
        interaction: { phase: 'idle' },
      },
      transaction: null,
    })
  })

  it('lets a newer terminal snapshot dominate a stale transaction', () => {
    const terminalSnapshot: AuthorizationSnapshotV2 = {
      ...readySignedOutSnapshot,
      interaction: {
        phase: 'cancelled',
        occurredAt: '2026-08-26T12:05:00.000Z',
      },
    }

    expect(
      reconcileAuthorizationState({
        snapshot: terminalSnapshot,
        grant: null,
        transaction: {
          phase: 'authorizing',
          createdAt: '2026-08-26T12:00:00.000Z',
        },
        now: '2026-08-26T12:10:00.000Z',
      }),
    ).toEqual({ snapshot: terminalSnapshot, transaction: null })
  })

  it('lets a terminal snapshot at the transaction time dominate it', () => {
    const terminalSnapshot: AuthorizationSnapshotV2 = {
      ...readySignedOutSnapshot,
      interaction: {
        phase: 'failed',
        occurredAt: '2026-08-26T12:00:00.000Z',
      },
    }

    expect(
      reconcileAuthorizationState({
        snapshot: terminalSnapshot,
        grant: null,
        transaction: {
          phase: 'authorizing',
          createdAt: '2026-08-26T12:00:00.000Z',
        },
        now: '2026-08-26T12:10:00.000Z',
      }),
    ).toEqual({ snapshot: terminalSnapshot, transaction: null })
  })

  it('preserves the snapshot when both grant and transaction are absent', () => {
    expect(
      reconcileAuthorizationState({
        snapshot: readySignedOutSnapshot,
        grant: null,
        transaction: null,
        now: '2026-08-26T12:10:00.000Z',
      }),
    ).toEqual({ snapshot: readySignedOutSnapshot, transaction: null })
  })

  it.each([
    {
      name: 'invalid current time',
      now: 'not-a-timestamp',
      grantExpiresAt: '2026-08-26T12:30:00.000Z',
      occurredAt: '2026-08-26T12:05:00.000Z',
      createdAt: '2026-08-26T12:00:00.000Z',
      terminal: false,
    },
    {
      name: 'invalid grant expiry',
      now: '2026-08-26T12:10:00.000Z',
      grantExpiresAt: 'not-a-timestamp',
      occurredAt: 'invalid-terminal-time',
      createdAt: '2026-08-26T12:00:00.000Z',
      terminal: true,
    },
    {
      name: 'invalid transaction creation time',
      now: '2026-08-26T12:10:00.000Z',
      grantExpiresAt: 'not-a-timestamp',
      occurredAt: '2026-08-26T12:05:00.000Z',
      createdAt: 'invalid-transaction-time',
      terminal: true,
    },
  ])('does not derive authority from $name', ({ now, grantExpiresAt, occurredAt, createdAt, terminal }) => {
    const snapshot: AuthorizationSnapshotV2 = {
      ...readySignedOutSnapshot,
      interaction: terminal
        ? { phase: 'expired', occurredAt }
        : { phase: 'authorizing' },
    }
    const transaction = { phase: 'authorizing' as const, createdAt }

    expect(
      reconcileAuthorizationState({
        snapshot,
        grant: {
          expiresAt: grantExpiresAt,
          sessionRevision: 'untrusted-revision',
        },
        transaction,
        now,
      }),
    ).toEqual({ snapshot, transaction })
  })
})
