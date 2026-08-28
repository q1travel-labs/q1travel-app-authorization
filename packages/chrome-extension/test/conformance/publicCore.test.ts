import { describe, expect, it } from 'vitest'
import { prepareAuthorization } from '../../src/index'
import type {
  AuthorizationPreparationProfile,
  CoreCryptoPort,
} from '../../src/core/contracts'

describe('public authorization core', () => {
  it('exports PKCE preparation without Chrome or DOM dependencies', async () => {
    const profile: AuthorizationPreparationProfile = {
      authorizeUrl: 'https://q1lx.com/api/app-authorizations/v1/authorize',
      clientId: 'client',
      redirectUri: 'https://q1lx.com/oauth/callback',
      scopes: ['scope:read'],
    }
    const crypto: CoreCryptoPort = {
      randomBytes: () => new Uint8Array(32).fill(7),
      sha256: async () => new Uint8Array(32).fill(9),
      timingSafeEqual: (left, right) => left === right,
    }

    const result = await prepareAuthorization(profile, crypto)
    expect(result.state).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(result.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    expect(new URL(result.authorizeUrl).searchParams.get('code_challenge_method')).toBe('S256')
  })
})
