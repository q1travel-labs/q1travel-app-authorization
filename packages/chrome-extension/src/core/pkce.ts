import type {
  AuthorizationPreparationProfile,
  CoreCryptoPort,
  PreparedAuthorization,
} from './contracts.js'

const BASE64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

const base64url = (value: Uint8Array): string => {
  let encoded = ''
  for (let index = 0; index < value.length; index += 3) {
    const first = value[index] ?? 0
    const second = value[index + 1] ?? 0
    const third = value[index + 2] ?? 0
    const combined = (first << 16) | (second << 8) | third
    const remaining = value.length - index

    encoded += BASE64_ALPHABET[(combined >>> 18) & 63]
    encoded += BASE64_ALPHABET[(combined >>> 12) & 63]
    if (remaining > 1) encoded += BASE64_ALPHABET[(combined >>> 6) & 63]
    if (remaining > 2) encoded += BASE64_ALPHABET[combined & 63]
  }

  return encoded.replaceAll('+', '-').replaceAll('/', '_')
}

const ascii = (value: string): Uint8Array =>
  Uint8Array.from(value, (character) => character.charCodeAt(0))

const requireBytes = (value: Uint8Array): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error('Invalid core crypto output')
  }
  return value
}

export const prepareAuthorization = async (
  profile: AuthorizationPreparationProfile,
  crypto: CoreCryptoPort,
): Promise<PreparedAuthorization> => {
  if (
    profile.authorizeUrl.includes('?') ||
    profile.authorizeUrl.includes('#')
  ) {
    throw new Error('Invalid authorization endpoint')
  }
  const authorizeUrl = new URL(profile.authorizeUrl)
  if (
    authorizeUrl.username !== '' ||
    authorizeUrl.password !== '' ||
    authorizeUrl.search !== '' ||
    authorizeUrl.hash !== ''
  ) {
    throw new Error('Invalid authorization endpoint')
  }

  const state = base64url(requireBytes(crypto.randomBytes(32)))
  const codeVerifier = base64url(requireBytes(crypto.randomBytes(32)))
  const challenge = base64url(
    requireBytes(await crypto.sha256(ascii(codeVerifier))),
  )
  const query = new URLSearchParams()
  query.set('client_id', profile.clientId)
  query.set('redirect_uri', profile.redirectUri)
  query.set('state', state)
  query.set('scope', profile.scopes.join(' '))
  query.set('code_challenge', challenge)
  query.set('code_challenge_method', 'S256')
  authorizeUrl.search = query.toString()

  return {
    state,
    codeVerifier,
    authorizeUrl: authorizeUrl.toString(),
  }
}
