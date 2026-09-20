export interface CryptoPort {
  randomBytes(length: number): Uint8Array
  sha256(value: Uint8Array): Promise<Uint8Array>
}

export interface AuthorizationRequestConfig {
  readonly authorizeUrl: string
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
}

export interface PreparedAuthorizationRequest {
  readonly authorizationUrl: string
  readonly codeVerifier: string
  readonly state: string
}

const encodeBase64Url = (value: Uint8Array): string => {
  let binary = ''
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
}

const exactBytes = (value: Uint8Array): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new TypeError('Cryptographic operation failed.')
  }
  return value
}

export const createAuthorizationRequest = async (
  config: AuthorizationRequestConfig,
  crypto: CryptoPort,
): Promise<PreparedAuthorizationRequest> => {
  const state = encodeBase64Url(exactBytes(crypto.randomBytes(32)))
  const codeVerifier = encodeBase64Url(exactBytes(crypto.randomBytes(32)))
  const challenge = encodeBase64Url(
    exactBytes(await crypto.sha256(new TextEncoder().encode(codeVerifier))),
  )
  const url = new URL(config.authorizeUrl)
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('scope', config.scopes.join(' '))
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  return { authorizationUrl: url.toString(), codeVerifier, state }
}

export const browserCryptoPort = (): CryptoPort => ({
  randomBytes(length) {
    return globalThis.crypto.getRandomValues(new Uint8Array(length))
  },
  async sha256(value) {
    return new Uint8Array(
      await globalThis.crypto.subtle.digest('SHA-256', Uint8Array.from(value).buffer),
    )
  },
})
