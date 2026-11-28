import type { CryptoPort } from '../core/pkce.js'

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
