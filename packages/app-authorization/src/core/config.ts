import { AppAuthorizationError, AuthErrorCode } from './types.js'

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

export const resolveAuthConfig = (config: AuthConfig, allowWebRedirect = false): ResolvedAuthConfig => {
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
    (redirect.protocol !== 'https:' && !(allowWebRedirect && config.allowInsecureLoopback === true &&
      redirect.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(redirect.hostname))) ||
    (!allowWebRedirect && !/^[a-p]{32}\.chromiumapp\.org$/u.test(redirect.hostname)) ||
    (!allowWebRedirect && redirect.port !== '') ||
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
  if (
    (pathPrefix !== '' && !PATH_PREFIX_PATTERN.test(pathPrefix)) ||
    pathPrefix.includes('..') ||
    (pathPrefix.length > 1 && pathPrefix.endsWith('/'))
  ) {
    invalidConfiguration()
  }
  const normalizedPathPrefix = pathPrefix === '/' ? '' : pathPrefix
  const base = `${api.origin}${normalizedPathPrefix}/app-authorizations/v1`
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
