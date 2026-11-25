import { protocolEndpoints } from './protocolEndpoints.js'
import { AppAuthorizationError, AuthErrorCode } from './types.js'

export interface AuthConfig {
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
  /** Origin serving the five public authorization endpoints. */
  readonly authOrigin: string
  /** Only this origin can receive authorizedFetch requests. */
  readonly apiOrigin: string
  readonly pathPrefix?: string
  readonly allowInsecureLoopback?: boolean
}

export interface ResolvedAuthConfig extends Readonly<ReturnType<typeof protocolEndpoints>> {
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly apiOrigin: string
  readonly pathPrefix: string
}

const CLIENT_ID_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/u
const SCOPE_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/u
const PATH_PREFIX_PATTERN = /^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?$/u

const invalidConfiguration = (): never => {
  throw new AppAuthorizationError(AuthErrorCode.configurationInvalid)
}

const parseUrl = (value: string): URL => {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return invalidConfiguration()
  }
  if (url.hostname.endsWith('.')) return invalidConfiguration()
  return url
}

const requireOrigin = (value: string, allowInsecureLoopback: boolean): string => {
  const url = parseUrl(value)
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
  if (url.origin !== value || (url.protocol !== 'https:' &&
    !(allowInsecureLoopback && loopback && url.protocol === 'http:'))) {
    return invalidConfiguration()
  }
  return url.origin
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
  const allowLoopback = config.allowInsecureLoopback === true
  const authOrigin = requireOrigin(config.authOrigin, allowLoopback)
  const apiOrigin = requireOrigin(config.apiOrigin, allowLoopback)
  if (authOrigin === apiOrigin) invalidConfiguration()

  const pathPrefix = config.pathPrefix ?? '/api'
  if (
    (pathPrefix !== '' && !PATH_PREFIX_PATTERN.test(pathPrefix)) ||
    pathPrefix.includes('..') ||
    pathPrefix.split('/').includes('.') ||
    (pathPrefix.length > 1 && pathPrefix.endsWith('/'))
  ) {
    invalidConfiguration()
  }
  const normalizedPathPrefix = pathPrefix === '/' ? '' : pathPrefix
  return Object.freeze({
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scopes: Object.freeze([...config.scopes]),
    apiOrigin,
    pathPrefix: normalizedPathPrefix,
    ...protocolEndpoints(authOrigin + normalizedPathPrefix),
  })
}
