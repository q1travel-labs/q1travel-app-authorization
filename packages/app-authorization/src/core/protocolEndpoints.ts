export const protocolEndpoints = (base: string) => {
  const prefix = `${base}/app-authorizations/v1`
  return {
    authorizeUrl: `${prefix}/authorize`,
    tokenUrl: `${prefix}/token`,
    revokeUrl: `${prefix}/revoke`,
    sessionUrl: `${prefix}/session`,
    contextsUrl: `${prefix}/contexts`,
  } as const
}

// Mirror the API host's case-insensitive check, including optional proxy prefixes.
export const reservedProtocolPaths = (pathPrefix: string): ReadonlySet<string> => new Set([
  ...Object.values(protocolEndpoints('')),
  ...Object.values(protocolEndpoints(pathPrefix.toLowerCase())),
])
