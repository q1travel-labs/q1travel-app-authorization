export const protocolEndpoints = (issuer: string, apiOrigin: string) => ({
  issuer,
  resource: apiOrigin + '/v1',
  identityUrl: apiOrigin + '/v1/identity',
  authorizeUrl: issuer + '/oauth/authorize',
  tokenUrl: issuer + '/oauth/token',
  revokeUrl: issuer + '/oauth/revoke',
  contextsUrl: issuer + '/oauth/contexts',
})
