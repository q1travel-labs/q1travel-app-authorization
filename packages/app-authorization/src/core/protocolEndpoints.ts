export const protocolEndpoints = (authOrigin: string, apiOrigin: string) => ({
  issuer: 'https://connect.q1lx.com',
  resource: 'https://api.q1lx.com/v1',
  identityUrl: apiOrigin + '/v1/identity',
  authorizeUrl: authOrigin + '/oauth/authorize',
  tokenUrl: authOrigin + '/oauth/token',
  revokeUrl: authOrigin + '/oauth/revoke',
  contextsUrl: authOrigin + '/oauth/contexts',
})
