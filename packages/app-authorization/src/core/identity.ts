import type { AuthIdentity } from './types.js'

const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string')

export function parseIdentity(value: unknown): AuthIdentity | null {
  if (!value || typeof value !== 'object') return null
  const data = value as Record<string, unknown>
  if (Object.keys(data).length !== 6 || data.object !== 'identity' || data.principal_type !== 'user' ||
    typeof data.user !== 'string' || !/^usr_[0-9a-hjkmnp-tv-z]{26}$/u.test(data.user) ||
    typeof data.organization !== 'string' || !/^org_[0-9a-hjkmnp-tv-z]{26}$/u.test(data.organization) ||
    !strings(data.scopes) || !data.scopes.every((scope) => /^[a-z0-9_:.-]+$/u.test(scope)) ||
    !(data.store_ids === null || (strings(data.store_ids) &&
      data.store_ids.every((id) => /^str_[0-9a-hjkmnp-tv-z]{26}$/u.test(id))))) return null
  return {
    object: 'identity', principal_type: 'user', user: data.user, organization: data.organization,
    scopes: [...data.scopes], store_ids: data.store_ids && [...data.store_ids],
  }
}
