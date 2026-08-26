const runtimeMethods = [
  'configure',
  'start',
  'status',
  'login',
  'focusAuthorization',
  'logout',
  'revoke',
  'authorizedFetch',
] as const

const uiFacadeMethods = [
  'status',
  'login',
  'focusAuthorization',
  'logout',
  'revoke',
  'authorizedFetch',
] as const

const assertExactMethods = (
  name: string,
  candidate: unknown,
  expected: readonly string[],
): void => {
  if (typeof candidate !== 'object' || candidate === null) {
    throw new TypeError(`${name} must be an object.`)
  }
  const actual = Object.keys(candidate).sort()
  const wanted = [...expected].sort()
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index]) ||
    wanted.some((key) =>
      typeof (candidate as Record<string, unknown>)[key] !== 'function')
  ) {
    throw new TypeError(`${name} does not match the V2 public surface.`)
  }
}

export const assertChromeAppAuthorizationConsumerConformance = (
  candidate: { runtime: unknown; uiFacade: unknown },
): void => {
  assertExactMethods('runtime', candidate.runtime, runtimeMethods)
  assertExactMethods('UI facade', candidate.uiFacade, uiFacadeMethods)
}
