const runtimeMethods = [
    'configure',
    'start',
    'status',
    'login',
    'focusAuthorization',
    'logout',
    'revoke',
    'authorizedFetch',
];
const uiFacadeMethods = [
    'status',
    'login',
    'focusAuthorization',
    'logout',
    'revoke',
    'authorizedFetch',
];
const assertExactMethods = (name, candidate, expected) => {
    if (typeof candidate !== 'object' || candidate === null) {
        throw new TypeError(`${name} must be an object.`);
    }
    const actual = Object.keys(candidate).sort();
    const wanted = [...expected].sort();
    if (actual.length !== wanted.length ||
        actual.some((key, index) => key !== wanted[index]) ||
        wanted.some((key) => typeof candidate[key] !== 'function')) {
        throw new TypeError(`${name} does not match the V2 public surface.`);
    }
};
export const assertChromeAppAuthorizationConsumerConformance = (candidate) => {
    assertExactMethods('runtime', candidate.runtime, runtimeMethods);
    assertExactMethods('UI facade', candidate.uiFacade, uiFacadeMethods);
};
