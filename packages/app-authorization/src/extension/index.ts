export { createAuthFacade } from './facade.js'
export type { AuthFacade } from './facade.js'
export type { AuthRuntime, AuthRuntimeOptions } from './runtime.js'
export type { AuthFlowLauncher } from './ports.js'

import type { AuthConfig } from '../core/types.js'
import {
  createAuthRuntime as createRuntime,
  type AuthRuntime,
  type AuthRuntimeDependencies,
  type AuthRuntimeOptions,
} from './runtime.js'
import { installRuntime } from './listener.js'

export const createAuthRuntime = (
  config: AuthConfig,
  options: AuthRuntimeOptions = {},
): AuthRuntime => {
  const runtime = installRuntime(
    createRuntime(config, options),
    (globalThis as typeof globalThis & { chrome?: AuthRuntimeDependencies['chrome'] }).chrome,
  )
  return runtime
}
