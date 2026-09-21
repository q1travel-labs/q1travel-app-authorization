export type { AuthFlowLauncher } from './ports.js'
export type { AuthRuntime, AuthRuntimeOptions } from './runtime.js'

import type { AuthConfig } from '../core/config.js'
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
