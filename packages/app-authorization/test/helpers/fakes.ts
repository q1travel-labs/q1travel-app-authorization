import type {
  ChromePort,
  RuntimeMessageListener,
  SessionStoragePort,
} from '../../src/extension/ports.js'

export class MemorySessionStorage implements SessionStoragePort {
  readonly values: Record<string, unknown> = {}
  accessLevel: string | undefined

  async get(keys: string | readonly string[] | null): Promise<Record<string, unknown>> {
    if (keys === null) return structuredClone(this.values)
    const requested = typeof keys === 'string' ? [keys] : keys
    return Object.fromEntries(
      requested
        .filter((key) => Object.prototype.hasOwnProperty.call(this.values, key))
        .map((key) => [key, structuredClone(this.values[key])]),
    )
  }

  async set(values: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, structuredClone(values))
  }

  async remove(keys: string | readonly string[]): Promise<void> {
    for (const key of typeof keys === 'string' ? [keys] : keys) {
      delete this.values[key]
    }
  }

  async setAccessLevel(options: { accessLevel: 'TRUSTED_CONTEXTS' }): Promise<void> {
    this.accessLevel = options.accessLevel
  }
}

export const createChromePort = (storage = new MemorySessionStorage()) => {
  const listeners = new Set<RuntimeMessageListener>()
  const sentMessages: unknown[] = []
  const chrome: ChromePort = {
    identity: {
      async launchWebAuthFlow() {
        throw new Error('No launcher installed')
      },
    },
    runtime: {
      id: 'abcdefghijklmnopabcdefghijklmnop',
      onMessage: {
        addListener(listener) {
          listeners.add(listener)
        },
        removeListener(listener) {
          listeners.delete(listener)
        },
      },
      async sendMessage(message) {
        sentMessages.push(structuredClone(message))
        for (const listener of listeners) {
          const result = await new Promise<unknown>((resolve) => {
            const keepChannel = listener(message, { id: chrome.runtime.id }, resolve)
            if (keepChannel !== true) resolve(undefined)
          })
          if (result !== undefined) return result
        }
        return undefined
      },
    },
    storage: { session: storage },
  }
  return { chrome, listeners, sentMessages, storage }
}

export const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
