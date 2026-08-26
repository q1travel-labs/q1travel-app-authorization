import type { AuthorizationSnapshotV2, UiMessageSender } from '../../src/index'

export type ChromeListener = (
  message: unknown,
  sender: UiMessageSender,
  sendResponse: (response: unknown) => void,
) => true | void

export const backgroundSnapshot: AuthorizationSnapshotV2 = {
  profile: null,
  runtime: 'ready',
  authorization: { kind: 'signed-out', reason: 'never-authorized' },
  interaction: { phase: 'idle' },
}

export const createBackgroundOnlyHarness = () => {
  const calls: string[] = []
  const internalListeners: ChromeListener[] = []
  const externalListeners: ChromeListener[] = []
  const alarmListeners: Array<(alarm: { name: string }) => void> = []
  const tabRemovedListeners: Array<(tabId: number) => void> = []
  const session = new Map<string, unknown>()
  let snapshot = structuredClone(backgroundSnapshot)
  let storedGrant: {
    accessToken: string
    expiresAt: string
    sessionRevision: string
  } | null = null

  const chrome = {
    storage: {
      session: {
        async setAccessLevel() {
          calls.push('storage.trusted')
        },
        async get(key: string) {
          return session.has(key) ? { [key]: structuredClone(session.get(key)) } : {}
        },
        async set(values: Record<string, unknown>) {
          for (const [key, value] of Object.entries(values)) {
            session.set(key, structuredClone(value))
          }
        },
        async remove(key: string) {
          session.delete(key)
        },
      },
    },
    runtime: {
      id: 'abcdefghijklmnopabcdefghijklmnop',
      getURL(path: string) {
        return `chrome-extension://abcdefghijklmnopabcdefghijklmnop/${path}`
      },
      onMessage: {
        addListener(listener: ChromeListener) {
          internalListeners.push(listener)
        },
      },
      onMessageExternal: {
        addListener(listener: ChromeListener) {
          externalListeners.push(listener)
        },
      },
    },
    tabs: {
      async create() {
        calls.push('tabs.create')
        return { id: 7, windowId: 3, active: true }
      },
      async update(_tabId: number, input: { url?: string; active?: boolean }) {
        calls.push(input.url === undefined ? 'tabs.activate' : 'tabs.navigate')
        return { id: 7, windowId: 3, active: input.active, url: input.url }
      },
      async get() {
        return { id: 7, windowId: 3, active: false }
      },
      async remove() {
        calls.push('tabs.remove')
      },
      onRemoved: {
        addListener(listener: (tabId: number) => void) {
          tabRemovedListeners.push(listener)
        },
      },
    },
    windows: {
      async get() {
        return { id: 3, focused: false }
      },
      async update() {
        calls.push('windows.focus')
        return { id: 3, focused: true }
      },
    },
    alarms: {
      async create() {
        calls.push('alarm.create')
      },
      async clear() {
        calls.push('alarm.clear')
        return true
      },
      onAlarm: {
        addListener(listener: (alarm: { name: string }) => void) {
          alarmListeners.push(listener)
        },
      },
    },
  }

  return {
    alarmListeners,
    background: {
      chrome,
      crypto: {
        randomBytes() {
          return new Uint8Array(32)
        },
        async sha256() {
          return new Uint8Array(32)
        },
        timingSafeEqual(left: string, right: string) {
          return left === right
        },
      },
      state: {
        async readSnapshot() {
          return structuredClone(snapshot)
        },
        async saveSnapshot(value: AuthorizationSnapshotV2) {
          snapshot = structuredClone(value)
        },
        async readGrant() {
          return structuredClone(storedGrant)
        },
        async saveGrant(value: NonNullable<typeof storedGrant>) {
          storedGrant = structuredClone(value)
        },
      },
      profile: {
        callbackOrigin: 'https://web.example.test',
        callbackPath: '/apps/extension-auth/callback/client-v2',
        now() {
          return Date.parse('2026-08-26T04:00:00.000Z')
        },
        async beginAuthorization() {
          calls.push('beginAuthorization')
          return {
            transactionId: 'transaction-id',
            clientId: 'browser-client-v2',
            redirectUri:
              'https://web.example.test/apps/extension-auth/callback/client-v2',
            prepared: {
              state: 's'.repeat(43),
              codeVerifier: 'v'.repeat(43),
              authorizeUrl:
                'https://accounts.example.test/app-authorizations/v1/authorize',
            },
            sourceTabId: 5,
            sourceWindowId: 3,
          }
        },
        async authorizationUrl() {
          return 'https://accounts.example.test/app-authorizations/v1/authorize'
        },
        async exchange() {
          return {
            accessToken: 'background-only-token',
            expiresAt: '2026-08-26T05:00:00.000Z',
            sessionRevision: 'revision-1',
          }
        },
      },
    },
    calls,
    chrome,
    externalListeners,
    internalListeners,
    tabRemovedListeners,
  }
}
