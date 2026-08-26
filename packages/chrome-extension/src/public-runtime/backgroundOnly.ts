import type { AuthorizationSnapshotV2 } from '../publicTypes.js'

export interface BackgroundOnlyMessageSender {
  id?: string
  frameId?: number
  origin?: string
  url?: string
  tab?: { id?: number; windowId?: number }
}

export type BackgroundOnlyMessageListener = (
  message: unknown,
  sender: BackgroundOnlyMessageSender,
  sendResponse: (response: unknown) => void,
) => boolean | void

export interface BackgroundOnlySessionStoragePort {
  get(key: string): Promise<Record<string, unknown>>
  set(values: Record<string, unknown>): Promise<void>
  remove(key: string): Promise<void>
  setAccessLevel(value: {
    accessLevel: 'TRUSTED_CONTEXTS'
  }): Promise<void>
}

export interface BackgroundOnlyChromePort {
  storage: {
    session: BackgroundOnlySessionStoragePort
  }
  runtime: {
    id: string
    getURL(path: string): string
    onMessage: {
      addListener(listener: BackgroundOnlyMessageListener): void
    }
    onMessageExternal: {
      addListener(listener: BackgroundOnlyMessageListener): void
    }
  }
  tabs: {
    create(input: {
      url: string
      windowId: number
      openerTabId: number
      active: true
    }): Promise<BackgroundOnlyTab>
    update(
      tabId: number,
      input: { url?: string; active?: boolean },
    ): Promise<BackgroundOnlyTab>
    get(tabId: number): Promise<BackgroundOnlyTab | null>
    remove(tabId: number): Promise<void>
    onRemoved: {
      addListener(listener: (tabId: number) => void): void
    }
  }
  windows: {
    get(windowId: number): Promise<{ id?: number; focused: boolean }>
    update(
      windowId: number,
      input: { focused: true },
    ): Promise<{ id?: number; focused?: boolean }>
  }
  alarms: {
    create(name: string, input: { when: number }): Promise<void>
    clear(name: string): Promise<boolean>
    onAlarm: {
      addListener(listener: (alarm: { name: string }) => void): void
    }
  }
}

export interface BackgroundOnlyTab {
  id?: number
  windowId?: number
  active?: boolean
  url?: string
}

export interface BackgroundOnlyCryptoPort {
  randomBytes(length: 32): Uint8Array
  sha256(value: Uint8Array): Promise<Uint8Array>
  timingSafeEqual(left: string, right: string): boolean
}

export interface BackgroundOnlyStoredGrant {
  accessToken: string
  expiresAt: string
  sessionRevision: string
}

export interface BackgroundOnlyAuthorizationStatePort {
  readSnapshot(): Promise<AuthorizationSnapshotV2>
  saveSnapshot(snapshot: AuthorizationSnapshotV2): Promise<void>
  readGrant(): Promise<BackgroundOnlyStoredGrant | null>
  saveGrant(grant: BackgroundOnlyStoredGrant): Promise<void>
}

export interface BackgroundOnlyPreparedAuthorization {
  state: string
  codeVerifier: string
  authorizeUrl: string
}

export interface BackgroundOnlyBeginAuthorizationResult {
  transactionId: string
  clientId: string
  redirectUri: string
  prepared: BackgroundOnlyPreparedAuthorization
  sourceTabId: number
  sourceWindowId: number
}

interface BackgroundOnlyTransactionBase {
  version: 1
  transactionId: string
  clientId: string
  redirectUri: string
  state: string
  codeVerifier: string
  sourceTabId: number
  sourceWindowId: number
  createdAt: string
  expiresAt: string
}

export type BackgroundOnlyTransactionV1 =
  | (BackgroundOnlyTransactionBase & {
      phase: 'opening'
      authTabId: null | number
    })
  | (BackgroundOnlyTransactionBase & {
      phase: 'authorizing' | 'exchanging'
      authTabId: number
    })

export interface BackgroundOnlyProfilePort {
  callbackOrigin: string
  callbackPath: string
  now(): number
  beginAuthorization(): Promise<BackgroundOnlyBeginAuthorizationResult>
  authorizationUrl(
    transaction: BackgroundOnlyTransactionV1,
  ): Promise<string>
  exchange(input: {
    code: string
    codeVerifier: string
    redirectUri: string
    signal: AbortSignal
  }): Promise<BackgroundOnlyStoredGrant>
}

export interface BackgroundOnlyRuntimeResources {
  chrome: BackgroundOnlyChromePort
  crypto: BackgroundOnlyCryptoPort
  state: BackgroundOnlyAuthorizationStatePort
  profile: BackgroundOnlyProfilePort
}
