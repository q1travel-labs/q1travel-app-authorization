export interface ChromeStorageAreaPort {
  get(key: string): Promise<Record<string, unknown>>
  set(values: Record<string, unknown>): Promise<void>
  remove(key: string): Promise<void>
}

export interface ChromeSessionStoragePort extends ChromeStorageAreaPort {
  setAccessLevel(value: {
    accessLevel: 'TRUSTED_CONTEXTS'
  }): Promise<void>
}

export interface ChromeStoragePort {
  session: ChromeSessionStoragePort
}

export interface ChromeMessageSenderPort {
  id?: string
  frameId?: number
  origin?: string
  url?: string
  tab?: { id?: number; windowId?: number }
}

export interface ChromeRuntimeIdentityPort {
  id: string
  getURL(path: string): string
}

export interface ChromeTabPort {
  id?: number
  windowId?: number
  active?: boolean
  url?: string
}

export interface ChromeTabsPort {
  create(input: {
    url: string
    windowId: number
    openerTabId: number
    active: true
  }): Promise<ChromeTabPort>
  update(
    tabId: number,
    input: { url?: string; active?: boolean },
  ): Promise<ChromeTabPort>
  get(tabId: number): Promise<ChromeTabPort | null>
  remove(tabId: number): Promise<void>
}

export interface ChromeWindowsPort {
  get(windowId: number): Promise<{ id?: number; focused: boolean }>
  update(
    windowId: number,
    input: { focused: true },
  ): Promise<{ id?: number; focused?: boolean }>
}

export interface ChromeTabCoordinationPort {
  runtime: ChromeRuntimeIdentityPort
  tabs: ChromeTabsPort
  windows: ChromeWindowsPort
}

export type ChromeMessageListenerPort = (
  message: unknown,
  sender: ChromeMessageSenderPort,
  sendResponse: (response: unknown) => void,
) => boolean | void

export interface ChromeAuthorizationPort {
  runtime: {
    onMessage: {
      addListener(listener: ChromeMessageListenerPort): void
    }
    onMessageExternal: {
      addListener(listener: ChromeMessageListenerPort): void
    }
  }
  tabs: {
    onRemoved: {
      addListener(listener: (tabId: number) => void): void
    }
  }
  alarms: {
    onAlarm: {
      addListener(listener: (alarm: { name: string }) => void): void
    }
  }
}
