import type { AuthRuntimeChromePort } from './ports.js'

export interface AuthTab {
  readonly id?: number
  readonly windowId: number
  readonly index: number
  readonly active: boolean
  readonly openerTabId?: number
  readonly url?: string
}

export interface ExternalCallbackSender {
  readonly id?: string
  readonly origin?: string
  readonly url?: string
  readonly frameId?: number
  readonly tab?: { readonly id?: number }
}

export type ExternalCallbackListener = (
  message: unknown,
  sender: ExternalCallbackSender,
  sendResponse: (response: unknown) => void,
) => boolean | void

export interface TabAuthChromePort extends AuthRuntimeChromePort {
  readonly runtime: AuthRuntimeChromePort['runtime'] & {
    readonly onMessageExternal: {
      addListener(listener: ExternalCallbackListener): void
      removeListener(listener: ExternalCallbackListener): void
    }
  }
  readonly tabs: {
    create(options: { url: string; windowId: number; index: number; openerTabId: number; active: true }): Promise<AuthTab>
    get(tabId: number): Promise<AuthTab>
    query(options: Record<string, unknown>): Promise<AuthTab[]>
    update(tabId: number, options: { url?: string; active?: true }): Promise<unknown>
    remove(tabId: number): Promise<void>
    readonly onRemoved: { addListener(listener: (tabId: number) => void): void }
  }
  readonly windows: {
    get(windowId: number): Promise<{ readonly focused: boolean }>
    update(windowId: number, options: { focused: true }): Promise<unknown>
  }
  readonly alarms: {
    create(name: string, options: { when: number }): Promise<void>
    clear(name: string): Promise<boolean>
    readonly onAlarm: { addListener(listener: (alarm: { readonly name: string }) => void): void }
  }
}
