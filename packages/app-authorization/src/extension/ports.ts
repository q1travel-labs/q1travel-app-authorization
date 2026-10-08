export interface SessionStoragePort {
  get(keys: string | readonly string[] | null): Promise<Record<string, unknown>>
  set(values: Record<string, unknown>): Promise<void>
  remove(keys: string | readonly string[]): Promise<void>
  setAccessLevel(options: { accessLevel: 'TRUSTED_CONTEXTS' }): Promise<void>
}

export interface RuntimeMessageSender {
  readonly id?: string
  readonly tab?: unknown
  readonly url?: string
  readonly origin?: string
}

export type RuntimeMessageListener = (
  message: unknown,
  sender: RuntimeMessageSender,
  sendResponse: (response: unknown) => void,
) => boolean | void

export interface ChromePort {
  readonly identity: {
    launchWebAuthFlow(options: {
      readonly url: string
      readonly interactive: true
    }): Promise<string | undefined>
  }
  readonly runtime: {
    readonly id: string
    readonly onMessage: {
      addListener(listener: RuntimeMessageListener): void
      removeListener(listener: RuntimeMessageListener): void
    }
    sendMessage(message: unknown): Promise<unknown>
  }
  readonly storage: { readonly session: SessionStoragePort }
}

export type AuthRuntimeChromePort = Pick<ChromePort, 'runtime' | 'storage'>

export interface AuthFlowLauncher {
  launch(authorizationUrl: string): Promise<string>
}
