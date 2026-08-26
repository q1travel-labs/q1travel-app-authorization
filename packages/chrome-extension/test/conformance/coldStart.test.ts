import { describe, expect, it } from 'vitest'

import {
  BackgroundRuntime,
  type RuntimeAuthorizationCoordinator,
} from '../../src/background-runtime/runtime'
import { installChromeAppAuthorizationListeners } from '../../src/chrome-adapter/listenerInstaller'

const deferred = () => {
  let resolve!: () => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<void>((done, fail) => {
    resolve = done
    reject = fail
  })
  return { promise, reject, resolve }
}

class EventPort<T extends (...args: never[]) => unknown> {
  readonly listeners: T[] = []
  addListener(listener: T): void {
    this.listeners.push(listener)
  }
}

const snapshot = {
  profile: { profileId: 'client-v2-development', environment: 'development' },
  runtime: 'ready',
  authorization: { kind: 'signed-out', reason: 'never-authorized' },
  interaction: { phase: 'authorizing' },
} as const

const callbackSender = {
  frameId: 0,
  origin: 'https://web.example.test',
  url: 'https://web.example.test/apps/extension-auth/callback/client-v2',
  tab: { id: 31 },
}

const createHarness = () => {
  const readiness = deferred()
  const calls: string[] = []
  const coordinator: RuntimeAuthorizationCoordinator = {
    async login() {
      calls.push('login')
      return snapshot
    },
    async status() {
      calls.push('status')
      return snapshot
    },
    async focusAuthorization() {
      calls.push('focus')
      return snapshot
    },
    async handleBootstrapReport() {
      calls.push('bootstrap')
      return true
    },
    async handleExternalCallback() {
      calls.push('external')
      return { ok: true }
    },
    async runPostResponseCleanup() {},
    async handleAlarm() {
      calls.push('alarm')
    },
    async handleTabRemoved() {
      calls.push('removed')
    },
  }
  const runtime = new BackgroundRuntime(coordinator, readiness.promise)
  const onMessage = new EventPort<RuntimeAuthorizationCoordinatorMessage>()
  const onMessageExternal =
    new EventPort<RuntimeAuthorizationCoordinatorMessage>()
  const onRemoved = new EventPort<(tabId: number) => void>()
  const onAlarm = new EventPort<(alarm: { name: string }) => void>()
  const chrome = {
    runtime: {
      onMessage,
      onMessageExternal,
    },
    tabs: { onRemoved },
    alarms: { onAlarm },
  }
  return {
    calls,
    chrome,
    onAlarm,
    onMessage,
    onMessageExternal,
    onRemoved,
    readiness,
    runtime,
  }
}

type RuntimeAuthorizationCoordinatorMessage = (
  message: unknown,
  sender: {
    id?: string
    frameId?: number
    origin?: string
    url?: string
    tab?: { id?: number }
  },
  sendResponse: (response: unknown) => void,
) => boolean | void

const dispatchMessage = (
  listener: RuntimeAuthorizationCoordinatorMessage,
  message: unknown,
): { handled: boolean; response: Promise<unknown> } => {
  let respond!: (response: unknown) => void
  const response = new Promise<unknown>((resolve) => {
    respond = resolve
  })
  const handled =
    listener(
      message,
      {
        frameId: 0,
        origin: 'https://web.example.test',
        url: 'https://web.example.test/apps/extension-auth/callback/client-v2',
        tab: { id: 31 },
      },
      respond,
    ) === true
  return { handled, response }
}

describe('synchronous listener installation and cold start', () => {
  it('installs all listeners synchronously before runtime readiness settles', () => {
    const harness = createHarness()

    installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)

    expect(harness.onMessage.listeners).toHaveLength(1)
    expect(harness.onMessageExternal.listeners).toHaveLength(1)
    expect(harness.onRemoved.listeners).toHaveLength(1)
    expect(harness.onAlarm.listeners).toHaveLength(1)
    expect(harness.calls).toEqual([])
  })

  it('captures the first external callback synchronously and handles it after readiness', async () => {
    const harness = createHarness()
    installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)

    const dispatched = dispatchMessage(
      harness.onMessageExternal.listeners[0],
      { type: 'q1travel.extensionAuth.callback.v1' },
    )

    expect(dispatched.handled).toBe(true)
    expect(harness.calls).toEqual([])
    harness.readiness.resolve()
    await expect(dispatched.response).resolves.toEqual({ ok: true })
    expect(harness.calls).toEqual(['external'])
  })

  it.each([
    ['internal', 'q1travel.someFutureProtocol.v1'],
    ['internal', undefined],
    ['external', 'q1travel.someFutureProtocol.v1'],
    ['external', undefined],
  ] as const)(
    'does not claim an unrelated %s message with marker %s',
    async (channel, type) => {
      const harness = createHarness()
      installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)
      const responses: unknown[] = []
      const listener =
        channel === 'internal'
          ? harness.onMessage.listeners[0]
          : harness.onMessageExternal.listeners[0]

      const handled = listener(
        type === undefined ? null : { type },
        callbackSender,
        (response) => responses.push(response),
      )

      expect(handled).toBeUndefined()
      expect(responses).toEqual([])
      expect(harness.calls).toEqual([])
      harness.readiness.resolve()
      await Promise.resolve()
      await Promise.resolve()
      expect(responses).toEqual([])
      expect(harness.calls).toEqual([])
    },
  )

  it('captures the first bootstrap report, alarm and tab removal before readiness', async () => {
    const harness = createHarness()
    installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)
    const internal = dispatchMessage(
      harness.onMessage.listeners[0],
      { type: 'q1travel.extensionAuth.bootstrap.v1' },
    )
    harness.onAlarm.listeners[0]({ name: 'transaction-alarm' })
    harness.onRemoved.listeners[0](31)

    expect(internal.handled).toBe(true)
    expect(harness.calls).toEqual([])
    harness.readiness.resolve()
    await expect(internal.response).resolves.toBe(true)
    await Promise.resolve()
    await Promise.resolve()
    expect(harness.calls.sort()).toEqual(['alarm', 'bootstrap', 'removed'])
  })

  it('fails the first external message closed when trusted readiness rejects', async () => {
    const harness = createHarness()
    installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)
    const dispatched = dispatchMessage(
      harness.onMessageExternal.listeners[0],
      { type: 'q1travel.extensionAuth.callback.v1' },
    )

    harness.readiness.reject(new Error('private storage failure detail'))

    await expect(dispatched.response).resolves.toEqual({
      ok: false,
      error: 'connectionFailed',
    })
    expect(harness.calls).toEqual([])
  })

  it('remembers an early readiness rejection and fails a later first message closed', async () => {
    const harness = createHarness()
    installChromeAppAuthorizationListeners(harness.chrome, harness.runtime)
    harness.readiness.reject(new Error('early private storage failure detail'))
    await Promise.resolve()
    await Promise.resolve()

    const dispatched = dispatchMessage(
      harness.onMessageExternal.listeners[0],
      { type: 'q1travel.extensionAuth.callback.v1' },
    )

    await expect(dispatched.response).resolves.toEqual({
      ok: false,
      error: 'connectionFailed',
    })
    expect(harness.calls).toEqual([])
  })

  it('makes public actions await the same readiness gate', async () => {
    const harness = createHarness()
    let settled = false
    const login = harness.runtime.login().then((value) => {
      settled = true
      return value
    })

    await Promise.resolve()
    expect(settled).toBe(false)
    expect(harness.calls).toEqual([])
    harness.readiness.resolve()

    await expect(login).resolves.toEqual(snapshot)
    expect(harness.calls).toEqual(['login'])
  })
})
