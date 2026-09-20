import { createElement } from 'react'
import { act, create } from 'react-test-renderer'
import { describe, expect, it } from 'vitest'
import type { AuthSession } from '../src/core/types.js'
import { AuthGate } from '../src/react/index.js'

describe('AuthGate', () => {
  it('renders loading and then authenticated children', async () => {
    let resolve!: (session: AuthSession) => void
    const client = {
      verifySession: () => new Promise<AuthSession>((done) => { resolve = done }),
      onSessionChange: () => () => undefined,
    }
    let renderer: ReturnType<typeof create>
    await act(async () => {
      renderer = create(createElement(AuthGate, {
        client,
        loading: createElement('span', null, 'loading'),
        signedOut: createElement('span', null, 'signed out'),
        children: createElement('main', null, 'application'),
      }))
    })
    expect(renderer!.toJSON()).toMatchObject({ type: 'span', children: ['loading'] })

    await act(async () => {
      resolve({
        status: 'authenticated',
        expiresAt: '2026-09-20T08:00:00.000Z',
        scopes: ['orders:read'],
      })
    })
    expect(renderer!.toJSON()).toMatchObject({ type: 'main', children: ['application'] })
  })

  it('renders the supplied signed-out view without product copy', async () => {
    const client = {
      verifySession: async () => ({ status: 'signed-out' } as const),
      onSessionChange: () => () => undefined,
    }
    let renderer: ReturnType<typeof create>
    await act(async () => {
      renderer = create(createElement(AuthGate, {
        client,
        loading: null,
        signedOut: createElement('button', null, 'Continue'),
        children: createElement('main', null, 'application'),
      }))
    })
    expect(renderer!.toJSON()).toMatchObject({ type: 'button', children: ['Continue'] })
  })

  it('does not let a stale initial read overwrite a newer session event', async () => {
    let resolveInitial!: (session: AuthSession) => void
    let publish!: (session: AuthSession) => void
    const client = {
      verifySession: () => new Promise<AuthSession>((resolve) => { resolveInitial = resolve }),
      onSessionChange: (callback: (session: AuthSession) => void) => {
        publish = callback
        return () => undefined
      },
    }
    let renderer: ReturnType<typeof create>
    await act(async () => {
      renderer = create(createElement(AuthGate, {
        client,
        loading: createElement('span', null, 'loading'),
        signedOut: createElement('button', null, 'Continue'),
        children: createElement('main', null, 'application'),
      }))
    })
    await act(async () => publish({ status: 'signed-out' }))
    await act(async () => resolveInitial({
      status: 'authenticated',
      expiresAt: '2026-09-20T08:00:00.000Z',
      scopes: ['orders:read'],
    }))

    expect(renderer!.toJSON()).toMatchObject({
      type: 'button',
      children: ['Continue'],
    })
  })
})
