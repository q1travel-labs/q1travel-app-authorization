import {
  Fragment,
  createElement,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from 'react'
import {
  AppAuthorizationError,
  AuthErrorCode,
  type AuthSession,
} from '../extension/ui.js'

export interface AuthClient {
  verifySession(): Promise<AuthSession>
  onSessionChange(callback: (session: AuthSession) => void): () => void
}

export interface AuthSessionState {
  readonly session: AuthSession | null
  readonly error: AppAuthorizationError | null
  readonly refresh: () => Promise<void>
}

const normalizeError = (error: unknown): AppAuthorizationError =>
  error instanceof AppAuthorizationError
    ? error
    : new AppAuthorizationError(AuthErrorCode.runtimeUnavailable)

export const useAuthSession = (client: AuthClient): AuthSessionState => {
  const [session, setSession] = useState<AuthSession | null>(null)
  const [error, setError] = useState<AppAuthorizationError | null>(null)
  const revision = useRef(0)
  const refresh = useCallback(async () => {
    const expectedRevision = ++revision.current
    try {
      const next = await client.verifySession()
      if (revision.current === expectedRevision) {
        setSession(next)
        setError(null)
      }
    } catch (reason) {
      if (revision.current === expectedRevision) {
        setError(normalizeError(reason))
      }
    }
  }, [client])

  useEffect(() => {
    let active = true
    const unsubscribe = client.onSessionChange((next) => {
      if (!active) return
      revision.current += 1
      setSession(next)
      setError(null)
    })
    const expectedRevision = ++revision.current
    void client.verifySession().then(
      (next) => {
        if (active && revision.current === expectedRevision) setSession(next)
      },
      (reason) => {
        if (active && revision.current === expectedRevision) {
          setError(normalizeError(reason))
        }
      },
    )
    return () => {
      active = false
      revision.current += 1
      unsubscribe()
    }
  }, [client])

  return { session, error, refresh }
}

export interface AuthGateProps {
  readonly client: AuthClient
  readonly children: ReactNode
  readonly signedOut: ReactNode
  readonly loading: ReactNode
  readonly failed?: ReactNode | ((error: AppAuthorizationError) => ReactNode)
}

export const AuthGate = (props: AuthGateProps): ReactElement | null => {
  const { session, error } = useAuthSession(props.client)
  if (error) {
    const fallback = typeof props.failed === 'function'
      ? props.failed(error)
      : props.failed ?? props.signedOut
    return createElement(Fragment, null, fallback)
  }
  if (session === null) return createElement(Fragment, null, props.loading)
  if (session.status === 'signed-out') return createElement(Fragment, null, props.signedOut)
  return createElement(Fragment, null, props.children)
}
