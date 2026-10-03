import type { AuthSession } from '../core/types.js'
import type { ChromePort } from './ports.js'
import { AUTH_PROTOCOL, SESSION_CHANGED, parseRequest, serializeError } from './protocol.js'
import type { AuthRuntime } from './runtime.js'
import { isTrustedExtensionSender } from './sender.js'

export const installRuntime = (
  runtime: AuthRuntime,
  chrome: ChromePort | undefined,
): AuthRuntime => {
  if (!chrome) throw new TypeError('Chrome runtime is unavailable.')
  runtime.onSessionChange((session: AuthSession) => {
    void chrome.runtime.sendMessage({ type: SESSION_CHANGED, session }).catch(() => undefined)
  })
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const request = parseRequest(message)
    if (!request || !isTrustedExtensionSender(sender, chrome.runtime.id)) return
    const operation = request.action === 'login'
      ? runtime.login()
      : request.action === 'logout'
        ? runtime.logout()
        : request.action === 'verifySession'
          ? runtime.verifySession()
          : runtime.getSession()
    void operation.then(
      (session) => sendResponse({
        protocol: AUTH_PROTOCOL,
        requestId: request.requestId,
        ok: true,
        session,
      }),
      (error) => sendResponse({
        protocol: AUTH_PROTOCOL,
        requestId: request.requestId,
        ok: false,
        error: serializeError(error),
      }),
    )
    return true
  })
  return runtime
}
