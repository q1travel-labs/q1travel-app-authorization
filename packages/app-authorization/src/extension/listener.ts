import type { AuthSession } from '../core/types.js'
import type { AuthRuntimeChromePort, AuthorizationSourceMetadata } from './ports.js'
import { AUTH_PROTOCOL, SESSION_CHANGED, parseRequest, serializeError } from './protocol.js'
import type { AuthRuntime } from './runtime.js'
import { isTrustedExtensionSender } from './sender.js'

export const installRuntime = (
  runtime: AuthRuntime,
  chrome: AuthRuntimeChromePort | undefined,
  loginFromSource?: (source: AuthorizationSourceMetadata) => Promise<AuthSession>,
): AuthRuntime => {
  if (!chrome) throw new TypeError('Chrome runtime is unavailable.')
  runtime.onSessionChange((session: AuthSession) => {
    void chrome.runtime.sendMessage({ type: SESSION_CHANGED, session }).catch(() => undefined)
  })
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const request = parseRequest(message)
    if (!request || !isTrustedExtensionSender(sender, chrome.runtime.id)) return
    if (loginFromSource && request.action === 'login' && sender.tab !== undefined &&
      (!Number.isInteger(sender.tab.id) || (sender.tab.id ?? -1) < 0)) return
    const operation = request.action === 'login'
      ? loginFromSource ? loginFromSource(Object.freeze({
        ...(sender.tab === undefined ? {} : { tabId: sender.tab.id }),
        ...(sender.frameId === undefined ? {} : { frameId: sender.frameId }),
        ...(sender.documentId === undefined ? {} : { documentId: sender.documentId }),
      })) : runtime.login()
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
