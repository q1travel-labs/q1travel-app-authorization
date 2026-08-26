import type { BackgroundRuntime } from '../background-runtime/runtime.js'
import type { ChromeAuthorizationPort } from './ports.js'

export function installChromeAppAuthorizationListeners(
  chrome: ChromeAuthorizationPort,
  runtime: BackgroundRuntime,
): void {
  chrome.runtime.onMessage.addListener(runtime.handleInternalMessage)
  chrome.runtime.onMessageExternal.addListener(runtime.handleExternalMessage)
  chrome.tabs.onRemoved.addListener(runtime.handleTabRemoved)
  chrome.alarms.onAlarm.addListener(runtime.handleAlarm)
}
