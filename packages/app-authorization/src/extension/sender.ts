import type { RuntimeMessageSender } from './ports.js'

export const isTrustedExtensionSender = (
  sender: RuntimeMessageSender,
  extensionId: string,
): boolean => {
  if (sender.id !== extensionId) return false
  const expectedOrigin = `chrome-extension://${extensionId}`
  if (sender.origin !== undefined && sender.origin !== expectedOrigin) return false
  if (sender.url === undefined) return sender.tab === undefined
  try {
    const url = new URL(sender.url)
    return url.protocol === 'chrome-extension:' && url.hostname === extensionId
  } catch {
    return false
  }
}
