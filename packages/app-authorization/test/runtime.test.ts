import { afterEach, describe, expect, it, vi } from 'vitest'
import { AppAuthorizationError, AuthErrorCode } from '../src/core/types.js'
import { createAuthFacadeWithDependencies } from '../src/extension/facade.js'
import { installRuntime } from '../src/extension/listener.js'
import { createAuthRuntimeWithDependencies, type AuthRuntimeDependencies } from '../src/extension/runtime.js'
import { SessionRepository, type SessionRecord, type StoredSession } from '../src/extension/storage.js'
import { createChromePort, jsonResponse } from './helpers/fakes.js'
import { browserPorts, callbackFor, config, grant, identity, inspectFetch } from './helpers/oauth.js'

function harness() {
  const ports = browserPorts()
  let time = 1_000
  const chrome = createChromePort()
  const launch = vi.fn(async (url: string) => callbackFor(url))
  const consumed = new Set<string>()
  const issued = new Set<string>()
  let active = false
  let generation = 0
  const tokens = () => {
    const value = { ...grant, access_token: 'access-' + generation, refresh_token: 'refresh-' + generation }
    issued.add(value.access_token)
    return jsonResponse(value)
  }
  const invalidToken = () => jsonResponse({ error: { code: 'invalid_token' } }, 401)
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input))
    const body = new URLSearchParams(String(init?.body))
    if (url.pathname === '/oauth/token') {
      if (body.get('grant_type') === 'authorization_code') {
        active = true
        return tokens()
      }
      const refresh = body.get('refresh_token')!
      if (consumed.has(refresh)) active = false
      if (!active || refresh !== 'refresh-' + generation) return jsonResponse({ error: 'invalid_grant' }, 400)
      consumed.add(refresh)
      generation++
      return tokens()
    }
    if (url.pathname === '/oauth/revoke') {
      if (body.get('token') === 'refresh-' + generation) active = false
      return new Response(null)
    }
    const authorization = new Headers(init?.headers).get('Authorization')
    if (!active || !authorization?.startsWith('DPoP ') || !issued.has(authorization.slice(5))) return invalidToken()
    return jsonResponse(url.pathname === '/v1/identity' ? identity : { ok: true })
  })
  const create = (options: Partial<AuthRuntimeDependencies> = {}) => createAuthRuntimeWithDependencies(config, {
    ...ports, chrome: chrome.chrome, fetch: inspectFetch(fetch), launcher: { launch }, now: () => time, ...options,
  })
  return { ...ports, ...chrome, fetch, launch, create, setTime(value: number) { time = value } }
}

const signedOut = { status: 'signed-out' }
const business = config.apiOrigin + '/v1/variants'
const fields = (init?: RequestInit) => Object.fromEntries(new URLSearchParams(String(init?.body)))
afterEach(() => vi.restoreAllMocks())

describe('后台会话', () => {
  it('Given 同时登录 / When 换码 / Then 只换一次并使用实际 expires_in 和零权限身份', async () => {
    const h = harness()
    const runtime = h.create()
    const subscriber = vi.fn(() => { throw new Error() })
    runtime.onSessionChange(subscriber)
    const [first, second] = await Promise.all([runtime.login(), runtime.login()])
    expect(first).toEqual({ status: 'authenticated', expiresAt: '1970-01-01T00:01:14.000Z', identity })
    expect(second).toEqual(first)
    expect(h.launch).toHaveBeenCalledOnce()
    expect(h.fetch.mock.calls.map(([url]) => url)).toEqual([config.authOrigin + '/oauth/token', config.apiOrigin + '/v1/identity'])
    expect(fields(h.fetch.mock.calls[0][1])).toEqual({ grant_type: 'authorization_code', client_id: config.clientId,
      resource: 'https://api.q1lx.com/v1', redirect_uri: config.redirectUri, code: 'issued-code', code_verifier: expect.stringMatching(/^[\w-]{43}$/u) })
    expect(subscriber).toHaveBeenCalledExactlyOnceWith(first)
    expect(h.storage.values).toEqual({})
  })

  it('Given 两个扩展页面 / When 同时刷新 / Then 只消费一次且两个响应都在新令牌提交后返回', async () => {
    const h = harness()
    installRuntime(h.create(), h.chrome)
    const a = createAuthFacadeWithDependencies({ chrome: h.chrome })
    const b = createAuthFacadeWithDependencies({ chrome: h.chrome })
    await a.login()
    h.fetch.mockClear()
    const afterCommit = async () => {
      const stored = await h.repository.read()
      expect(stored).toMatchObject({ refreshToken: 'refresh-1', accessToken: 'access-1' })
    }
    await Promise.all([a.refresh().then(afterCommit), b.refresh().then(afterCommit)])
    expect(h.fetch).toHaveBeenCalledOnce()
    expect(fields(h.fetch.mock.calls[0][1])).toEqual({ grant_type: 'refresh_token', client_id: config.clientId,
      resource: 'https://api.q1lx.com/v1', refresh_token: 'refresh-0' })
    expect(JSON.stringify(h.sentMessages)).not.toMatch(/access-[01]|refresh-[01]|"jwk"|code_verifier/)
  })

  it('Given 两个独立 runtime / When 同代并发刷新 / Then 锁内重读版本并返回同一轮换结果', async () => {
    const h = harness()
    const a = h.create()
    await a.login()
    const b = h.create()
    h.fetch.mockClear()
    await Promise.all([a.refresh(), b.refresh()])
    expect(h.fetch).toHaveBeenCalledOnce()
    expect(h.request.mock.calls.length).toBeGreaterThanOrEqual(2)
    expect(new Set(h.request.mock.calls.map(([name]) => name)).size).toBe(1)
  })

  it('Given 后台重启 / When 恢复到期的 AT / Then 轮换一次并使用原密钥', async () => {
    const h = harness()
    await h.create().login()
    const previous = await h.repository.read() as StoredSession
    await expect(crypto.subtle.exportKey('jwk', previous.key.privateKey)).rejects.toThrow()
    h.setTime(74_000)
    h.fetch.mockClear()
    const worker = h.create({ verifyOnStartup: true })
    await worker.ready()
    expect(await worker.restore()).toMatchObject({ status: 'authenticated', expiresAt: '1970-01-01T00:02:27.000Z' })
    expect(h.fetch.mock.calls.map(([url]) => url)).toEqual([config.authOrigin + '/oauth/token', config.apiOrigin + '/v1/identity'])
    const next = await h.repository.read() as StoredSession
    expect(await crypto.subtle.exportKey('jwk', next.key.publicKey)).toEqual(await crypto.subtle.exportKey('jwk', previous.key.publicKey))
  })

  it.each(['database', 'key', 'claim'])('Given 丢失 %s 或刷新中断 / When 重启 / Then 清理会话且不发送旧 RT', async (loss) => {
    const h = harness()
    await h.create().login()
    const session = await h.repository.read() as StoredSession
    if (loss === 'claim') await h.repository.write({ rotating: true, version: session.version })
    if (loss === 'key') await h.repository.write({ ...session, key: undefined } as unknown as StoredSession)
    if (loss === 'database') await new Promise<void>((resolve, reject) => {
      const request = h.database.deleteDatabase('q1travel.oauth')
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })
    h.fetch.mockClear()
    expect(await h.create().restore()).toEqual(signedOut)
    expect(await h.repository.read()).toBeUndefined()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it.each(['response', 'commit'])('Given 服务器完成轮换 / When %s 失败 / Then 重新授权且重启不重放', async (failure) => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    const server = h.fetch.getMockImplementation()!
    h.fetch.mockImplementationOnce(async (url, init) => {
      const claimed = await h.repository.read()
      expect(claimed).toEqual({ rotating: true, version: expect.any(String) })
      const response = await server(url, init)
      if (failure === 'response') throw new Error('lost response')
      return response
    })
    if (failure === 'commit') {
      const write = SessionRepository.prototype.write
      vi.spyOn(SessionRepository.prototype, 'write').mockImplementation(function (this: SessionRepository, row: SessionRecord) {
        if (!('rotating' in row)) throw new AppAuthorizationError(AuthErrorCode.storageUnavailable)
        return write.call(this, row)
      })
    }
    await expect(worker.refresh()).rejects.toMatchObject({ code: 'reauthorization_required' })
    h.fetch.mockClear()
    expect(await h.create().refresh()).toEqual(signedOut)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('Given 领用标记落盘失败 / When 刷新 / Then 未发令牌请求且保留可用会话', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    h.fetch.mockClear()
    vi.spyOn(SessionRepository.prototype, 'write').mockRejectedValueOnce(new AppAuthorizationError(AuthErrorCode.storageUnavailable))
    await expect(worker.refresh()).rejects.toMatchObject({ code: 'storage_unavailable' })
    expect(h.fetch).not.toHaveBeenCalled()
    expect(await worker.restore()).toMatchObject({ status: 'authenticated' })
  })

  it('Given 旧 RT 已消费 / When 替身报告重放并撤族 / Then 客户端清会话且兄弟 AT 无效', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    const stale = await h.repository.read() as StoredSession
    await worker.refresh()
    const sibling = await h.repository.read() as StoredSession
    await h.repository.write(stale)
    await expect(worker.refresh()).rejects.toMatchObject({ code: 'oauth_invalid_grant' })
    expect(await worker.restore()).toEqual(signedOut)
    await h.repository.write(sibling)
    expect(await worker.getIdentity()).toEqual(signedOut)
  })

  it('Given 到期 AT 和当前 RT / When 退出 / Then 直接撤整族并清除本地会话', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    await worker.refresh()
    h.setTime(100_000)
    h.fetch.mockClear()
    expect(await worker.logout()).toEqual(signedOut)
    expect(h.fetch).toHaveBeenCalledOnce()
    expect(fields(h.fetch.mock.calls[0][1])).toEqual({ client_id: config.clientId, token_type_hint: 'refresh_token', token: 'refresh-1' })
    expect(await h.create().restore()).toEqual(signedOut)
  })

  it('Given 撤销请求断网 / When 退出 / Then 清本地并报告远端未确认', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    h.fetch.mockRejectedValueOnce(new Error('private message'))
    await expect(worker.logout()).rejects.toMatchObject({ code: 'revocation_unconfirmed' })
    expect(await worker.restore()).toEqual(signedOut)
  })

  it('Given 资源返回禁止或无效证明 / When 请求结束 / Then 保留仍然有效的会话', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    for (const [status, code] of [[403, 'insufficient_scope'], [401, 'invalid_dpop_proof']] as const) {
      h.fetch.mockResolvedValueOnce(jsonResponse({ error: { code } }, status))
      expect((await worker.authorizedFetch(business)).status).toBe(status)
      expect(await worker.restore()).toMatchObject({ status: 'authenticated' })
    }
  })

  it('Given 远端撤销 / When 后台验证或业务请求 / Then 返回退出态并通知页面', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    const publish = vi.fn()
    worker.onSessionChange(publish)
    h.fetch.mockResolvedValueOnce(jsonResponse({ error: { code: 'invalid_token' } }, 401))
    expect((await worker.authorizedFetch(business)).status).toBe(401)
    expect(publish).toHaveBeenCalledExactlyOnceWith(signedOut)
    expect(await worker.restore()).toEqual(signedOut)
  })

  it('Given 资源输入 / When 地址或头超出授权范围 / Then 在读取存储前拒绝', async () => {
    const h = harness()
    const worker = h.create()
    const read = vi.spyOn(SessionRepository.prototype, 'read')
    for (const address of [config.authOrigin + '/oauth/token', config.apiOrigin + '/oauth/token',
      config.apiOrigin + '/v10/path', business + '/%252f', business + '/..%2Fadmin', business + '/%2e%2e']) {
      await expect(worker.authorizedFetch(address)).rejects.toMatchObject({ code: 'request_not_allowed' })
    }
    for (const name of ['Authorization', 'DPoP']) {
      await expect(worker.authorizedFetch(business, { headers: { [name]: 'caller' } })).rejects.toMatchObject({ code: 'request_not_allowed' })
    }
    expect(read).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('Given 共享链接对象与 Request / When 调用后地址变化 / Then 只向已校验的目标发送', async () => {
    const h = harness()
    const worker = h.create()
    await worker.login()
    const url = new URL(business)
    const operation = worker.authorizedFetch(url)
    url.hostname = 'outside.test'
    await operation
    expect(h.fetch.mock.calls.at(-1)?.[0]).toBe(business)
    const request = new Request(config.authOrigin + '/oauth/token')
    Object.defineProperty(request, 'url', { value: business })
    await expect(worker.authorizedFetch(request)).rejects.toMatchObject({ code: 'request_not_allowed' })
  })

  it.each(['cancel', 'invalid', 'exception'])('Given %s 登录交互 / When 提示失败 / Then 错误可安全返回', async (mode) => {
    const h = harness()
    h.launch.mockImplementationOnce(async () => {
      if (mode === 'invalid') return config.redirectUri + '?code=private'
      throw new Error(mode === 'cancel' ? 'User rejected the request.' : 'private')
    })
    const error = await h.create().login().catch((reason: unknown) => reason)
    expect(error).toBeInstanceOf(AppAuthorizationError)
    expect(String(error)).not.toContain('private')
    expect(h.fetch).not.toHaveBeenCalled()
  })

  it('Given 登录提示未完成 / When 退出后旧回调到达 / Then 不换码也不恢复授权', async () => {
    const h = harness()
    let release!: (url: string) => void
    h.launch.mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
    const worker = h.create()
    const login = expect(worker.login()).rejects.toMatchObject({ code: 'interaction_cancelled' })
    await vi.waitFor(() => expect(h.launch).toHaveBeenCalledOnce())
    await worker.logout()
    release(callbackFor(h.launch.mock.calls[0][0]))
    await login
    expect(h.fetch).not.toHaveBeenCalled()
  })
})
