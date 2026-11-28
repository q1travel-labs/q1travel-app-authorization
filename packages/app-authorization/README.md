# @q1travel/app-authorization

0.5.0 为 Chrome MV3 扩展提供 OAuth 授权码登录、PKCE S256 和 REST DPoP。包发布后，四个扩展固定使用同一版本。

```sh
pnpm add --save-exact @q1travel/app-authorization@0.5.0
```

## 后台装配

在 service worker 模块顶层创建一次 runtime。价格指数通过 Chrome 自有回调登录。

```ts
import { createAuthRuntime } from '@q1travel/app-authorization/extension/background'

export const auth = createAuthRuntime({
  installationId: 'iijaknjejahomefhkamjojfjoallpcdl',
  clientId: 'q1travel-price-index-v1',
  redirectUri: 'https://iijaknjejahomefhkamjojfjoallpcdl.chromiumapp.org/q1travel-price-index-v1',
  scopes: [],
  authOrigin: 'https://connect.q1lx.com',
  apiOrigin: 'https://api.q1lx.com',
})
```

`installationId` 取与分发公钥对应的登记值，启动时逐字比对 `chrome.runtime.id`。登记的 Chromium 回调必须属于该安装 ID。配置清单的 `identity` 权限、两个主机的 `host_permissions` 及相应的 CSP `connect-src`。构建配置选择环境的 HTTP 入口。OAuth 的登记 issuer 为 `https://connect.q1lx.com`，REST resource 为 `https://api.q1lx.com/v1`。开发环境如启用 HTTP，仅允许显式 `allowInsecureLoopback: true` 的本机地址。DPoP 的 `htu` 取实际请求的外部地址，网关验签须使用同一地址。

| 应用 | clientId | 身份与权限 |
| --- | --- | --- |
| Ozon 管理器 | `q1travel-ozon-manager-store-v1` | 安装 ID `pgehlkfmmgcnlibpfmjbedeollciifmj`，登记的 dashboard 回调，`ozon_store_bindings:read`，严格核对当前店铺 |
| 价格指数 | `q1travel-price-index-v1` | 上例回调，空业务 scope，店铺准入 |
| AliExpress 管理器 | `q1travel-aliexpress-manager-v2` | 安装 ID `hdgkeopenjhfbjomggpelamjbfcllbpm`，登记的 dashboard 回调，空业务 scope，店铺成员准入 |
| 工作台 | `q1travel-workbench` | 使用所有者确认的固定安装 ID 与逐字回调，空业务 scope，组织准入 |

## 冻结的页面与后台接口

弹窗、侧栏、选项页通过 `createAuthFacade()` 发送业务消息。下面五个无参方法均返回 `Promise<AuthSession>`。

| 方法 | 调用效果 |
| --- | --- |
| `login()` | 发起交互授权。校验回调并换码后，用新 AT 回读身份，持久化成功才返回已登录 |
| `restore()` | 恢复已落盘的身份状态。AT 到期时协调一次刷新。没有可用会话时返回退出态 |
| `refresh()` | 主动轮换本代令牌。并发等待者取得同一份已提交状态 |
| `logout()` | 提交当前 RT 和 `token_type_hint=refresh_token` 撤整族，清本地会话并通知页面。远端无法确认时抛出 `revocation_unconfirmed` |
| `getIdentity()` | 调用 `GET /v1/identity` 复核身份。无会话或服务端确认令牌失效时返回退出态；网络故障通过异常返回 |

```ts
import { createAuthFacade } from '@q1travel/app-authorization/extension/ui'

const auth = createAuthFacade()
const session = await auth.getIdentity()
if (session.status === 'authenticated') {
  const { user, organization, scopes, store_ids } = session.identity
}
const unsubscribe = auth.onSessionChange(renderSession)
```

`AuthSession` 为 `{ status: 'signed-out' }` 或 `{ status: 'authenticated', expiresAt, identity }`。`expiresAt` 为从实际 `expires_in` 计算的 UTC ISO 时间。委托身份只含 `object: 'identity'`、`principal_type: 'user'`、`user`、`organization`、`scopes`、`store_ids`。未限店时 `store_ids` 为 null。React 入口可选用 `AuthGate` 或 `useAuthSession`，`client` 传入同一 facade。

后台另有 `ready()` 和 `authorizedFetch(input, init?)`。`ready()` 等待本次 worker 启动时的身份复核，网络故障可用 `restore()` 读取仍有效的本地状态。`authorizedFetch` 仅向配置的 API 主机 `/v1/` 资源发送请求，保持请求方法和正文，每次新签证明，省略 Cookie 并拒绝跟随重定向。调用者传入 Authorization 或 DPoP 头会得到 `request_not_allowed`。HTTP 业务响应交给调用方处理。

## 相邻页签与严格店铺

Ozon 和 AliExpress 在 SW 顶层改用 `createAdjacentTabAuthRuntime(config, { chrome, getSourceTab, authorizationContextPort? })`。其 `redirectUri` 为 `https://dashboard.q1lx.com/oauth-callback.html`。声明对应回调来源的 `externally_connectable.matches`、`alarms` 与 `storage` 权限，并向 runtime 提供所需的标签页和窗口 API。由应用的 `getSourceTab(source?)` 一次确定原始业务页签。有 `source.tabId` 时须返回该精确页签。SDK 只将待完成的 PKCE 交易和页签归属放入受信的 `chrome.storage.session`。

E 线的桥接页按发起页签中的一次性 state、client 和安装 ID 选择目标。发送调用与消息格式如下，`callbackUrl` 为地址栏里的完整绝对地址，保留服务端返回的 state 和 iss。

```js
chrome.runtime.sendMessage(extensionId, {
  type: 'q1travel.appAuthorization.callback.v1',
  clientId, extensionId, callbackUrl,
})
```

SDK 校验目标 client / 安装 ID、Chrome 提供的 sender、顶层窗口、精确回调来源与地址、授权页签及 opener、交易有效期、state 和 issuer。换码前先持久化“已领用”。成功回执为 `{ ok: true }`；已领用等交易错误返回 `{ ok: false, error }`。来源或消息形状不可信时忽略该消息。

严格店铺应用实现 `AuthorizationContextPort.prepare({ contextsUrl, clientId, redirectUri, state, codeChallenge, sourceTabId })`。读取原页签的当前 Ozon client ID，向 `POST /oauth/contexts` 发 JSON，字段为 `kind: 'ozon-client-id-v1'`、`observed_client_id`、`client_id`、`redirect_uri`、`state`、`code_challenge`。响应字段为 `authorization_context` 和 Unix 秒 `expires_at`，向 SDK 返回 `{ token: authorization_context }`。`assertCurrent({ token, phase })` 在 `beforeExchange` 和 `beforeSessionCommit` 复核原始观测。登录后，后台通过 `authorizedFetch(apiOrigin + '/v1/store_contexts/current')` 核对 `state === 'matched'` 且 `identity.id` 与当前浏览器观测相同，才开放原业务功能。

## 刷新、错误和存储

每次授权生成不可导出的 P-256 私钥。后台在扩展来源的 IndexedDB 中用一条记录存储密钥、AT、RT、版本、有效期和公开身份。只有后台入口实现存取、签名和刷新。同一扩展源的特权页面属于信任边界。网页和内容脚本处于网页来源。应用的内容脚本只通过校验过的具体业务消息调用后台。

签名采用 ES256，`htu` 省略查询与片段，每次请求使用新 `jti`。访问资源时带 AT 的 SHA-256 摘要 `ath`。授权服务器和资源服务器分别记录 nonce。收到本端 `use_dpop_nonce` 与新 nonce 后，仅用原参数重签一次。

后台按会话版本合并刷新，并持有 `navigator.locks` 独占锁。锁内重读持久化版本，先写入不含旧 RT 的领用标记，再出网，最后原子提交新 AT、RT 与到期时间。进程中断、密钥丢失、结果不明或新 RT 无法落盘时，后续调用须重新授权。

错误通过 `AppAuthorizationError` 暴露 `code`、固定 `message` 和 `retryable`。完整冻结夹具随包提供，路径为 `@q1travel/app-authorization/fixtures/errors.json`，以错误码为键。连续 nonce 挑战返回 `use_dpop_nonce`。刷新结果不明或新 RT 落盘失败返回 `reauthorization_required`。服务端明确拒绝已失效或重放的 RT 返回 `oauth_invalid_grant`。发生以上刷新错误后，页面从交互登录开始恢复。

0.4.x 的会话随平台切换失效，使用者更新扩展后重新登录。
