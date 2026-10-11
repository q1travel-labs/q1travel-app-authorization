# App Authorization

## 项目边界

- API V2 JSON fixture 是只读契约权威；上游变更须原样复制，记录的 SHA-256 只能依据已评审 API 证据更新。
- `src/core` 保持平台无关、消费方中立，运行时能力通过显式 ports 注入。core 改动以聚焦 conformance 测试与包 typecheck 验收。
- Token 仅在后台内存与 `chrome.storage.session`；初始化设置 `TRUSTED_CONTEXTS`。扩展自有页与 service worker 属同一信任域；content scripts、网页、SDK UI 消息只接收无 token 元数据/稳定错误。业务消息白名单与授权清理由应用后台负责。
- 保留 identity 与 adjacent-tab 两种公开授权入口及现有 exports；`src/core`/extension 不依赖可选 React。React gate 无 UI 风格与业务文案，消费方拥有展示与登录动作。
- 授权码单次交换、PKCE S256、精确 callback origin/path/state 校验，固定八小时会话无 refresh token；`authorizedFetch` 仅允许配置的 API origin、拒绝调用者 Authorization、`credentials: 'omit'`。
- adjacent-tab 改动读 `packages/app-authorization/README.md` 对应章节：worker 顶层同步注册、受信回调封闭消息、持久事务认领不重放、只关闭记录且 opener 匹配的授权 tab；浏览器回调/worker 重启/位置焦点须单独真实浏览器验收，单测或打包不代表该验收。

## 工具与依赖

使用根 `packageManager` 的 `pnpm@11.13.1`、开发 Node ≥ 24.5；包消费运行时最低 Node 22。保留 pnpm workspace/锁文件；React 为可选 peer（18.2 或 19）。根 `pnpm typecheck` 为 `tsc --noEmit`，本机定向测试如 `pnpm exec vitest run packages/app-authorization/test/facade.test.ts`；`build-boundaries.test.ts` 会调用构建，须卸载。无 lint 脚本（N/A）。全量 `pnpm build`、`pnpm test` 及 `pnpm check:pack` 按下方卸载规则执行，打包输出与公开入口以包 `package.json` 为准。

## 算力卸载（devmini-01，动态调度）

所有者 2026-10-12 定：不再一刀切禁止本机，按任务轻重动态调度。

**1. 轻重分级**
- 轻量任务一律本机直接跑，不 rsync：单文件测试、单个 describe/it、`tsc --noEmit`、lint。例：`pnpm vitest run <文件>  /  pnpm tsc --noEmit`。
- 重型任务优先卸载到 `devmini-01`：全量 `test`、全套 e2e、Docker 相关，以及任何预计超过 30 秒的批处理。

**2. 远端执行（在当前 worktree 根目录；沙箱目录必须带分支后缀，禁止多任务写同一目录）**

```sh
BR=$(git branch --show-current | tr '/' '-')
rsync -az --delete --exclude node_modules --exclude .git --exclude dist --exclude .next --exclude .worktrees --exclude .local ./ devmini-01:~/offload/q1travel-app-authorization-$BR/
ssh -o ConnectTimeout=8 -o BatchMode=yes devmini-01 'export PATH=/opt/homebrew/bin:$PATH; cd ~/offload/q1travel-app-authorization-'$BR' && pnpm install --frozen-lockfile --prefer-offline && pnpm test'
```

mini 上 Node/pnpm 在 `/opt/homebrew/bin`，非交互 SSH 不在 PATH，必须显式导出。

**3. 执行前探测与降级（每次重型任务前必做）**

```sh
ssh -o ConnectTimeout=8 -o BatchMode=yes devmini-01 'uptime | sed "s/.*load averages*: *//"; pgrep -fl "vitest|vite build|tsc|pnpm|npm (run|test|ci)" | grep -v pgrep | wc -l'
```

- SSH 超时/拒绝、1 分钟负载 ≥ 8（mini 为 8 核）、或已有其他重型进程在跑：自动降级为本机只跑受影响改动的定向单测 + lint/typecheck，不得本机跑全量；若任务必须全量，先询问所有者再排队。
- 降级与原因写进汇报。结果以 mini 回显为准，附退出码与关键输出；最终门禁仍以 GitHub CI 为准。
- 任务结束后不必删沙箱，但同一分支再次执行会被 `--delete` 覆盖，属预期。
