import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const expected = new Set([
  'CHANGELOG.md',
  'README.md',
  'dist/core/callback.d.ts',
  'dist/core/callback.js',
  'dist/core/config.d.ts',
  'dist/core/config.js',
  'dist/core/pkce.d.ts',
  'dist/core/pkce.js',
  'dist/core/types.d.ts',
  'dist/core/types.js',
  'dist/extension/background.d.ts',
  'dist/extension/background.js',
  'dist/extension/facade.d.ts',
  'dist/extension/facade.js',
  'dist/extension/http.d.ts',
  'dist/extension/http.js',
  'dist/extension/listener.d.ts',
  'dist/extension/listener.js',
  'dist/extension/ports.d.ts',
  'dist/extension/ports.js',
  'dist/extension/protocol.d.ts',
  'dist/extension/protocol.js',
  'dist/extension/runtime.d.ts',
  'dist/extension/runtime.js',
  'dist/extension/sender.d.ts',
  'dist/extension/sender.js',
  'dist/extension/storage.d.ts',
  'dist/extension/storage.js',
  'dist/extension/tabAuthPorts.d.ts',
  'dist/extension/tabAuthPorts.js',
  'dist/extension/tabAuthRuntime.d.ts',
  'dist/extension/tabAuthRuntime.js',
  'dist/extension/ui.d.ts',
  'dist/extension/ui.js',
  'dist/index.d.ts',
  'dist/index.js',
  'dist/react/index.d.ts',
  'dist/react/index.js',
  'package.json',
])

const tarball = process.argv[2]
const files = tarball
  ? execFileSync('tar', ['-tzf', resolve(tarball)], { encoding: 'utf8' })
      .trim()
      .split('\n')
      .filter((file) => file.startsWith('package/') && !file.endsWith('/'))
      .map((file) => file.slice('package/'.length))
  : JSON.parse(
      execFileSync('npm', ['pack', '--dry-run', '--json'], {
        encoding: 'utf8',
        env: {
          ...process.env,
          npm_config_cache:
            process.env.NPM_CONFIG_CACHE ?? '/tmp/q1travel-app-authorization-npm-cache',
        },
      }),
    )[0]?.files?.map((entry) => entry.path)
if (!Array.isArray(files)) throw new Error('npm pack did not return a file list.')

const actual = new Set(files)
const unexpected = files.filter((file) => !expected.has(file))
const missing = [...expected].filter((file) => !actual.has(file))
if (unexpected.length > 0 || missing.length > 0) {
  throw new Error(
    `Package contents differ. Unexpected: ${unexpected.join(', ') || 'none'}. Missing: ${missing.join(', ') || 'none'}.`,
  )
}

if (tarball) {
  const directory = mkdtempSync(join(tmpdir(), 'q1travel-app-authorization-'))
  try {
    execFileSync('tar', ['-xzf', resolve(tarball), '-C', directory])
    const root = await import(pathToFileURL(join(directory, 'package/dist/index.js')).href)
    const background = await import(
      pathToFileURL(join(directory, 'package/dist/extension/background.js')).href
    )
    const ui = await import(
      pathToFileURL(join(directory, 'package/dist/extension/ui.js')).href
    )
    if (
      typeof root.AppAuthorizationError !== 'function' ||
      typeof background.createAuthRuntime !== 'function' ||
      typeof background.createAdjacentTabAuthRuntime !== 'function' ||
      background.TAB_AUTH_CALLBACK !== 'q1travel.appAuthorization.callback.v1' ||
      typeof ui.createAuthFacade !== 'function'
    ) {
      throw new Error('Published entry points do not expose the required API.')
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

process.stdout.write(`${files.sort().join('\n')}\n`)
