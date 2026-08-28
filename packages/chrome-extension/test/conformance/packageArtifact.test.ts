import { describe, expect, it } from 'vitest'

// @ts-expect-error The package deliberately has no Node runtime dependency.
import { execFileSync } from 'node:child_process'
// @ts-expect-error The package deliberately has no Node runtime dependency.
import { existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs'
// @ts-expect-error The package deliberately has no Node runtime dependency.
import { tmpdir } from 'node:os'
// @ts-expect-error The package deliberately has no Node runtime dependency.
import { dirname, join, posix, resolve } from 'node:path'

interface PackEntry {
  filename: string
  files: Array<{ path: string }>
  name: string
  version: string
}

interface DirectoryEntry {
  isDirectory(): boolean
  name: string
}

const packageRoot = resolve(
  decodeURIComponent(new URL('.', import.meta.url).pathname),
  '../..',
)

const expectedManifest = [
  'package/CHANGELOG.md',
  'package/README.md',
  'package/dist/background-runtime/authorizationCoordinator.js',
  'package/dist/background-runtime/runtime.js',
  'package/dist/chrome-adapter/externalCallback.js',
  'package/dist/chrome-adapter/listenerInstaller.js',
  'package/dist/chrome-adapter/ports.js',
  'package/dist/chrome-adapter/sessionRepository.js',
  'package/dist/chrome-adapter/tabCoordinator.js',
  'package/dist/core/callback.js',
  'package/dist/core/contracts.js',
  'package/dist/core/pkce.js',
  'package/dist/core/reconcile.js',
  'package/dist/index.d.ts',
  'package/dist/index.js',
  'package/dist/public-runtime/backgroundOnly.d.ts',
  'package/dist/public-runtime/backgroundOnly.js',
  'package/dist/public-runtime/runtime.d.ts',
  'package/dist/public-runtime/runtime.js',
  'package/dist/publicTypes.d.ts',
  'package/dist/publicTypes.js',
  'package/dist/ui-facade/data.d.ts',
  'package/dist/ui-facade/data.js',
  'package/dist/ui-facade/facade.d.ts',
  'package/dist/ui-facade/facade.js',
  'package/dist/ui-facade/operationCatalog.d.ts',
  'package/dist/ui-facade/operationCatalog.js',
  'package/dist/ui-facade/protocol.d.ts',
  'package/dist/ui-facade/protocol.js',
  'package/package.json',
  'package/testing/index.d.ts',
  'package/testing/index.js',
].sort()

const walkFiles = (root: string, directory = root): string[] =>
  (readdirSync(directory, { withFileTypes: true }) as DirectoryEntry[]).flatMap((entry) => {
    const absolute = join(directory, entry.name)
    return entry.isDirectory()
      ? walkFiles(root, absolute)
      : [absolute.slice(root.length + 1).split('\\').join('/')]
  })

describe('0.1.1 package candidate', () => {
  it('builds, packs, extracts and executes one exact isolated candidate', () => {
    const temporaryRoot = mkdtempSync(join(tmpdir(), 'q1travel-auth-package-'))
    try {
      execFileSync(
        'npm',
        ['exec', '--yes', 'pnpm@11.13.1', '--', 'run', 'build'],
        { cwd: packageRoot, stdio: 'pipe' },
      )
      const packOutput = execFileSync(
        'npm',
        ['pack', '--json', '--pack-destination', temporaryRoot],
        {
          cwd: packageRoot,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      const [candidate] = JSON.parse(packOutput) as PackEntry[]
      expect({ name: candidate.name, version: candidate.version }).toEqual({
        name: '@q1travel/app-authorization-chrome-extension',
        version: '0.1.1',
      })

      const tarball = join(temporaryRoot, candidate.filename)
      const listed: string[] = execFileSync('tar', ['-tzf', tarball], {
        encoding: 'utf8',
      }).trim().split('\n').filter(Boolean).sort()
      expect(listed).toEqual(expectedManifest)
      expect(listed.every((entry) =>
        entry.startsWith('package/') &&
        posix.normalize(entry) === entry &&
        !entry.includes('../') &&
        !entry.startsWith('/'),
      )).toBe(true)

      const verbose: string[] = execFileSync('tar', ['-tvzf', tarball], {
        encoding: 'utf8',
      }).trim().split('\n').filter(Boolean)
      expect(verbose.every((entry) => entry.startsWith('-'))).toBe(true)

      const extracted = join(temporaryRoot, 'extracted')
      mkdirSync(extracted)
      execFileSync('tar', ['-xzf', tarball, '-C', extracted])
      const extractedPackage = join(extracted, 'package')
      expect(
        walkFiles(extracted).map((entry) => entry).sort(),
      ).toEqual(expectedManifest)
      for (const entry of expectedManifest) {
        expect(lstatSync(join(extracted, entry)).isFile()).toBe(true)
      }

      const declarationSecret =
        /\b(?:accessToken|authorizationCode|codeVerifier|bearer|state|verifier)\s*[?:]/i
      const forbiddenCoordinatorSurface =
        /handleExternalCallback|callbackRejected|connectionFailed/
      const fixtureOrConsumer =
        /ozon|localhost|127\.0\.0\.1|example\.test|AAECAwQF|ICEiIyQl|Bearer private|private-token/i
      for (const entry of expectedManifest) {
        const bytes = readFileSync(join(extracted, entry))
        expect(bytes.includes(0)).toBe(false)
        const text = bytes.toString('utf8')
        expect(text).not.toMatch(/sourceMappingURL|sourcesContent|\/test\/|fixture/i)
        expect(text).not.toMatch(fixtureOrConsumer)
        if (entry.endsWith('.d.ts')) {
          expect(text).not.toMatch(forbiddenCoordinatorSurface)
        }
      }

      for (const uiDeclaration of [
        'package/dist/publicTypes.d.ts',
        'package/dist/ui-facade/data.d.ts',
        'package/dist/ui-facade/facade.d.ts',
        'package/dist/ui-facade/operationCatalog.d.ts',
      ]) {
        expect(readFileSync(join(extracted, uiDeclaration), 'utf8'))
          .not.toMatch(declarationSecret)
      }

      for (const entry of expectedManifest.filter((path) =>
        path.endsWith('.js'))) {
        const absolute = join(extracted, entry)
        const source = readFileSync(absolute, 'utf8')
        const relativeImports = [...source.matchAll(
          /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(['"])(\.{1,2}\/[^'"]+)\1/g,
        )].map((match) => match[2])
        for (const specifier of relativeImports) {
          const target = resolve(dirname(absolute), specifier)
          expect(existsSync(target) && lstatSync(target).isFile(),
            `${entry} has unresolved relative import ${specifier}`).toBe(true)
        }
      }

      for (const internalEntry of [
        'dist/background-runtime/runtime.js',
        'dist/background-runtime/authorizationCoordinator.js',
      ]) {
        execFileSync(
          'node',
          [
            '--input-type=module',
            '--eval',
            "const { pathToFileURL } = await import('node:url'); await import(pathToFileURL(process.argv[1]).href)",
            join(extractedPackage, internalEntry),
          ],
          { stdio: ['ignore', 'pipe', 'pipe'] },
        )
      }

      const productionExports = execFileSync(
        'node',
        [
          '--input-type=module',
          '--eval',
          "import * as sdk from '@q1travel/app-authorization-chrome-extension'; process.stdout.write(JSON.stringify(Object.keys(sdk).sort()))",
        ],
        {
          cwd: extractedPackage,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      expect(productionExports).toBe(
        '["createChromeAppAuthorizationRuntime","createChromeAppAuthorizationUiFacade","defineChromeAppAuthorizationOperations","prepareAuthorization"]',
      )
      const extractedComposition = execFileSync(
        'node',
        [
          '--input-type=module',
          '--eval',
          `
            import {
              createChromeAppAuthorizationRuntime,
              defineChromeAppAuthorizationOperations,
            } from '@q1travel/app-authorization-chrome-extension'
            const snapshot = {
              profile: null,
              runtime: 'ready',
              authorization: { kind: 'signed-out', reason: 'never-authorized' },
              interaction: { phase: 'idle' },
            }
            const catalog = defineChromeAppAuthorizationOperations({
              'probe.ready': {
                allowedCallers: ['popup'],
                input: { type: 'null' },
                output: { type: 'boolean' },
              },
            })
            const internalListeners = []
            const session = new Map()
            let currentSnapshot = structuredClone(snapshot)
            const runtime = createChromeAppAuthorizationRuntime({
              background: {
                chrome: {
                  storage: { session: {
                    async setAccessLevel() {},
                    async get(key) { return session.has(key) ? { [key]: session.get(key) } : {} },
                    async set(values) { for (const [key, value] of Object.entries(values)) session.set(key, value) },
                    async remove(key) { session.delete(key) },
                  } },
                  runtime: {
                    id: 'abcdefghijklmnopabcdefghijklmnop',
                    getURL(path) { return 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/' + path },
                    onMessage: { addListener(listener) { internalListeners.push(listener) } },
                    onMessageExternal: { addListener() {} },
                  },
                  tabs: {
                    async create() { return { id: 7, windowId: 3, active: true } },
                    async update(_id, input) { return { id: 7, windowId: 3, ...input } },
                    async get() { return { id: 7, windowId: 3, active: false } },
                    async remove() {},
                    onRemoved: { addListener() {} },
                  },
                  windows: {
                    async get() { return { id: 3, focused: false } },
                    async update() { return { id: 3, focused: true } },
                  },
                  alarms: {
                    async create() {},
                    async clear() { return true },
                    onAlarm: { addListener() {} },
                  },
                },
                crypto: {
                  randomBytes() { return new Uint8Array(32) },
                  async sha256() { return new Uint8Array(32) },
                  timingSafeEqual(left, right) { return left === right },
                },
                state: {
                  async readSnapshot() { return structuredClone(currentSnapshot) },
                  async saveSnapshot(value) { currentSnapshot = structuredClone(value) },
                  async readGrant() { return null },
                  async saveGrant() {},
                },
                profile: {
                  callbackOrigin: 'https://web.example.test',
                  callbackPath: '/apps/extension-auth/callback/client-v2',
                  now() { return Date.parse('2026-08-26T04:00:00.000Z') },
                  async beginAuthorization() { return {
                    transactionId: 'transaction-id',
                    clientId: 'browser-client-v2',
                    redirectUri: 'https://web.example.test/apps/extension-auth/callback/client-v2',
                    prepared: {
                      state: 's'.repeat(43),
                      codeVerifier: 'v'.repeat(43),
                      authorizeUrl: 'https://accounts.example.test/app-authorizations/v1/authorize',
                    },
                    sourceTabId: 5,
                    sourceWindowId: 3,
                  } },
                  async authorizationUrl() { return 'https://accounts.example.test/app-authorizations/v1/authorize' },
                  async exchange() { return {
                    accessToken: 'background-only-token',
                    expiresAt: '2026-08-26T05:00:00.000Z',
                    sessionRevision: 'revision-1',
                  } },
                },
              },
              configure: { async configure() { return { ok: true, value: snapshot } } },
              termination: {
                async logout() { return { ok: true, value: { snapshot, cleanup: 'complete' } } },
                async revoke() { return { ok: true, value: { snapshot, cleanup: 'complete' } } },
              },
              operationExecutor: { async execute() { return { ok: true, value: true } } },
              catalog,
              senderPolicy: {
                expectedExtensionId: 'abcdefghijklmnopabcdefghijklmnop',
                entryPaths: {
                  popup: '/popup.html',
                  options: '/options.html',
                  'side-panel': '/side-panel.html',
                },
                managementCallers: ['popup'],
              },
            })
            const started = await runtime.start()
            const status = await runtime.status()
            const login = await runtime.login()
            process.stdout.write(JSON.stringify({
              listeners: internalListeners.length,
              started: started.ok,
              status: status.ok,
              loginPhase: login.ok ? login.value.interaction.phase : null,
            }))
          `,
        ],
        {
          cwd: extractedPackage,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      expect(JSON.parse(extractedComposition)).toEqual({
        listeners: 2,
        started: true,
        status: true,
        loginPhase: 'authorizing',
      })
      const testingExports = execFileSync(
        'node',
        [
          '--input-type=module',
          '--eval',
          "import * as testing from '@q1travel/app-authorization-chrome-extension/testing'; process.stdout.write(JSON.stringify(Object.keys(testing).sort()))",
        ],
        {
          cwd: extractedPackage,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      expect(testingExports).toBe(
        '["assertChromeAppAuthorizationConsumerConformance"]',
      )
      const deepImport = execFileSync(
        'node',
        [
          '--input-type=module',
          '--eval',
          "try { await import('@q1travel/app-authorization-chrome-extension/dist/core/callback.js') } catch (error) { process.stdout.write(String(error.code)) }",
        ],
        {
          cwd: extractedPackage,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      )
      expect(deepImport).toBe('ERR_PACKAGE_PATH_NOT_EXPORTED')

      const dryRunOutput = execFileSync('npm', ['pack', '--dry-run', '--json'], {
        cwd: packageRoot,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      const [dryRun] = JSON.parse(dryRunOutput) as PackEntry[]
      expect({ name: dryRun.name, version: dryRun.version }).toEqual({
        name: candidate.name,
        version: candidate.version,
      })
      expect(dryRun.files.map(({ path }) => `package/${path}`).sort()).toEqual(
        expectedManifest,
      )

      const packageJson = JSON.parse(
        readFileSync(join(extractedPackage, 'package.json'), 'utf8'),
      ) as {
        engines?: { node?: string }
        exports?: Record<string, { import?: string; types?: string }>
      }
      expect(packageJson.engines).toEqual({ node: '>=24.5.0' })
      expect(packageJson.exports).toEqual({
        '.': { types: './dist/index.d.ts', import: './dist/index.js' },
        './testing': {
          types: './testing/index.d.ts',
          import: './testing/index.js',
        },
      })
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true })
    }
  })
})
