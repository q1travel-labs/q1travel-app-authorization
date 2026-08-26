import { copyFileSync, mkdirSync, rmSync } from 'node:fs'

const internalDeclarationDirectories = [
  'dist/background-runtime',
  'dist/chrome-adapter',
  'dist/core',
]

const clean = () => {
  rmSync('dist', { recursive: true, force: true })
  rmSync('.testing-build', { recursive: true, force: true })
  rmSync('testing/index.js', { force: true })
  rmSync('testing/index.d.ts', { force: true })
}

const finalize = () => {
  for (const directory of internalDeclarationDirectories) {
    for (const file of [
      'authorizationCoordinator.d.ts',
      'runtime.d.ts',
      'externalCallback.d.ts',
      'listenerInstaller.d.ts',
      'ports.d.ts',
      'sessionRepository.d.ts',
      'tabCoordinator.d.ts',
      'callback.d.ts',
      'contracts.d.ts',
      'pkce.d.ts',
      'reconcile.d.ts',
    ]) {
      rmSync(`${directory}/${file}`, { force: true })
    }
  }

  mkdirSync('testing', { recursive: true })
  copyFileSync('.testing-build/index.js', 'testing/index.js')
  copyFileSync('.testing-build/index.d.ts', 'testing/index.d.ts')
  rmSync('.testing-build', { recursive: true, force: true })
}

const command = process.argv[2]

if (command === 'clean') {
  clean()
} else if (command === 'finalize') {
  finalize()
} else {
  throw new TypeError('Expected the build staging command clean or finalize.')
}
