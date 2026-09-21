import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const packageDirectory = resolve(import.meta.dirname, '..')

const readModuleGraph = (entry: string): string => {
  const visited = new Set<string>()
  const visit = (file: string): string => {
    if (visited.has(file)) return ''
    visited.add(file)
    const source = readFileSync(file, 'utf8')
    const dependencies = [...source.matchAll(/(?:from\s*|import\s*)['"](\.[^'"]+)['"]/gu)]
      .map((match) => resolve(dirname(file), match[1]))
    return [source, ...dependencies.map(visit)].join('\n')
  }
  return visit(resolve(packageDirectory, entry))
}

describe('published entry boundaries', () => {
  it('keeps background-only implementation out of the UI and React module graphs', () => {
    execFileSync('pnpm', ['build'], { cwd: packageDirectory, stdio: 'pipe' })

    for (const entry of ['dist/extension/ui.js', 'dist/react/index.js']) {
      const output = readModuleGraph(entry)
      expect(output, entry).not.toContain('q1travel.appAuthorization.session.v1')
      expect(output, entry).not.toContain('q1travel.appAuthorization.transaction.v1')
      expect(output, entry).not.toContain('authorizedFetch')
      expect(output, entry).not.toContain('/token')
    }
  })

  it('publishes separate background and UI subpaths without the former combined entry', () => {
    const manifest = JSON.parse(readFileSync(resolve(packageDirectory, 'package.json'), 'utf8'))
    expect(manifest.exports['./extension/background']).toBeDefined()
    expect(manifest.exports['./extension/ui']).toBeDefined()
    expect(manifest.exports['./extension']).toBeUndefined()
  })
})
