// Token budget guards: the two things this plugin adds to every model request
// must stay small, and the prompt section must honour the live toggle.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { PROMPT_SECTION, buildTool } from '../lib/index.js'
import { Store } from '../lib/store.js'

test('global rule stays tiny (<= 80 chars)', () => {
  assert.ok(PROMPT_SECTION.length <= 80, `PROMPT_SECTION is ${PROMPT_SECTION.length} chars`)
})

test('tool schema stays under budget (<= 820 chars)', () => {
  const tool = buildTool({})
  const json = JSON.stringify(tool)
  assert.ok(json.length <= 820, `tool schema is ${json.length} chars`)
  assert.deepEqual(tool.parameters.required, ['action'])
  assert.equal(tool.parameters.additionalProperties, false)
})

test('injectPrompt=false is visible to settingsSync without restart', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'safety-budget-'))
  try {
    const dir = path.join(home, 'agent-safety')
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ injectPrompt: false }), 'utf8')
    const store = new Store(home)
    assert.equal(store.settingsSync().injectPrompt, false)
    writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ injectPrompt: true, maxSessions: 7 }), 'utf8')
    const next = store.settingsSync()
    assert.equal(next.injectPrompt, true)
    assert.equal(next.maxSessions, 7)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})

test('missing settings file falls back to the defaults', () => {
  const home = mkdtempSync(path.join(tmpdir(), 'safety-budget-'))
  try {
    const store = new Store(home)
    assert.equal(store.settingsSync().injectPrompt, true)
  } finally {
    rmSync(home, { recursive: true, force: true })
  }
})
