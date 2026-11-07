// apply() smoke: the prompt section must resolve its text per call so the
// toggle works without a restart, and an empty string must be returned when off.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

import { apply, PROMPT_SECTION } from '../lib/index.js'

function fakeCtx(capture) {
  const ctx = {
    logger: { info() {}, error() {}, warn() {} },
    get: () => undefined,
    inject(names, run) {
      const scope = {
        effect(fn) { return fn() },
        tools: { register() {} },
        systemPrompt: { section(config) { capture.section = config } },
        webServer: { register() { return () => {} } },
      }
      run(scope)
    },
    effect(fn) { return fn() },
  }
  return ctx
}

test('prompt section text follows the setting live', async () => {
  const home = mkdtempSync(path.join(tmpdir(), 'safety-apply-'))
  const dir = path.join(home, 'agent-safety')
  mkdirSync(dir, { recursive: true })
  writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ injectPrompt: true }), 'utf8')
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const capture = {}
    apply(fakeCtx(capture), {})
    assert.ok(capture.section, 'systemPrompt.section was registered')
    assert.equal(typeof capture.section.text, 'function', 'text must be a function')
    assert.equal(capture.section.text({}), PROMPT_SECTION)

    // flip the switch in the file: the same callback must now return nothing
    writeFileSync(path.join(dir, 'settings.json'), JSON.stringify({ injectPrompt: false }), 'utf8')
    assert.equal(capture.section.text({}), '', 'empty text drops the section')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    rmSync(home, { recursive: true, force: true })
  }
})
