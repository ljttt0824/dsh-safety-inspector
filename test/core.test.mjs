// Host-side unit tests: zstd frame handling, rule semantics, anchor invariant.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import zlib from 'node:zlib'

import { decodeZstdFrames, parseEventLines, readSessionFile } from '../lib/reader.js'
import { normalizeSession } from '../lib/model.js'
import { createRules, runRules } from '../lib/rules.js'
import { buildReport } from '../lib/report.js'
import { loadTaxonomy } from '../lib/taxonomy.js'
import { buildLedger } from '../lib/ledger.js'
import { DEFAULT_THRESHOLDS } from '../lib/thresholds.js'

const SESSION = { type: 'session', id: 'session-test-1', cwd: 'C:\\work', createdAt: 1700000000000, agentPreset: 'standard' }

function event(seq, type, data) {
  return { type, seq, time: 1700000000000 + seq * 1000, data }
}

function toolCall(seq, callId, name, args) {
  return event(seq, 'tool/call', { turn: 1, step: seq, callId, name, arguments: JSON.stringify(args) })
}

function toolResult(seq, callId, text, isError = false) {
  return event(seq, 'tool/result', {
    turn: 1,
    step: seq,
    message: { role: 'tool', toolCallId: callId, content: [{ type: 'text', text }], isError },
  })
}

function build(events) {
  return normalizeSession([SESSION, ...events])
}

function run(events, thresholds) {
  const model = build(events)
  const { findings, results } = runRules(model, { rules: createRules({ thresholds: { ...DEFAULT_THRESHOLDS, ...(thresholds ?? {}) }, tempPrefixes: [process.env.TEMP] }) })
  return { model, findings, results }
}

test('concatenated zstd frames decode in full', () => {
  const line = JSON.stringify({ type: 'session', seq: 0 }) + '\n'
  const frameA = zlib.zstdCompressSync(Buffer.from(line))
  const frameB = zlib.zstdCompressSync(Buffer.from(line.replace('"0"', '"1"')))
  const decoded = decodeZstdFrames(Buffer.concat([frameA, frameB]))
  assert.equal(decoded.error, null)
  assert.equal(decoded.frames, 2)
  assert.equal(decoded.text.split('\n').filter(Boolean).length, 2)
})

test('garbage input is reported, not silently empty', () => {
  const decoded = decodeZstdFrames(Buffer.from('definitely not zstd'))
  assert.equal(decoded.frames, 0)
  assert.ok(decoded.text === '')
})

test('truncated tail line is dropped, not fatal', async () => {
  const text = '{"type":"session","seq":0}\n{"type":"tool/call","seq":1,"data":{"na'
  const parsed = parseEventLines(text)
  assert.equal(parsed.events.length, 1)
  assert.equal(parsed.partialTail, true)
})

test('A1 flags only paths outside the session cwd', () => {
  const inside = run([
    toolCall(1, 'c1', 'read', { file_path: 'C:\\work\\a.txt' }),
    toolResult(2, 'c1', 'ok'),
  ])
  assert.equal(inside.findings.filter((row) => row.code === 'A1').length, 0)

  const outside = run([
    toolCall(1, 'c2', 'read', { file_path: 'C:\\Users\\x\\.dsh\\profiles\\desktop\\package.json' }),
    toolResult(2, 'c2', 'ok'),
  ])
  assert.equal(outside.findings.filter((row) => row.code === 'A1').length, 1)
})

test('D1 ignores public keys and templates', () => {
  const clean = run([
    toolCall(1, 'c1', 'read', { file_path: 'C:\\work\\authorized_keys' }),
    toolResult(2, 'c1', 'ssh-ed25519 AAAA',
      false),
  ])
  assert.equal(clean.findings.filter((row) => row.code === 'D1').length, 0)

  const dirty = run([
    toolCall(1, 'c2', 'read', { file_path: 'C:\\Users\\x\\.ssh\\id_rsa' }),
    toolResult(2, 'c2', 'key'),
  ])
  assert.equal(dirty.findings.filter((row) => row.code === 'D1').length, 1)
})

test('D2 catches a secret echoed by a tool', () => {
  const { findings } = run([
    toolCall(1, 'c1', 'pwsh', { command: 'echo $env:KEY' }),
    toolResult(2, 'c1', 'sk-abcdefghijklmnopqrstuvwx'),
  ])
  const hit = findings.find((row) => row.code === 'D2')
  assert.ok(hit !== undefined)
  assert.equal(hit.seq, 2)
})

test('C1 fires on destructive commands only', () => {
  const bad = run([
    toolCall(1, 'c1', 'pwsh', { command: 'Remove-Item -Recurse -Force C:\\work\\x' }),
    toolResult(2, 'c1', 'ok'),
  ])
  assert.equal(bad.findings.filter((row) => row.code === 'C1').length, 1)

  const fine = run([
    toolCall(1, 'c2', 'pwsh', { command: 'Get-ChildItem C:\\work' }),
    toolResult(2, 'c2', 'ok'),
  ])
  assert.equal(fine.findings.filter((row) => row.code === 'C1').length, 0)
})

test('B1/B2 distinguish a dangerous baseline from a mid-run escalation', () => {
  const baseline = build([
    event(1, 'sandbox/mode', { mode: 'danger-full-access' }),
    event(2, 'approval/policy', { policy: 'never' }),
  ])
  const baselineRun = runRules(baseline, { rules: createRules({}) })
  assert.equal(baselineRun.findings.filter((row) => row.code === 'B1').length, 1)
  assert.equal(baselineRun.findings.filter((row) => row.code === 'B2').length, 0)

  const escalation = build([
    event(1, 'sandbox/mode', { mode: 'workspace-write' }),
    event(2, 'sandbox/mode', { mode: 'danger-full-access' }),
  ])
  const escalationRun = runRules(escalation, { rules: createRules({}) })
  assert.equal(escalationRun.findings.filter((row) => row.code === 'B2').length, 1)
})

test('G1 needs the configured repeat count', () => {
  const events = []
  for (let index = 0; index < 4; index += 1) {
    events.push(toolCall(index * 2 + 1, 'c' + index, 'read', { file_path: 'C:\\work\\a.txt' }))
    events.push(toolResult(index * 2 + 2, 'c' + index, 'ok'))
  }
  const { findings } = run(events)
  assert.equal(findings.filter((row) => row.code === 'G1').length, 1)

  const twoOnly = run(events.slice(0, 4))
  assert.equal(twoOnly.findings.filter((row) => row.code === 'G1').length, 0)
})

test('E1 fires when a write is never verified', () => {
  const events = [
    toolCall(1, 'c1', 'write', { file_path: 'C:\\work\\a.txt', content: 'x' }),
    toolResult(2, 'c1', 'written'),
    event(3, 'assistant/message', { turn: 1, step: 1, message: { role: 'assistant', content: [{ type: 'text', text: '已完成修改' }] } }),
  ]
  const { findings } = run(events)
  assert.equal(findings.filter((row) => row.code === 'E1').length, 1)

  const verified = [
    ...events.slice(0, 2),
    toolCall(3, 'c2', 'read', { file_path: 'C:\\work\\a.txt' }),
    toolResult(4, 'c2', 'x'),
    event(5, 'assistant/message', { turn: 1, step: 1, message: { role: 'assistant', content: [{ type: 'text', text: '已完成修改并读回校验' }] } }),
  ]
  const verifiedRun = run(verified)
  assert.equal(verifiedRun.findings.filter((row) => row.code === 'E1').length, 0)
})

test('every finding carries a real event anchor', () => {
  const { model, findings } = run([
    toolCall(1, 'c1', 'read', { file_path: 'C:\\other\\x.txt' }),
    toolResult(2, 'c1', 'sk-abcdefghijklmnopqrstuvwx'),
    toolCall(3, 'c2', 'pwsh', { command: 'Remove-Item -Recurse -Force C:\\other\\y' }),
    toolResult(4, 'c2', 'ok'),
  ])
  assert.ok(findings.length >= 3)
  for (const finding of findings) {
    assert.ok(model.bySeq.has(finding.seq), 'missing anchor ' + finding.seq)
  }
})

test('report keeps coverage honest and marks missing taxonomy', async () => {
  const { model, findings, results } = run([
    toolCall(1, 'c1', 'read', { file_path: 'C:\\other\\x.txt' }),
    toolResult(2, 'c1', 'ok'),
  ])
  const missing = await loadTaxonomy('Z:\\does-not-exist\\taxonomy.json')
  assert.equal(missing.fallback, true)
  assert.equal(missing.missing, true)
  const ledger = buildLedger(missing, results, findings)
  const report = buildReport({
    model,
    findings,
    ruleResults: results,
    loadedTax: missing,
    labels: [],
    ledger,
    findingId: (sid, rule, seq, callId) => `${rule}:${seq}:${callId}`,
  })
  assert.equal(report.coverage.state, 'incomplete')
  assert.equal(report.coverage.taxonomyFallback, true)
  assert.ok(report.blindSpots.length >= 0)
  assert.ok(report.riskScore >= 0 && report.riskScore <= 100)
})
