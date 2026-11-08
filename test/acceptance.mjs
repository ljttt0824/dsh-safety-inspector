// Acceptance harness for dsh-safety-inspector, run against a live DSH web host.
// Usage: node test/acceptance.mjs <baseUrl> <token>
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const base = (process.argv[2] ?? 'http://127.0.0.1:7801').replace(/\/$/, '')
const token = process.argv[3] ?? ''
const home = process.env.DSH_HOME ?? path.join(process.env.USERPROFILE ?? '.', '.dsh')

const results = []
function check(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`)
}

async function call(pathname, options = {}) {
  const url = `${base}/api/agent-safety${pathname}`
  const response = await fetch(url, {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...(options.headers ?? {}) },
    ...options,
  })
  const text = await response.text()
  let body
  try { body = JSON.parse(text) } catch { throw new Error(`non-JSON (${response.status}): ${text.slice(0, 200)}`) }
  if (!response.ok || body.ok === false) throw new Error(body.error ?? `HTTP ${response.status}`)
  return body
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// 1 — session list
let sessions = []
{
  const t0 = Date.now()
  const body = await call('/sessions?limit=100')
  sessions = body.sessions ?? []
  const elapsed = Date.now() - t0
  const sorted = sessions.every((row, index) => index === 0 || sessions[index - 1].mtimeMs >= row.mtimeMs)
  check('1 会话列表：数量与排序', sessions.length >= 10 && sorted, `${sessions.length} 个，${elapsed}ms`)
  check('1b 列表加载 < 1s', elapsed < 1000, `${elapsed}ms`)
}

// 2 — the acceptance session
let report = null
{
  const t0 = Date.now()
  const body = await call('/session?sessionId=47cd3ca7-e607-4f13-b2b7-4a8505419648&force=1')
  report = body.report
  const elapsed = Date.now() - t0
  check('2 会话可打开', report.sessionId.startsWith('47cd3ca7'), `${report.stats.events} events / ${report.stats.toolCalls} calls`)
  check('2b 总览数据 < 1.5s', elapsed < 1500, `${elapsed}ms`)
  check('3 每条 finding 带 seq', report.findings.every((row) => Number.isInteger(row.seq) && row.seq > 0), `${report.findings.length} 条`)
}

// 3 — the A1/B2 session
let current = null
{
  const body = await call('/session?sessionId=e3a7ff48-dc85-4d45-9a9d-8c94a1e4a0b8&force=1')
  current = body.report
  const a1 = current.findings.filter((row) => row.code === 'A1')
  const b2 = current.findings.filter((row) => row.code === 'B2')
  check('3b A1 ≥ 20', a1.length >= 20, `${a1.length} 条`)
  check('3c B2 ≥ 1', b2.length >= 1, `${b2.length} 条`)
}

// 4 — anchors really exist in the event stream
{
  const body = await call('/events?sessionId=47cd3ca7-e607-4f13-b2b7-4a8505419648&limit=5000')
  const seqs = new Set((body.events ?? []).map((event) => event.seq))
  const missing = report.findings.filter((row) => !seqs.has(row.seq))
  check('4 证据锚点可回查', missing.length === 0, `${missing.length} 条锚点缺失`)
}

// 5 — chain + data access
{
  const body = await call('/chain?sessionId=47cd3ca7-e607-4f13-b2b7-4a8505419648')
  const chain = body.chain
  const calls = chain.turns.flatMap((turn) => turn.calls)
  const readCall = calls.find((item) => item.name === 'read' && (item.dataAccess?.reads ?? []).length > 0)
  check('5 执行链可展开', chain.turns.length > 0 && calls.length > 0, `${chain.turns.length} 步 / ${calls.length} 调用`)
  check('6 数据访问-读了什么', readCall !== undefined, readCall ? readCall.dataAccess.reads[0] : '未找到带路径的 read')
  const messageIds = chain.turns.flatMap((turn) => turn.assistants.map((item) => item.id)).filter(Boolean)
  check('6b 回答消息可定位', messageIds.length > 0, `${messageIds.length} 条回答`)
}

// 7 — label a C1 finding as benign, rescan, verify downgrade
{
  const c1 = report.findings.find((row) => row.code === 'C1')
  if (c1 === undefined) check('7 标记误报', false, '没有 C1 可标')
  else {
    await call('/label', { method: 'POST', body: JSON.stringify({ findingId: c1.id, mark: 'benign' }) })
    const body = await call('/session?sessionId=47cd3ca7-e607-4f13-b2b7-4a8505419648&force=1')
    const again = body.report.findings.find((row) => row.id === c1.id)
    check('7 标记误报后降级', again !== undefined && again.verdict === 'rejected' && again.severity === null,
      again ? `${c1.verdict} -> ${again.verdict} / severity ${again.severity} / ${again.rejectReason ?? ''}` : '未找到')
    const sameRule = body.report.findings.filter((row) => row.feature === c1.feature && row.state !== 'benign' && row.id !== c1.id)
    check('7b 同特征不再计违规', sameRule.length === 0, `${sameRule.length} 条同特征仍在 violation`)
  }
}

// 8 — explain
{
  const target = report.findings.find((row) => row.code === 'B2') ?? report.findings[0]
  const body = await call('/explain?findingId=' + encodeURIComponent(target.id))
  check('8 explain 返回证据与邻居', body.ok === true && Array.isArray(body.neighbours) && body.link.includes('#safety?'), body.link ?? '')
}

// 9 — coverage consistency between report and rules catalog
{
  const body = await call('/rules')
  const covered = new Set(body.coveredSubcodes)
  const totals = body.taxonomy.categories.flatMap((category) => category.subcodes)
  const total = totals.length
  const blind = total - covered.size
  check('12 覆盖声明一致',
    covered.size === report.coverage.coveredSubcodes && total === report.coverage.totalSubcodes && blind === report.blindSpots.length,
    `rules=${covered.size} report=${report.coverage.coveredSubcodes} total=${total} blind=${blind}`)
}

// 10 — corrupted session must be 'error', never 'pass'
{
  const workspace = path.join(home, 'sessions', '--safety-acceptance--')
  const dir = path.join(workspace, 'session-badc0ffee-0000-0000-0000-000000000000')
  try {
    mkdirSync(dir, { recursive: true })
    writeFileSync(path.join(dir, 'session.v4.jsonl.zstd'), Buffer.from('not a zstd frame at all'))
    const body = await call('/session?sessionId=badc0ffee-0000-0000-0000-000000000000&force=1')
    check('10 损坏 zstd → error 不是 pass', body.report.state === 'error' || body.report.verdict === 'unscannable', String(body.report.state ?? body.report.verdict))
    const list = await call('/sessions?limit=100')
    check('10b 单会话失败不影响其他', (list.sessions ?? []).filter((row) => row.state === 'ok').length >= 10, '其余会话仍可列出')
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
}

// 11 — no secrets in the cache/log
{
  const { readdirSync, readFileSync } = await import('node:fs')
  const root = path.join(home, 'agent-safety')
  const offenders = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) { walk(full); continue }
      const text = readFileSync(full, 'utf8')
      if (/sk-[A-Za-z0-9_-]{16,}/.test(text) || /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) offenders.push(full)
    }
  }
  walk(root)
  check('9 缓存/日志无密钥原文', offenders.length === 0, offenders.join(', ') || 'clean')
}

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
