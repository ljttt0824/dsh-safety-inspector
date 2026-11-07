/**
 * dsh-safety-inspector — host half.
 *
 * Read-only behavior audit over DSH session event streams: classify unsafe
 * behavior, anchor every finding to a real event seq, and serve the drill-down
 * data the browser half renders.
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'

import { normalizeSession, compact } from './model.js'
import { listSessionDirs, readSessionFile, zstdSupport } from './reader.js'
import { createRules, runRules } from './rules.js'
import { buildReport, summarize } from './report.js'
import { Store, resolveHome } from './store.js'
import { loadTaxonomy } from './taxonomy.js'
import { mergeThresholds } from './thresholds.js'

export const name = 'safety-inspector'
export const inject = ['tools']

const ROUTE_PREFIX = '/api/agent-safety'
const MAX_BODY = 1024 * 1024
const TOOL_NAME = 'safety_audit'

function json(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  })
  res.end(body)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY) {
        reject(new Error('请求体超过 1MB'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8')
      if (text.trim().length === 0) return resolve({})
      try {
        resolve(JSON.parse(text))
      } catch (error) {
        reject(new Error('请求体不是 JSON: ' + error.message))
      }
    })
    req.on('error', reject)
  })
}

function normalizeId(value) {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/^session-/, '')
}

export function createService(options) {
  const home = options.home
  const store = new Store(home)
  const log = (message) => { void store.log(message) }
  const inflight = new Map()

  async function taxonomy() {
    const settings = await store.settings()
    return loadTaxonomy(options.taxonomyPath ?? settings.taxonomyPath)
  }

  async function ruleSet() {
    const settings = await store.settings()
    return createRules({
      thresholds: mergeThresholds(settings.thresholds),
      tempPrefixes: [process.env.TEMP, process.env.TMP, home].filter((value) => typeof value === 'string'),
    })
  }

  async function discoverSessions(limit = 200) {
    const dirs = await listSessionDirs(home)
    return dirs.slice(0, limit)
  }

  async function scanSession(sessionId, { force = false } = {}) {
    const wanted = normalizeId(sessionId)
    if (wanted.length === 0) throw new Error('缺少 sessionId')
    if (inflight.has(wanted)) return inflight.get(wanted)
    const task = (async () => {
      const dirs = await discoverSessions(500)
      const target = dirs.find((item) => item.sessionId === wanted)
      if (target === undefined) throw new Error(`找不到会话 ${wanted}`)
      if (!zstdSupport() && target.compressed) throw new Error('当前运行时没有 zstd 解码能力（需要 Node >= 22.15）')

      const cacheKey = `${target.mtimeMs}:${target.size}`
      if (!force) {
        const cached = await store.readSessionCache(wanted)
        if (cached !== null && cached.cacheKey === cacheKey && cached.report !== undefined) return { ...cached, fromCache: true }
      }

      const read = await readSessionFile(target.file)
      if (!read.ok) {
        const settings = await store.settings()
        const failed = {
          cacheKey,
          fromCache: false,
          error: read.error,
          sessionId: wanted,
          report: {
            schemaVersion: 1,
            sessionId: wanted,
            state: 'error',
            error: read.error,
            coverage: { state: 'incomplete', coveredSubcodes: 0, totalSubcodes: 0, taxonomyFallback: false, rulesTotal: 0, skipped: 0, errors: 1 },
            blindSpots: [],
            findings: [],
            stats: { events: 0, toolCalls: 0, tools: {}, turns: [] },
            counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            riskScore: 0,
            riskLevel: '—',
            verdict: 'unscannable',
            settings,
            generatedAt: new Date().toISOString(),
          },
        }
        await store.writeSessionCache(wanted, failed)
        await store.touchSession(wanted, {
          sessionId: wanted,
          file: target.file,
          cwd: null,
          startedAt: new Date(target.mtimeMs).toISOString(),
          state: 'error',
          error: read.error,
          events: 0,
          toolCalls: 0,
          riskScore: 0,
          riskLevel: '—',
          coverage: 'incomplete',
          findings: 0,
          scannedAt: new Date().toISOString(),
        })
        log(`scan ${wanted} failed: ${read.error}`)
        return failed
      }

      const model = normalizeSession(read.events)
      const loadedTax = await taxonomy()
      const rules = await ruleSet()
      const { findings, results } = runRules(model, { rules })
      const labels = await store.readLabels()
      const report = buildReport({
        model,
        findings,
        ruleResults: results,
        loadedTax,
        labels,
        findingId: (sid, ruleId, seq, callId) => store.findingId(sid, ruleId, seq, callId),
      })
      report.decode = {
        frames: read.frames,
        droppedFrames: read.droppedFrames,
        malformed: read.malformed,
        partialTail: read.partialTail,
        size: read.size,
      }
      report.ruleResults = results

      const payload = { cacheKey, fromCache: false, sessionId: wanted, file: target.file, report }
      await store.writeSessionCache(wanted, payload)
      await store.touchSession(wanted, {
        sessionId: wanted,
        file: target.file,
        cwd: report.cwd,
        startedAt: report.startedAt !== null ? new Date(report.startedAt).toISOString() : null,
        model: report.model,
        state: 'ok',
        events: report.stats.events,
        toolCalls: report.stats.toolCalls,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel,
        verdict: report.verdict,
        coverage: report.coverage.state,
        covered: report.coverage.coveredSubcodes,
        total: report.coverage.totalSubcodes,
        findings: report.findings.filter((item) => item.state !== 'benign').length,
        scannedAt: new Date().toISOString(),
      })
      const slim = report.findings.map((item) => ({
        id: item.id,
        sessionId: item.sessionId,
        code: item.code,
        codeName: item.codeName,
        severity: item.severity,
        state: item.state,
        ruleId: item.ruleId,
        seq: item.seq,
        callId: item.callId,
        evidence: item.evidence,
        feature: item.feature,
        at: report.generatedAt,
      }))
      await store.appendFindings(slim)
      log(`scan ${wanted}: events=${report.stats.events} calls=${report.stats.toolCalls} findings=${slim.length} coverage=${report.coverage.state}`)
      return payload
    })().finally(() => inflight.delete(wanted))
    inflight.set(wanted, task)
    return task
  }

  async function listSessions(limit = 50) {
    const dirs = await discoverSessions(limit)
    const index = await store.readIndex()
    return dirs.map((dir) => {
      const meta = index.sessions[dir.sessionId] ?? {}
      return {
        sessionId: dir.sessionId,
        file: dir.file,
        size: dir.size,
        mtimeMs: dir.mtimeMs,
        workspaceKey: dir.workspaceKey,
        cwd: meta.cwd ?? null,
        startedAt: meta.startedAt ?? new Date(dir.mtimeMs).toISOString(),
        model: meta.model ?? null,
        events: meta.events ?? null,
        toolCalls: meta.toolCalls ?? null,
        riskScore: meta.riskScore ?? null,
        riskLevel: meta.riskLevel ?? '—',
        verdict: meta.verdict ?? 'unscanned',
        state: meta.state ?? (meta.error !== undefined ? 'error' : 'unscanned'),
        coverage: meta.coverage ?? null,
        findings: meta.findings ?? null,
        scannedAt: meta.scannedAt ?? null,
      }
    })
  }

  async function eventsOf(sessionId, { from = null, to = null, limit = 4000 } = {}) {
    const wanted = normalizeId(sessionId)
    const dirs = await discoverSessions(500)
    const target = dirs.find((item) => item.sessionId === wanted)
    if (target === undefined) throw new Error(`找不到会话 ${wanted}`)
    const read = await readSessionFile(target.file)
    if (!read.ok) throw new Error(read.error)
    let rows = read.events
    if (from !== null) rows = rows.filter((event) => (event.seq ?? 0) >= from)
    if (to !== null) rows = rows.filter((event) => (event.seq ?? 0) <= to)
    return {
      sessionId: wanted,
      total: read.events.length,
      returned: Math.min(rows.length, limit),
      events: rows.slice(-limit),
    }
  }

  async function explain(findingId) {
    const rows = (await store.readIndex()).sessions
    for (const [sessionId, meta] of Object.entries(rows)) {
      const cached = await store.readSessionCache(sessionId)
      const hit = cached?.report?.findings?.find((item) => item.id === findingId)
      if (hit === undefined) continue
      const events = await eventsOf(sessionId, { from: hit.seq - 3, to: hit.seq + 3, limit: 40 })
      const related = await eventsOf(sessionId, { from: hit.seq - 120, to: hit.seq + 120, limit: 400 })
      const callEvents = related.events.filter((event) => {
        if (event.type === 'tool/call') return event.data?.callId === hit.callId
        if (event.type === 'tool/result') return event.data?.message?.toolCallId === hit.callId
        return false
      })
      return {
        ok: true,
        finding: hit,
        session: { sessionId, cwd: meta.cwd, startedAt: meta.startedAt },
        neighbours: events.events,
        callEvents,
        link: `#safety?session=${sessionId}&seq=${hit.seq}`,
      }
    }
    return { ok: false, error: '找不到该发现（可能已被重扫替换）' }
  }

  async function label(input) {
    const findingId = String(input?.findingId ?? '')
    const mark = String(input?.mark ?? '')
    if (findingId.length === 0) throw new Error('缺少 findingId')
    if (!['confirmed', 'benign', 'violation'].includes(mark)) throw new Error(`未知标注 ${mark}`)
    const entry = await explain(findingId)
    if (entry.ok !== true) throw new Error(entry.error)
    const row = {
      findingId,
      mark,
      sessionId: entry.finding.sessionId,
      code: entry.finding.code,
      ruleId: entry.finding.ruleId,
      seq: entry.finding.seq,
      feature: entry.finding.feature,
      evidence: compact(entry.finding.evidence, 240),
      at: new Date().toISOString(),
    }
    await store.appendLabel(row)
    log(`label ${findingId} -> ${mark}`)
    return { ok: true, label: row }
  }

  async function rulesCatalog() {
    const loadedTax = await taxonomy()
    const { results } = runRules(normalizeSession([]), { rules: await ruleSet() })
    const implemented = new Set(results.map((row) => row.code))
    return {
      ok: true,
      taxonomy: {
        path: loadedTax.path,
        fallback: loadedTax.fallback,
        missing: loadedTax.missing,
        error: loadedTax.error,
        total: loadedTax.total,
        categories: (loadedTax.taxonomy.categories ?? []).map((category) => ({
          code: category.code,
          name: category.name,
          summary: category.summary ?? '',
          subcodes: (category.subcodes ?? []).map((sub) => ({
            code: sub.code,
            name: sub.name,
            definition: sub.definition ?? '',
            severity: sub.severity ?? '中',
            reversibility: sub.reversibility ?? '可逆',
            detect: sub.detect ?? [],
            covered: implemented.has(sub.code),
          })),
        })),
      },
      rules: (await ruleSet()).map((rule) => ({
        id: rule.id,
        code: rule.code,
        name: rule.name,
        covered: implemented.has(rule.code),
      })),
      coveredSubcodes: [...implemented].sort(),
    }
  }

  async function chainOf(sessionId, { resultChars = 4000 } = {}) {
    const wanted = normalizeId(sessionId)
    const dirs = await discoverSessions(500)
    const target = dirs.find((item) => item.sessionId === wanted)
    if (target === undefined) throw new Error(`找不到会话 ${wanted}`)
    const read = await readSessionFile(target.file)
    if (!read.ok) throw new Error(read.error)
    const model = normalizeSession(read.events)
    const clip = (text, limit) => {
      const value = String(text ?? '')
      return value.length > limit ? value.slice(0, limit) + `…[+${value.length - limit}]` : value
    }
    const callsById = new Map(model.calls.map((call) => [call.callId, call]))
    const turns = new Map()
    const touch = (turn, step) => {
      const key = `${turn ?? '?'}:${step ?? '?'}`
      if (!turns.has(key)) turns.set(key, { turn: turn ?? null, step: step ?? null, seqStart: null, calls: [], assistants: [], userMessages: [] })
      return turns.get(key)
    }
    for (const message of model.assistantMessages) {
      const bucket = touch(message.turn, message.step)
      bucket.assistants.push({ id: message.id, turn: message.turn, step: message.step, seq: message.seq, text: clip(message.text, 1200) })
      if (bucket.seqStart === null || message.seq < bucket.seqStart) bucket.seqStart = message.seq
    }
    for (const user of model.userMessages) {
      const bucket = touch(null, null)
      bucket.userMessages.push({ seq: user.seq, text: clip(user.text, 1200) })
      if (bucket.seqStart === null || user.seq < bucket.seqStart) bucket.seqStart = user.seq
    }
    for (const call of model.calls) {
      const bucket = touch(call.turn, call.step)
      const args = call.arguments ?? {}
      const reads = []
      const writes = []
      const domains = []
      if (typeof args.file_path === 'string' || typeof args.path === 'string') {
        const target = args.file_path ?? args.path
        if (['write', 'edit', 'append'].includes(call.name)) writes.push(target)
        else reads.push(target)
      }
      for (const key of ['url', 'uri']) {
        if (typeof args[key] === 'string') {
          try { domains.push(new URL(args[key]).host) } catch { domains.push(args[key].slice(0, 80)) }
        }
      }
      bucket.calls.push({
        callId: call.callId,
        name: call.name,
        callSeq: call.callSeq,
        resultSeq: call.resultSeq,
        durationMs: call.durationMs,
        isError: call.isError,
        argsPreview: clip(call.argumentsRaw, 400),
        args: clip(call.argumentsRaw, 8000),
        result: clip(call.resultText, resultChars),
        resultBytes: call.resultBytes,
        dataAccess: { reads, writes, domains },
      })
      if (bucket.seqStart === null || (call.callSeq !== null && call.callSeq < bucket.seqStart)) bucket.seqStart = call.callSeq
    }
    const approvalSeqs = new Set()
    for (const approval of model.approvals) {
      approvalSeqs.add(approval.callId)
    }
    const ordered = [...turns.values()].sort((a, b) => (a.seqStart ?? 0) - (b.seqStart ?? 0))

    // A turn is one user request; its assistant replies land on the final step,
    // which by construction carries no tool call. The UI therefore needs the
    // per-turn aggregate, not just the step.
    const turnGroups = []
    const groupByTurn = new Map()
    for (const bucket of ordered) {
      const key = bucket.turn ?? null
      if (!groupByTurn.has(key)) {
        const group = { turn: key, steps: 0, calls: 0, errors: 0, firstSeq: bucket.seqStart ?? 0, lastSeq: bucket.seqStart ?? 0, callIds: [] }
        groupByTurn.set(key, group)
        turnGroups.push(group)
      }
      const group = groupByTurn.get(key)
      group.steps += 1
      for (const call of bucket.calls) {
        group.calls += 1
        if (call.isError === true) group.errors += 1
        group.callIds.push(call.callId)
        if (call.callSeq !== null && call.callSeq > group.lastSeq) group.lastSeq = call.callSeq
        if (call.resultSeq !== null && call.resultSeq > group.lastSeq) group.lastSeq = call.resultSeq
      }
      if (bucket.seqStart !== null && bucket.seqStart < group.firstSeq) group.firstSeq = bucket.seqStart
    }
    turnGroups.sort((a, b) => (a.firstSeq ?? 0) - (b.firstSeq ?? 0))

    return {
      sessionId: wanted,
      cwd: model.cwd,
      model: model.model,
      startedAt: model.startedAt,
      policy: model.policy,
      approvals: model.approvals.map((approval) => ({
        id: approval.id,
        tool: approval.tool,
        callId: approval.callId,
        reason: clip(approval.reason, 600),
        outcome: approval.outcome,
        askedSeq: approval.askedSeq,
        decidedSeq: approval.decidedSeq,
      })),
      approvalCallIds: [...approvalSeqs],
      jobs: model.jobs.map((job) => ({ jobId: job.jobId, kind: job.kind, label: job.label, settled: job.settled, callId: job.callId })),
      turns: ordered.map((bucket) => ({
        ...bucket,
        calls: bucket.calls.sort((a, b) => (a.callSeq ?? 0) - (b.callSeq ?? 0)),
      })),
      turnGroups,
      totals: {
        events: model.eventCount,
        calls: model.calls.length,
        errors: model.calls.filter((call) => call.isError === true).length,
      },
    }
  }

  return {
    home,
    store,
    scanSession,
    listSessions,
    eventsOf,
    chainOf,
    explain,
    label,
    rulesCatalog,
    summarize,
    taxonomy,
    log,
  }
}

/* ------------------------------------------------------------------ tool --- */

function toolSchema(properties, required = []) {
  return { type: 'object', properties, required, additionalProperties: false }
}

function textOutput() {
  return {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: String(value) }],
  }
}

function buildTool(service) {
  return {
    name: TOOL_NAME,
    description: '只读的行为安全审计：扫描 DSH 会话事件流，返回风险分、不安全行为分类（A–H）、带事件锚点的发现，以及覆盖/盲区声明。',
    parameters: toolSchema({
      action: {
        type: 'string',
        enum: ['scan_session', 'list_sessions', 'findings', 'explain', 'label', 'rules'],
        description: '要执行的动作',
      },
      sessionId: { type: 'string', description: '目标会话 id；省略时取最近修改的会话' },
      force: { type: 'boolean', description: '忽略缓存强制重扫' },
      code: { type: 'string', description: '过滤：子类码，如 C1' },
      severity: { type: 'string', description: '过滤：严重度（严重/高/中/低/info）' },
      findingId: { type: 'string', description: 'explain / label 的目标发现 id' },
      mark: { type: 'string', enum: ['confirmed', 'benign', 'violation'], description: 'label 动作的标注' },
      limit: { type: 'integer', description: '列表条数上限，默认 20' },
    }, ['action']),
    output: textOutput(),
    timeoutMs: 90000,
    async execute(args) {
      const action = String(args?.action ?? '')
      if (action === 'list_sessions') {
        const rows = await service.listSessions(Number.isFinite(args.limit) ? args.limit : 20)
        return JSON.stringify({ ok: true, schemaVersion: 1, sessions: rows }, null, 2)
      }
      if (action === 'rules') return JSON.stringify(await service.rulesCatalog(), null, 2)
      if (action === 'explain') return JSON.stringify(await service.explain(String(args.findingId ?? '')), null, 2)
      if (action === 'label') return JSON.stringify(await service.label(args), null, 2)

      const sessionId = typeof args?.sessionId === 'string' && args.sessionId.length > 0
        ? args.sessionId
        : (await service.listSessions(1))[0]?.sessionId
      if (sessionId === undefined) return JSON.stringify({ ok: false, error: '本机没有可审计的会话' })

      if (action === 'findings') {
        const { report } = await service.scanSession(sessionId, { force: Boolean(args.force) })
        let rows = report.findings ?? []
        if (typeof args.code === 'string' && args.code.length > 0) rows = rows.filter((row) => row.code === args.code)
        if (typeof args.severity === 'string' && args.severity.length > 0) rows = rows.filter((row) => row.severity === args.severity)
        return JSON.stringify({
          ok: true,
          schemaVersion: 1,
          sessionId,
          count: rows.length,
          findings: rows.slice(0, Number.isFinite(args.limit) ? args.limit : 50),
          coverage: report.coverage,
          link: `#safety?session=${sessionId}`,
        }, null, 2)
      }

      const { report, fromCache } = await service.scanSession(sessionId, { force: Boolean(args.force) })
      return JSON.stringify({
        ok: true,
        schemaVersion: 1,
        fromCache,
        sessionId,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel,
        verdict: report.verdict,
        counts: report.counts,
        coverage: report.coverage,
        byCategory: report.byCategory,
        blindSpots: report.blindSpots.slice(0, 40),
        findings: (report.findings ?? []).slice(0, 40),
        stats: {
          events: report.stats?.events,
          toolCalls: report.stats?.toolCalls,
          errors: report.stats?.errors,
          approvals: report.stats?.approvals,
        },
        link: `#safety?session=${sessionId}`,
      }, null, 2)
    },
  }
}

/* ---------------------------------------------------------------- routes --- */

function registerRoutes(scope, service) {
  const disposers = []
  const add = (kind, routePath, handler) => {
    disposers.push(scope.webServer.register({ kind, path: routePath, handler }))
  }

  add('exact', `${ROUTE_PREFIX}/health`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    json(res, 200, { ok: true, schemaVersion: 1, home: service.home, zstd: zstdSupport() })
  })

  add('exact', `${ROUTE_PREFIX}/sessions`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const limit = Number(url.searchParams.get('limit') ?? 50)
      json(res, 200, { ok: true, sessions: await service.listSessions(Number.isFinite(limit) ? limit : 50) })
    } catch (error) {
      json(res, 500, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/session`, async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      if (req.method === 'GET') {
        const sessionId = url.searchParams.get('sessionId') ?? ''
        const force = url.searchParams.get('force') === '1'
        const payload = await service.scanSession(sessionId, { force })
        return json(res, 200, { ok: true, fromCache: payload.fromCache, error: payload.error ?? null, report: payload.report })
      }
      if (req.method === 'POST') {
        const body = await readBody(req)
        const payload = await service.scanSession(body.sessionId ?? '', { force: body.force === true })
        return json(res, 200, { ok: true, fromCache: payload.fromCache, error: payload.error ?? null, report: payload.report })
      }
      return json(res, 405, { ok: false, error: 'method not allowed' })
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/events`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const sessionId = url.searchParams.get('sessionId') ?? ''
      const from = url.searchParams.get('from')
      const to = url.searchParams.get('to')
      const limit = Number(url.searchParams.get('limit') ?? 4000)
      const payload = await service.eventsOf(sessionId, {
        from: from === null ? null : Number(from),
        to: to === null ? null : Number(to),
        limit: Number.isFinite(limit) ? limit : 4000,
      })
      json(res, 200, { ok: true, ...payload })
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/chain`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const sessionId = url.searchParams.get('sessionId') ?? ''
      const resultChars = Number(url.searchParams.get('resultChars') ?? 4000)
      json(res, 200, { ok: true, chain: await service.chainOf(sessionId, { resultChars: Number.isFinite(resultChars) ? resultChars : 4000 }) })
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/rules`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      json(res, 200, await service.rulesCatalog())
    } catch (error) {
      json(res, 500, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/explain`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      json(res, 200, await service.explain(url.searchParams.get('findingId') ?? ''))
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/label`, async (req, res) => {
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      json(res, 200, await service.label(await readBody(req)))
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/settings`, async (req, res) => {
    try {
      if (req.method === 'GET') return json(res, 200, { ok: true, settings: await service.store.settings() })
      if (req.method === 'POST') {
        const patch = await readBody(req)
        return json(res, 200, { ok: true, settings: await service.store.updateSettings(patch) })
      }
      return json(res, 405, { ok: false, error: 'method not allowed' })
    } catch (error) {
      json(res, 400, { ok: false, error: String(error?.message ?? error) })
    }
  })

  add('exact', `${ROUTE_PREFIX}/search`, async (req, res) => {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: 'method not allowed' })
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const query = (url.searchParams.get('q') ?? '').toLowerCase()
      const sessions = await service.listSessions(200)
      const hits = []
      for (const session of sessions) {
        const cached = await service.store.readSessionCache(session.sessionId)
        for (const finding of cached?.report?.findings ?? []) {
          const haystack = `${finding.code} ${finding.ruleId} ${finding.evidence} ${finding.codeName}`.toLowerCase()
          if (query.length === 0 || haystack.includes(query)) {
            hits.push({ ...finding, sessionId: session.sessionId, riskLevel: session.riskLevel })
          }
        }
      }
      json(res, 200, { ok: true, count: hits.length, hits: hits.slice(0, 300) })
    } catch (error) {
      json(res, 500, { ok: false, error: String(error?.message ?? error) })
    }
  })

  scope.effect(() => () => {
    for (const dispose of disposers) dispose()
  }, 'safety-inspector: http routes')
}

/* -------------------------------------------------------------- plugin ---- */

export function apply(ctx, rawConfig) {
  const logger = ctx.logger
  const home = resolveHome()
  const config = rawConfig !== null && typeof rawConfig === 'object' ? rawConfig : {}
  const service = createService({
    home,
    taxonomyPath: typeof config.taxonomyPath === 'string' ? config.taxonomyPath : undefined,
  })
  service.ready = service.store.ready().catch((error) => {
    logger?.error?.(`safety-inspector: 初始化存储失败: ${String(error?.message ?? error)}`)
  })
  void service.store.ready()

  ctx.inject(['tools'], (scope) => {
    scope.tools.register(buildTool(service))
    logger?.info?.(`safety-inspector: 已注册工具 ${TOOL_NAME}；数据目录 ${service.store.paths.root}`)
  })

  ctx.inject(['systemPrompt'], (scope) => {
    scope.systemPrompt.section({
      name: 'tool:safety-inspector',
      order: 170,
      text: [
        '本机装有「安全巡检」插件，可用只读工具 safety_audit 审计会话行为安全。',
        '当用户问「这次会话安全吗 / 有没有越权 / 有没有不安全操作」时，先调用 safety_audit（action=scan_session，sessionId 可选），再基于返回的 findings、coverage、blindSpots 回答。',
        '回答时必须区分「发现了什么」「覆盖了哪些子类」「没覆盖哪些」，不得把未覆盖说成安全；每条发现都要给出深链，格式为 [查看证据](#safety?session=<sessionId>&seq=<seq>)。',
      ].join(' '),
    })
  })

  ctx.inject(['webServer'], (scope) => {
    registerRoutes(scope, service)
    logger?.info?.(`safety-inspector: 已挂载 ${ROUTE_PREFIX}`)
  })

  return service
}
