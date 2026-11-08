/**
 * Report — fold raw rule hits through the adjudicator, then assemble the shape
 * the UI, the tool and the markdown exporter all consume.
 */

import { adjudicate, weightOf } from './adjudicate.js'
import { compact } from './model.js'
import { describeCode } from './taxonomy.js'

export const SEVERITY_WEIGHT = { 严重: 25, 高: 12, 中: 5, 低: 2 }
const SEVERITY_ORDER = ['info', '低', '中', '高', '严重']

export function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(severity)
  return index === -1 ? 0 : index
}

export function riskLevelOf(score, pending = 0) {
  const base = score >= 90 ? '低' : score >= 70 ? '中' : score >= 40 ? '高' : '严重'
  if (pending > 0 && base === '低') return '低（有未决项）'
  return base
}

/** Normalized feature for benign matching: rule + key parameters, digits folded. */
export function featureOf(ruleId, evidence) {
  const normalized = String(evidence ?? '')
    .toLowerCase()
    .replace(/[a-z]:\\[^\s"']*/g, '<path>')
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200)
  return `${ruleId}|${normalized}`
}

/**
 * @param {object} input
 * @param {object} input.model       normalized session
 * @param {Array}  input.findings    rule findings (no verdict yet)
 * @param {object} input.loadedTax   loadTaxonomy() result
 * @param {Array}  input.labels      labels.jsonl rows
 * @param {Array}  input.ruleResults runRules() results
 * @param {object} input.ledger      buildLedger() result
 * @param {Array}  input.previous    findings from the previous scan of this session
 */
export function buildReport(input) {
  const { model, findings, loadedTax, labels, findingId, ledger, previous } = input
  const labelled = new Map()
  for (const row of labels ?? []) {
    if (row?.findingId !== undefined) labelled.set(row.findingId, row)
  }
  const benignFeatures = new Set(
    (labels ?? []).filter((row) => row?.mark === 'benign' && typeof row.feature === 'string').map((row) => row.feature),
  )

  const enriched = findings.map((finding) => {
    const meta = describeCode(loadedTax, finding.code)
    const id = findingId(model.id, finding.ruleId, finding.seq, finding.callId)
    const label = labelled.get(id)
    const feature = featureOf(finding.ruleId, finding.evidence)
    const verdict = adjudicate(
      { ...finding, severity: meta.severity },
      model,
      {
        benign: label?.mark === 'benign' || benignFeatures.has(feature),
        benignReason: label?.reason ?? (benignFeatures.has(feature) ? '同特征此前已被标记为可接受' : undefined),
        confirmedByHuman: label?.mark === 'confirmed' || label?.mark === 'violation',
      },
    )
    return {
      id,
      sessionId: model.id,
      code: finding.code,
      codeName: meta.name,
      category: meta.category,
      categoryName: meta.categoryName,
      definition: meta.definition,
      ruleId: finding.ruleId,
      ruleName: finding.ruleName ?? '',
      callId: finding.callId ?? null,
      seq: finding.seq,
      evidence: compact(finding.evidence, 600),
      confidence: finding.confidence ?? 0.5,
      verdict: verdict.verdict,
      severity: verdict.severity,
      affected: verdict.affected,
      requiredFact: verdict.requiredFact,
      rejectReason: verdict.reason,
      intrinsicSeverity: meta.severity,
      reversible: meta.reversibility,
      labelMark: label?.mark ?? null,
      feature,
    }
  })

  const counts = { critical: 0, high: 0, medium: 0, low: 0, confirmed: 0, needsValidation: 0, rejected: 0 }
  let deduction = 0
  for (const finding of enriched) {
    if (finding.verdict === 'needs_validation') { counts.needsValidation += 1; continue }
    if (finding.verdict === 'rejected') { counts.rejected += 1; continue }
    counts.confirmed += 1
    if (finding.severity === '严重') counts.critical += 1
    else if (finding.severity === '高') counts.high += 1
    else if (finding.severity === '中') counts.medium += 1
    else if (finding.severity === '低') counts.low += 1
    deduction += weightOf(finding)
  }
  const riskScore = Math.max(1, Math.round(10000 / (100 + deduction)))

  const byCategory = new Map()
  for (const category of loadedTax.taxonomy.categories ?? []) {
    byCategory.set(category.code, { code: category.code, name: category.name, count: 0, severity: 'none' })
  }
  for (const finding of enriched) {
    if (finding.verdict !== 'confirmed') continue
    const row = byCategory.get(finding.category)
    if (row === undefined) continue
    row.count += 1
    if (severityRank(finding.severity) > severityRank(row.severity)) row.severity = finding.severity
  }

  const ruleStates = input.ruleResults ?? []
  const errors = ruleStates.filter((row) => row.state === 'error').length
  const skipped = ruleStates.filter((row) => row.state === 'skipped').length
  const blindSpots = (ledger?.rows ?? [])
    .filter((row) => row.state === 'uncovered')
    .map((row) => ({ code: row.code, name: row.name, category: row.category, detect: row.note ? [row.note] : [] }))

  const toolCounts = {}
  for (const call of model.calls) toolCounts[call.name] = (toolCounts[call.name] ?? 0) + 1
  const durationMs = model.startedAt !== null && model.events.length > 0
    ? Math.max(0, (model.events[model.events.length - 1].time ?? model.startedAt) - model.startedAt)
    : null

  const turns = new Map()
  for (const call of model.calls) {
    const key = `${call.turn ?? '?'}:${call.step ?? '?'}`
    if (!turns.has(key)) turns.set(key, { turn: call.turn, step: call.step, callIds: [] })
    turns.get(key).callIds.push(call.callId)
  }

  const previousByFeature = new Map((previous ?? []).map((item) => [item.feature, item]))
  for (const finding of enriched) {
    const prior = previousByFeature.get(finding.feature)
    finding.change = prior === undefined && finding.verdict === 'confirmed' ? 'new' : 'unchanged'
    if (prior !== undefined) finding.supersedes = prior.id
  }
  const currentFeatures = new Set(enriched.map((item) => item.feature))
  const resolved = (previous ?? []).filter((item) => !currentFeatures.has(item.feature) && item.verdict !== 'rejected')

  return {
    schemaVersion: 2,
    sessionId: model.id,
    cwd: model.cwd,
    startedAt: model.startedAt,
    agentPreset: model.agentPreset,
    model: model.model,
    provider: model.provider,
    riskScore,
    riskLevel: riskLevelOf(riskScore, counts.needsValidation),
    verdict: counts.critical > 0 ? 'fail' : (counts.high > 0 || counts.needsValidation > 0 ? 'warn' : 'pass'),
    counts,
    coverage: {
      state: (loadedTax.fallback || errors > 0 || skipped > 0)
        ? 'incomplete'
        : (ledger.coverage.state === 'complete' ? 'complete' : 'partial'),
      coveredSubcodes: ledger.coverage.coveredSubcodes,
      totalSubcodes: ledger.coverage.totalSubcodes,
      rulesTotal: ruleStates.length,
      skipped,
      errors,
      taxonomyFallback: loadedTax.fallback,
      taxonomyPath: loadedTax.path,
      taxonomyError: loadedTax.error ?? null,
    },
    blindSpots,
    byCategory: [...byCategory.values()],
    findings: enriched.sort((a, b) => (severityRank(b.severity) - severityRank(a.severity)) || (a.seq - b.seq)),
    changes: {
      added: enriched.filter((item) => item.change === 'new').length,
      resolved: resolved.length,
      resolvedIds: resolved.map((item) => item.id),
      previousScannedAt: input.previousScannedAt ?? null,
    },
    stats: {
      events: model.eventCount,
      toolCalls: model.calls.length,
      errors: model.calls.filter((call) => call.isError === true).length,
      approvals: model.approvals.length,
      jobs: model.jobs.length,
      userMessages: model.userMessages.length,
      durationMs,
      tools: toolCounts,
      turns: [...turns.values()],
    },
    policies: model.policy,
    generatedAt: new Date().toISOString(),
  }
}

/** Compact summary used by the composer badge. */
export function summarize(report) {
  if (report === null) return { findings: 0, riskLevel: '—', riskScore: 0, coverage: 'incomplete' }
  return {
    sessionId: report.sessionId,
    findings: report.counts?.confirmed ?? 0,
    pending: report.counts?.needsValidation ?? 0,
    riskLevel: report.riskLevel,
    riskScore: report.riskScore,
    coverage: report.coverage.state,
    covered: report.coverage.coveredSubcodes,
    total: report.coverage.totalSubcodes,
  }
}
