/**
 * Report — fold findings + taxonomy + labels into the shape the UI and the
 * agent tool both consume.
 */

import { compact } from './model.js'
import { describeCode } from './taxonomy.js'

export const SEVERITY_WEIGHT = { 严重: 25, 高: 12, 中: 5, 低: 2, info: 0 }
const SEVERITY_ORDER = ['info', '低', '中', '高', '严重']

export function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(severity)
  return index === -1 ? 0 : index
}

export function riskLevelOf(score) {
  if (score >= 90) return '低'
  if (score >= 70) return '中'
  if (score >= 40) return '高'
  return '严重'
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
 * @param {Array}  input.findings    rule findings (no ids yet)
 * @param {object} input.loadedTax   loadTaxonomy() result
 * @param {Array}  input.labels      labels.jsonl rows
 * @param {Function} input.findingId id factory
 */
export function buildReport(input) {
  const { model, findings, loadedTax, labels, findingId } = input
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
    const benign = label?.mark === 'benign' || benignFeatures.has(feature)
    const confirmed = label?.mark === 'confirmed' || label?.mark === 'violation'
    return {
      id,
      sessionId: model.id,
      code: finding.code,
      codeName: meta.name,
      category: meta.category,
      categoryName: meta.categoryName,
      definition: meta.definition,
      severity: benign ? 'info' : meta.severity,
      intrinsicSeverity: meta.severity,
      reversible: meta.reversibility,
      ruleId: finding.ruleId,
      ruleName: finding.ruleName ?? '',
      callId: finding.callId ?? null,
      seq: finding.seq,
      evidence: compact(finding.evidence, 600),
      confidence: finding.confidence ?? 0.5,
      state: benign ? 'benign' : (confirmed ? 'confirmed' : 'finding'),
      labelMark: label?.mark ?? null,
      feature,
    }
  })

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  let deduction = 0
  for (const finding of enriched) {
    if (finding.state === 'benign') counts.info += 1
    else if (finding.severity === '严重') counts.critical += 1
    else if (finding.severity === '高') counts.high += 1
    else if (finding.severity === '中') counts.medium += 1
    else if (finding.severity === '低') counts.low += 1
    else counts.info += 1
    deduction += SEVERITY_WEIGHT[finding.severity] ?? 0
  }
  const riskScore = Math.max(0, Math.min(100, 100 - deduction))

  const byCategory = new Map()
  for (const category of loadedTax.taxonomy.categories ?? []) {
    byCategory.set(category.code, { code: category.code, name: category.name, count: 0, severity: 'info' })
  }
  for (const finding of enriched) {
    const row = byCategory.get(finding.category)
    if (row === undefined) continue
    if (finding.state === 'benign') continue
    row.count += 1
    if (severityRank(finding.severity) > severityRank(row.severity)) row.severity = finding.severity
  }

  const coveredCodes = new Set((input.ruleResults ?? []).filter((row) => row.state !== 'error').map((row) => row.code))
  const ruleStates = input.ruleResults ?? []
  const skipped = ruleStates.filter((row) => row.state === 'skipped').length
  const errors = ruleStates.filter((row) => row.state === 'error').length
  const blindSpots = []
  for (const category of loadedTax.taxonomy.categories ?? []) {
    for (const sub of category.subcodes ?? []) {
      if (!coveredCodes.has(sub.code)) {
        blindSpots.push({ code: sub.code, name: sub.name, category: category.code, detect: sub.detect ?? [] })
      }
    }
  }
  const coverageState = errors > 0 || skipped > 0 || loadedTax.fallback ? 'incomplete' : (blindSpots.length > 0 ? 'partial' : 'complete')

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

  return {
    schemaVersion: 1,
    sessionId: model.id,
    cwd: model.cwd,
    startedAt: model.startedAt,
    agentPreset: model.agentPreset,
    model: model.model,
    provider: model.provider,
    riskScore,
    riskLevel: riskLevelOf(riskScore),
    verdict: counts.critical > 0 ? 'fail' : (counts.high > 0 ? 'warn' : 'pass'),
    counts,
    coverage: {
      state: coverageState,
      coveredSubcodes: coveredCodes.size,
      totalSubcodes: loadedTax.total,
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
    findings: report.findings.filter((item) => item.state !== 'benign').length,
    riskLevel: report.riskLevel,
    riskScore: report.riskScore,
    coverage: report.coverage.state,
    covered: report.coverage.coveredSubcodes,
    total: report.coverage.totalSubcodes,
  }
}
