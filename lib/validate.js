/**
 * Report validator — the invariants as code, not as a promise in the README.
 *
 * Runs at the end of every scan. A report that fails here is not published as
 * a normal result: the scan degrades to `error`, because an internally
 * inconsistent report is worse than an obviously missing one.
 */

const VERDICTS = new Set(['confirmed', 'needs_validation', 'rejected'])
const SEVERITIES = new Set(['严重', '高', '中', '低'])

/**
 * @param {object} report   the assembled report
 * @param {object} model    normalized session (for seq anchors)
 * @param {object} ledger   buildLedger() result
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateReport(report, model, ledger) {
  const errors = []
  const findings = report.findings ?? []

  const ids = new Set()
  for (const finding of findings) {
    if (typeof finding.id !== 'string' || finding.id.length === 0) errors.push('发现缺少 id')
    if (ids.has(finding.id)) errors.push(`发现 id 重复: ${finding.id}`)
    ids.add(finding.id)

    if (!VERDICTS.has(finding.verdict)) errors.push(`${finding.id}: 未知判定 ${finding.verdict}`)
    if (!Number.isInteger(finding.seq) || !model.bySeq.has(finding.seq)) {
      errors.push(`${finding.id}: seq ${finding.seq} 不在事件流里`)
    }
    if (finding.verdict === 'needs_validation') {
      if (finding.severity !== null) errors.push(`${finding.id}: 待验证的发现不得带严重度`)
      if (typeof finding.requiredFact !== 'string' || finding.requiredFact.length === 0) {
        errors.push(`${finding.id}: 待验证的发现必须写明缺少的事实`)
      }
    }
    if (finding.verdict === 'confirmed') {
      if (!SEVERITIES.has(finding.severity)) errors.push(`${finding.id}: 已确认的发现必须有严重度`)
      if (finding.affected === null || typeof finding.affected?.resource !== 'string' || finding.affected.resource.length === 0) {
        errors.push(`${finding.id}: 已确认的发现必须写明受影响的对象`)
      }
    }
    if (finding.verdict === 'rejected') {
      if (finding.severity !== null) errors.push(`${finding.id}: 已排除的发现不得带严重度`)
      if (typeof finding.rejectReason !== 'string' || finding.rejectReason.length === 0) {
        errors.push(`${finding.id}: 已排除的发现必须写明理由`)
      }
    }
    if (typeof finding.evidence !== 'string' || finding.evidence.length === 0) errors.push(`${finding.id}: 缺少证据`)
  }

  const totals = ledger?.totals ?? {}
  const sum = (totals.covered ?? 0) + (totals.partial ?? 0) + (totals.uncovered ?? 0) + (totals.error ?? 0)
  if (sum !== totals.total) errors.push(`台账合计不一致: ${sum} !== ${totals.total}`)
  if (totals.total !== (report.coverage?.totalSubcodes ?? -1)) {
    errors.push(`台账子类数 ${totals.total} 与报告 ${report.coverage?.totalSubcodes} 不一致`)
  }
  if ((report.coverage?.coveredSubcodes ?? -1) !== (totals.covered ?? 0) + (totals.partial ?? 0)) {
    errors.push('覆盖数与台账不一致')
  }
  if ((totals.error ?? 0) > 0 && report.coverage?.state === 'complete') {
    errors.push('有规则异常却声明覆盖完整')
  }
  if (report.coverage?.taxonomyFallback === true && report.coverage?.state === 'complete') {
    errors.push('分类体系回退却声明覆盖完整')
  }

  const confirmed = findings.filter((item) => item.verdict === 'confirmed').length
  const pending = findings.filter((item) => item.verdict === 'needs_validation').length
  const rejected = findings.filter((item) => item.verdict === 'rejected').length
  const counts = report.counts ?? {}
  if ((counts.confirmed ?? -1) !== confirmed) errors.push('确认数与发现列表不一致')
  if ((counts.needsValidation ?? -1) !== pending) errors.push('待验证数与发现列表不一致')
  if ((counts.rejected ?? -1) !== rejected) errors.push('已排除数与发现列表不一致')

  if (!Number.isFinite(report.riskScore) || report.riskScore < 0 || report.riskScore > 100) {
    errors.push(`风险分越界: ${report.riskScore}`)
  }

  return { ok: errors.length === 0, errors }
}
