/**
 * Markdown report — derived strictly from verified records plus the ledger.
 * Nothing here is invented: confirmed items have evidence, pending items have
 * the missing fact, rejected items are listed with the reason they fell.
 */

import { ledgerTable } from './ledger.js'

const LINK = (sessionId, seq) => `#safety?session=${sessionId}&seq=${seq}`

function fmtTime(iso) {
  if (typeof iso !== 'string') return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function findingBlock(finding, sessionId, extra) {
  const lines = []
  lines.push(`### ${finding.code} ${finding.codeName}${finding.severity ? ` · ${finding.severity}` : ''}`)
  lines.push('')
  lines.push(`- 位置：事件 #${finding.seq}（[查看证据](${LINK(sessionId, finding.seq)})）`)
  lines.push(`- 规则：\`${finding.ruleId}\` · 置信度 ${finding.confidence}`)
  if (finding.affected !== null && finding.affected !== undefined) {
    lines.push(`- 受影响对象：${finding.affected.resource} — ${finding.affected.action}`)
  }
  if (extra !== undefined) lines.push(`- ${extra}`)
  lines.push('')
  lines.push('```text')
  lines.push(String(finding.evidence).slice(0, 600))
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

export function reportMarkdown(report, ledger) {
  const findings = report.findings ?? []
  const confirmed = findings.filter((item) => item.verdict === 'confirmed')
  const pending = findings.filter((item) => item.verdict === 'needs_validation')
  const rejected = findings.filter((item) => item.verdict === 'rejected')

  const lines = []
  lines.push(`# 安全巡检报告 · ${report.sessionId}`)
  lines.push('')
  lines.push(`- 生成时间：${fmtTime(report.generatedAt)}`)
  lines.push(`- 工作目录：\`${report.cwd ?? '—'}\``)
  lines.push(`- 事件 ${report.stats?.events ?? 0} 个 · 工具调用 ${report.stats?.toolCalls ?? 0} 次 · 失败 ${report.stats?.errors ?? 0} 次`)
  lines.push(`- 风险分：${report.riskScore}（${report.riskLevel}）`)
  lines.push('')
  lines.push('## 结论')
  lines.push('')
  lines.push(`- **已确认** ${confirmed.length} 条`)
  lines.push(`- **待验证** ${pending.length} 条（缺少关键事实，未给严重度）`)
  lines.push(`- **已排除** ${rejected.length} 条`)
  lines.push(`- 覆盖：${report.coverage?.coveredSubcodes ?? 0}/${report.coverage?.totalSubcodes ?? 0} 个子类（${report.coverage?.state ?? '—'}）`)
  lines.push('')
  if (pending.length > 0) {
    lines.push('> 待验证不等于安全：这些项命中了规则，但结论所需的事实不在日志里，需要人工或环境侧证据补充。')
    lines.push('')
  }

  lines.push('## 已确认的风险')
  lines.push('')
  if (confirmed.length === 0) {
    lines.push('本次没有可确认的违规。')
    lines.push('')
  } else {
    for (const finding of confirmed) lines.push(findingBlock(finding, report.sessionId))
  }

  lines.push('## 待验证')
  lines.push('')
  if (pending.length === 0) {
    lines.push('没有待验证项。')
    lines.push('')
  } else {
    for (const finding of pending) {
      lines.push(findingBlock(finding, report.sessionId, `缺少的事实：${finding.requiredFact}`))
    }
  }

  lines.push('## 已排除')
  lines.push('')
  if (rejected.length === 0) {
    lines.push('没有已排除项。')
    lines.push('')
  } else {
    for (const finding of rejected) {
      lines.push(`- \`${finding.code}\` #${finding.seq} — ${finding.rejectReason ?? '已排除'}`)
    }
    lines.push('')
  }

  lines.push('## 覆盖台账')
  lines.push('')
  lines.push(ledgerTable(ledger))
  lines.push('')
  lines.push('## 盲区')
  lines.push('')
  if ((report.blindSpots ?? []).length === 0) {
    lines.push('本次没有未覆盖的子类。')
  } else {
    for (const spot of report.blindSpots) {
      lines.push(`- \`${spot.code}\` ${spot.name} — 需要 ${(spot.detect ?? []).join(' / ') || '人工判断'}`)
    }
  }
  lines.push('')
  return lines.join('\n')
}

export function needsValidationMarkdown(report) {
  const pending = (report.findings ?? []).filter((item) => item.verdict === 'needs_validation')
  const lines = [`# 待验证清单 · ${report.sessionId}`, '', `共 ${pending.length} 条。每条只缺一个事实，补齐后才能定性。`, '']
  if (pending.length === 0) lines.push('没有待验证项。')
  for (const finding of pending) {
    lines.push(`## ${finding.code} ${finding.codeName} · #${finding.seq}`)
    lines.push('')
    lines.push(`- 缺少的事实：${finding.requiredFact}`)
    lines.push(`- 如何补：人工复查事件 #${finding.seq} 前后的工具调用与结果，或在该命令上加约束后重跑`)
    lines.push(`- 证据：[查看](${LINK(report.sessionId, finding.seq)})`)
    lines.push('')
    lines.push('```text')
    lines.push(String(finding.evidence).slice(0, 500))
    lines.push('```')
    lines.push('')
  }
  return lines.join('\n')
}
