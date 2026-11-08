/**
 * Coverage ledger — what this run actually checked, per taxonomy subcode.
 *
 * Four states, and the difference matters:
 *   covered    a rule that can prove a violation ran clean
 *   partial    a rule ran, but by construction it can only reach needs_validation
 *   uncovered  nothing in this build can judge it
 *   error      the rule threw; silence is not coverage
 */

import { RULE_CEILING } from './adjudicate.js'

const STATE_LABEL = {
  covered: '已覆盖',
  partial: '只能部分判定',
  uncovered: '未覆盖',
  error: '规则异常',
}

/**
 * @param {object} loadedTax  loadTaxonomy() result
 * @param {Array} ruleResults runRules() results: [{ruleId, code, state, error}]
 * @param {Array} findings    adjudicated findings (for hit counts)
 */
export function buildLedger(loadedTax, ruleResults, findings) {
  const byCode = new Map()
  for (const result of ruleResults ?? []) {
    const entry = byCode.get(result.code) ?? { ruleIds: [], states: [], errors: [] }
    entry.ruleIds.push(result.ruleId)
    entry.states.push(result.state)
    if (result.error !== undefined) entry.errors.push(result.error)
    byCode.set(result.code, entry)
  }

  const hits = new Map()
  for (const finding of findings ?? []) {
    if (finding.verdict === 'rejected') continue
    hits.set(finding.code, (hits.get(finding.code) ?? 0) + 1)
  }

  const rows = []
  for (const category of loadedTax.taxonomy.categories ?? []) {
    for (const sub of category.subcodes ?? []) {
      const entry = byCode.get(sub.code)
      let state
      let note = ''
      if (entry === undefined) {
        state = 'uncovered'
        note = (sub.detect ?? []).length > 0 ? `需要 ${(sub.detect ?? []).join(' / ')}` : '本版本没有对应规则'
      } else if (entry.states.includes('error')) {
        state = 'error'
        note = entry.errors[0] ?? '规则执行失败'
      } else {
        const soft = entry.ruleIds.filter((id) => (RULE_CEILING[id] ?? 'needs_validation') !== 'confirmed')
        state = soft.length === entry.ruleIds.length ? 'partial' : 'covered'
        if (state === 'partial') note = '规则只能判定到「待验证」'
      }
      rows.push({
        code: sub.code,
        name: sub.name ?? sub.code,
        category: category.code,
        categoryName: category.name,
        state,
        stateLabel: STATE_LABEL[state] ?? state,
        hits: hits.get(sub.code) ?? 0,
        ruleIds: entry?.ruleIds ?? [],
        note,
      })
    }
  }

  const totals = { covered: 0, partial: 0, uncovered: 0, error: 0 }
  for (const row of rows) totals[row.state] += 1
  const judgeable = totals.covered + totals.partial

  return {
    rows,
    totals: { ...totals, total: rows.length },
    coverage: {
      state: totals.uncovered === 0 && totals.partial === 0 && totals.error === 0 ? 'complete' : 'partial',
      coveredSubcodes: judgeable,
      totalSubcodes: rows.length,
    },
  }
}

/** One line per subcode, for the markdown report's coverage table. */
export function ledgerTable(ledger) {
  const lines = ['| 子类 | 名称 | 状态 | 命中 | 说明 |', '|---|---|---|---|---|']
  for (const row of ledger.rows) {
    lines.push(`| ${row.code} | ${row.name} | ${row.stateLabel} | ${row.hits} | ${row.note || ''} |`)
  }
  return lines.join('\n')
}
