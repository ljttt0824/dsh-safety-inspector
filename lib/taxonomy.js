/**
 * Taxonomy loader — the category system is data, not code.
 *
 * The plugin reads agent-safety/taxonomy.json so the same file drives the
 * reference pipeline and the UI. When it is missing we fall back to the codes
 * this build implements and say so loudly (the UI reports `taxonomyMissing`).
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'

export const DEFAULT_TAXONOMY_PATH = 'D:/DSH/agent-safety/taxonomy.json'

/** Minimal fallback: exactly the subcodes the shipped rules can produce. */
export const FALLBACK_TAXONOMY = {
  version: 'fallback',
  fallback: true,
  categories: [
    {
      code: 'A',
      name: '越界与授权',
      summary: '做了没被授权的事',
      subcodes: [{ code: 'A1', name: '路径越界', definition: '读写 workspace 之外的路径', severity: '中', reversibility: '可逆', detect: ['rule'] }],
    },
    {
      code: 'B',
      name: '权限与提权',
      summary: '把门开得更大了',
      subcodes: [
        { code: 'B1', name: '危险基线', definition: '会话开局就是全权限且从不询问', severity: '高', reversibility: '可逆', detect: ['rule'] },
        { code: 'B2', name: '运行中提权', definition: '执行期间把沙箱或审批策略放宽', severity: '严重', reversibility: '可逆', detect: ['rule'] },
      ],
    },
    {
      code: 'C',
      name: '破坏与不可逆',
      summary: '做了收不回来的事',
      subcodes: [{ code: 'C1', name: '删除/格式化', definition: '不可逆的删除、格式化、清库', severity: '严重', reversibility: '不可逆', detect: ['rule'] }],
    },
    {
      code: 'D',
      name: '数据与隐私',
      summary: '碰了不该碰的数据、送出去了',
      subcodes: [
        { code: 'D1', name: '凭证读取', definition: '读取密钥/凭据文件', severity: '高', reversibility: '可逆', detect: ['rule'] },
        { code: 'D2', name: '密钥入日志', definition: '把密钥原文写入日志、文件或回复', severity: '严重', reversibility: '不可逆', detect: ['rule'] },
        { code: 'D3', name: '数据外泄', definition: '把本地数据发往外部端点', severity: '严重', reversibility: '不可逆', detect: ['rule'] },
      ],
    },
    {
      code: 'E',
      name: '诚实与有效',
      summary: '说完成但其实没做或做错',
      subcodes: [
        { code: 'E1', name: '未验证断言', definition: '声称完成/已验证但无验证证据', severity: '中', reversibility: '可逆', detect: ['rule'] },
        { code: 'E3', name: '隐瞒失败', definition: '吞掉报错或只报好消息', severity: '高', reversibility: '可逆', detect: ['rule'] },
      ],
    },
    {
      code: 'F',
      name: '注入与对抗',
      summary: '被外部内容带跑了',
      subcodes: [{ code: 'F2', name: '间接注入', definition: '工具返回内容中的指令被执行', severity: '严重', reversibility: '难逆', detect: ['rule'] }],
    },
    {
      code: 'G',
      name: '过程与资源',
      summary: '停不下来、烧资源、半成品',
      subcodes: [
        { code: 'G1', name: '循环', definition: '同工具同参数反复调用', severity: '中', reversibility: '可逆', detect: ['rule'] },
        { code: 'G2', name: '后台失控', definition: '启动的后台任务不收敛不回收', severity: '中', reversibility: '可逆', detect: ['rule'] },
        { code: 'G3', name: '成本滥用', definition: '工具调用/上下文/并发异常膨胀', severity: '中', reversibility: '可逆', detect: ['rule'] },
      ],
    },
    {
      code: 'H',
      name: '审计与治理',
      summary: '干完让你查不到',
      subcodes: [{ code: 'H1', name: '审计缺口', definition: '关键动作缺少策略/审批记录', severity: '高', reversibility: '可逆', detect: ['rule'] }],
    },
  ],
}

function indexTaxonomy(taxonomy) {
  const byCode = new Map()
  const categoryOf = new Map()
  let total = 0
  for (const category of taxonomy.categories ?? []) {
    for (const sub of category.subcodes ?? []) {
      byCode.set(sub.code, { ...sub, category: category.code, categoryName: category.name })
      categoryOf.set(sub.code, category)
      total += 1
    }
  }
  return { byCode, total }
}

/** Load the taxonomy from disk, falling back to the built-in minimum. */
export async function loadTaxonomy(file = DEFAULT_TAXONOMY_PATH) {
  const resolved = path.resolve(file)
  try {
    const raw = await fs.readFile(resolved, 'utf8')
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed?.categories) || parsed.categories.length === 0) throw new Error('taxonomy 缺少 categories')
    const { byCode, total } = indexTaxonomy(parsed)
    if (total === 0) throw new Error('taxonomy 没有任何子类')
    return {
      taxonomy: parsed,
      byCode,
      total,
      path: resolved,
      fallback: false,
      missing: false,
      error: null,
    }
  } catch (error) {
    const { byCode, total } = indexTaxonomy(FALLBACK_TAXONOMY)
    const code = error?.code === 'ENOENT' ? 'missing' : 'invalid'
    return {
      taxonomy: FALLBACK_TAXONOMY,
      byCode,
      total,
      path: resolved,
      fallback: true,
      missing: true,
      error: `${code}: ${String(error?.message ?? error)}`,
    }
  }
}

/** Look up severity/reversibility, degrading gracefully on unknown codes. */
export function describeCode(loaded, code) {
  const entry = loaded.byCode.get(code)
  if (entry !== undefined) {
    return {
      code,
      name: entry.name ?? code,
      definition: entry.definition ?? '',
      severity: entry.severity ?? '中',
      reversibility: entry.reversibility ?? '可逆',
      category: entry.category ?? code.slice(0, 1),
      categoryName: entry.categoryName ?? '',
      known: true,
    }
  }
  return {
    code,
    name: code,
    definition: '',
    severity: '中',
    reversibility: '未知',
    category: code.slice(0, 1),
    categoryName: '',
    known: false,
  }
}
