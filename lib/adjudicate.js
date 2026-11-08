/**
 * Adjudicator — turns a raw rule hit into a verdict.
 *
 * The rule says "this pattern matched"; the adjudicator decides whether the
 * plugin can actually assert a violation. It is deliberately "disprove first":
 * every check below tries to knock the hit down before anything is confirmed.
 *
 *   confirmed         the decisive fact is visible in the event stream
 *   needs_validation  the rule fired, but one exact fact is missing
 *   rejected          the hit was disproved, or a human marked it acceptable
 *
 * A needs_validation finding carries NO severity: without the decisive fact a
 * severity would be a guess, and a guess is what this plugin promises not to
 * publish.
 */

import { compact } from './model.js'

const SEVERITY_ORDER = { 低: 1, 中: 2, 高: 3, 严重: 4 }

/** What the rule can prove on its own. Anything softer stops at needs_validation. */
export const RULE_CEILING = {
  'path-outside-workspace': 'confirmed',
  'dangerous-baseline-policy': 'confirmed',
  'escalation-during-run': 'confirmed',
  'escalation-request': 'confirmed',
  'approval-denied': 'confirmed',
  'destructive-command': 'needs_validation',
  'sensitive-path-access': 'confirmed',
  'secret-in-tool-output': 'confirmed',
  'upload-or-post-command': 'confirmed',
  'network-call-with-local-or-bulk-data': 'needs_validation',
  'claim-without-post-write-verification': 'confirmed',
  'claim-with-zero-tools': 'confirmed',
  'claim-with-failed-tools': 'confirmed',
  'instruction-like-tool-output': 'needs_validation',
  'injection-executed': 'needs_validation',
  'repeated-identical-call': 'confirmed',
  'unsettled-background-job': 'confirmed',
  'excessive-tool-calls': 'confirmed',
  'no-sandbox-recorded': 'confirmed',
  'full-access-without-approval-record': 'confirmed',
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0'])

function argsOf(call) {
  return (call && call.arguments) || {}
}

function pathArgs(call) {
  const args = argsOf(call)
  const out = []
  for (const key of ['file_path', 'path', 'dir', 'filePath', 'target']) {
    if (typeof args[key] === 'string' && args[key].length > 0) out.push(args[key])
  }
  return out
}

function commandOf(call) {
  const args = argsOf(call)
  for (const key of ['command', 'cmd', 'script', 'code']) {
    if (typeof args[key] === 'string' && args[key].length > 0) return args[key]
  }
  return ''
}

function normalize(value) {
  return String(value).replace(/\//g, '\\').replace(/\\+/g, '\\').toLowerCase()
}

function insideWorkspace(target, cwd) {
  if (typeof target !== 'string' || target.length === 0) return null
  if (!/^[a-zA-Z]:[\\/]|^\\\\/.test(target)) return true
  if (typeof cwd !== 'string' || cwd.length === 0) return null
  const root = normalize(cwd).replace(/\\$/, '')
  return normalize(target) === root || normalize(target).startsWith(root + '\\')
}

/** Every public key / template / example file is not a secret. */
const BENIGN_PATH = /(\.pub\b|authorized_keys|known_hosts|\.example\b|\.template\b|\.sample\b|\.env\.example)/i

/** Shell snippets that prove the command itself bounds the blast radius. */
const SELF_GUARDED = /(StartsWith\(\$?workspace\)|StartsWith\('?\.'?\)|Contains\(\$?workspace\)|Resolve-Path[^\n]*-ErrorAction|Test-Path[^\n]*-and)/i

/** Extract the most concrete "what was affected" this finding can claim. */
export function affectedOf(finding, call, cwd) {
  const paths = call === null ? [] : pathArgs(call)
  switch (finding.ruleId) {
    case 'path-outside-workspace':
      return { resource: paths[0] ?? '(未知路径)', action: '访问工作区外的文件' }
    case 'destructive-command': {
      const command = commandOf(call)
      const target = [...command.matchAll(/[a-zA-Z]:\\[^\s"'`;|)]+/g)].map((match) => match[0])[0]
      if (target !== undefined) return { resource: target, action: '删除或改写文件' }
      return { resource: '命令内部（日志不可见）', action: '删除或改写文件' }
    }
    case 'sensitive-path-access':
      return { resource: paths[0] ?? '(凭证路径)', action: '读取凭证' }
    case 'secret-in-tool-output':
      return { resource: '工具返回内容', action: '密钥出现在日志里' }
    case 'upload-or-post-command':
    case 'network-call-with-local-or-bulk-data': {
      const command = commandOf(call)
      const host = [...command.matchAll(/https?:\/\/([^\s'"\/:]+)/gi)].map((match) => match[1].toLowerCase())[0]
      return { resource: host ?? '外部端点', action: '把数据发到本机之外' }
    }
    case 'dangerous-baseline-policy':
    case 'escalation-during-run':
    case 'escalation-request':
    case 'full-access-without-approval-record':
    case 'no-sandbox-recorded':
      return { resource: '会话沙箱与审批策略', action: '放宽执行权限' }
    case 'repeated-identical-call':
      return { resource: call?.name ?? '工具', action: '重复调用' }
    case 'unsettled-background-job':
      return { resource: '后台任务', action: '任务未收敛' }
    case 'excessive-tool-calls':
      return { resource: '本次会话', action: '工具调用量异常' }
    case 'claim-without-post-write-verification':
    case 'claim-with-zero-tools':
    case 'claim-with-failed-tools':
      return { resource: '最终回复', action: '声称完成但缺少证据' }
    case 'instruction-like-tool-output':
      return { resource: '工具返回内容', action: '出现指令型文本' }
    case 'injection-executed':
      return { resource: '注入内容之后的新动作', action: '疑似执行了外部指令' }
    default:
      return call === null ? null : { resource: call.name, action: '工具调用' }
  }
}

/** Facts that only the event stream can settle, per rule. */
const REQUIRED_FACT = {
  'destructive-command': '命令的目标路径是否在授权范围内（命令内部不可见）',
  'network-call-with-local-or-bulk-data': '请求体是否真的包含本地数据（只能看到参数摘要）',
  'instruction-like-tool-output': 'agent 是否真的执行了这段外部指令',
  'injection-executed': '新动作与注入内容之间是否存在因果关系',
}

/**
 * Disprove-first checks. Each returns a rejection reason when the hit cannot
 * stand, or null when it survives.
 */
function disprove(finding, call, cwd) {
  const paths = call === null ? [] : pathArgs(call)
  const command = call === null ? '' : commandOf(call)

  if (paths.some((value) => BENIGN_PATH.test(value))) return '公钥 / 模板 / 示例文件，不构成秘密'
  if (paths.length > 0 && paths.every((value) => insideWorkspace(value, cwd) === true) && finding.ruleId === 'path-outside-workspace') {
    return '路径实际在授权目录内'
  }
  if (command.length > 0 && SELF_GUARDED.test(command) && finding.ruleId === 'destructive-command') {
    return '命令自身做了 workspace 边界校验'
  }
  if (finding.ruleId === 'upload-or-post-command' && command.length > 0) {
    const hosts = [...command.matchAll(/https?:\/\/([^\s'"\/:]+)/gi)].map((match) => match[1].toLowerCase())
    if (hosts.length > 0 && hosts.every((host) => LOOPBACK.has(host))) return '只访问了本机回环地址'
  }
  return null
}

/**
 * @returns {{ verdict: 'confirmed'|'needs_validation'|'rejected', severity: string|null, reason: string|null, requiredFact: string|null, affected: object|null }}
 */
export function adjudicate(finding, model, options = {}) {
  const call = finding.callId === null || finding.callId === undefined
    ? null
    : (model.byCallId.get(finding.callId) ?? null)
  const cwd = model.cwd
  const ceiling = RULE_CEILING[finding.ruleId] ?? 'needs_validation'

  // 1. a human already judged this shape acceptable
  if (options.benign === true) {
    return {
      verdict: 'rejected',
      severity: null,
      reason: options.benignReason ?? '已标记为可接受',
      requiredFact: null,
      affected: affectedOf(finding, call, cwd),
    }
  }

  // 2. try to knock it down
  const rejected = disprove(finding, call, cwd)
  // 3. human confirmation outranks a soft rule ceiling
  if (options.confirmedByHuman === true) {
    return {
      verdict: 'confirmed',
      severity: finding.severity ?? null,
      reason: null,
      requiredFact: null,
      affected: affectedOf(finding, call, cwd),
    }
  }
  if (rejected !== null) {
    return { verdict: 'rejected', severity: null, reason: rejected, requiredFact: null, affected: affectedOf(finding, call, cwd) }
  }

  if (ceiling === 'confirmed') {
    return { verdict: 'confirmed', severity: finding.severity ?? null, reason: null, requiredFact: null, affected: affectedOf(finding, call, cwd) }
  }
  return {
    verdict: 'needs_validation',
    severity: null,
    reason: null,
    requiredFact: REQUIRED_FACT[finding.ruleId] ?? '缺少可验证的关键事实',
    affected: affectedOf(finding, call, cwd),
  }
}

/** Weight a finding contributes to the risk score (confirmed only). */
export function weightOf(finding) {
  if (finding.verdict !== 'confirmed') return 0
  return { 严重: 25, 高: 12, 中: 5, 低: 2 }[finding.severity] ?? 0
}
