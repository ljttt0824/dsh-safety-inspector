/**
 * Narrator — turn raw tool calls into plain-language statements, locally.
 *
 * This layer is deterministic and costs **zero tokens**: it never calls a
 * model. It answers the four questions a non-technical reader actually has:
 * what did this step try to do, what data did it touch, what came back, and is
 * there a risk. The LLM layer (lib/analyze.js) is opt-in and sits on top.
 */

const TOOL_LABEL = {
  read: '读取文件',
  write: '写入文件',
  edit: '修改文件',
  append: '追加内容',
  glob: '按文件名查找',
  grep: '按内容搜索文件',
  list_files: '列出目录',
  pwsh: '执行命令',
  bash: '执行命令',
  shell: '执行命令',
  web_search: '联网搜索',
  web_fetch: '打开网页',
  read_image: '查看图片',
  job_output: '读取后台任务输出',
  job_kill: '停止后台任务',
  todo_write: '更新任务清单',
  ask_user_question: '向用户提问',
  safety_audit: '安全巡检',
  knowledge_index: '读取知识库索引',
  knowledge_read: '读取知识库页面',
  knowledge_search: '搜索知识库',
  knowledge_graph: '读取知识图谱',
  career_status: '查看职业库状态',
  career_index: '读取职业库索引',
  career_search: '搜索职业库',
  present: '展示文件',
}

const COMMAND_INTENT = [
  [/\bgit\s+(status|diff|log|show|branch)\b/i, '查看代码库状态'],
  [/\bgit\s+(commit|push|pull|fetch)\b/i, '同步代码库'],
  [/\bgit\s+reset\s+--hard\b/i, '丢弃本地改动'],
  [/\b(npm|pnpm|yarn|bun)\s+(install|add|i)\b/i, '安装依赖'],
  [/\b(npm|pnpm|yarn|bun)\s+(run\s+)?(test|vitest|jest)\b/i, '运行测试'],
  [/\b(npm|pnpm|yarn|bun)\s+(run\s+)?(build|lint|typecheck)\b/i, '构建或检查代码'],
  [/\b(node|python|py)\s/i, '运行脚本'],
  [/\b(Get-ChildItem|ls|dir)\b/i, '列出目录内容'],
  [/\b(Select-String|grep|rg)\b/i, '在文本中搜索'],
  [/\b(Remove-Item|rm|del)\b/i, '删除文件或目录'],
  [/\b(Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b/i, '发送网络请求'],
  [/\b(Start-Process|Start-Job|nohup)\b/i, '启动后台进程'],
  [/\b(Stop-Process|kill|taskkill)\b/i, '结束进程'],
  [/\bCopy-Item|cp\b/i, '复制文件'],
  [/\bMove-Item|mv\b/i, '移动文件'],
  [/\bGet-Content|cat|type\b/i, '查看文件内容'],
  [/\bTest-Path|Get-Item|stat\b/i, '检查文件是否存在'],
]

const RISK_ORDER = { none: 0, 低: 1, 中: 2, 高: 3, 严重: 4 }
const SEVERITY_TO_RISK = { 低: '低', 中: '中', 高: '高', 严重: '严重', info: 'none' }

function firstLine(text, limit = 120) {
  const value = String(text ?? '').replace(/\r/g, '').trim()
  if (value.length === 0) return ''
  const line = value.split('\n')[0]
  return line.length > limit ? line.slice(0, limit) + '…' : line
}

function isLoopback(value) {
  return /^(127\.0\.0\.1|localhost|::1|0\.0\.0\.0)$/i.test(String(value ?? '').replace(/^\[|\]$/g, ''))
}

function hostOf(url) {
  try { return new URL(url).host } catch { return '' }
}

/** Recognize the intent behind a shell command, without reading its output. */
export function commandIntent(command) {
  const text = String(command ?? '')
  for (const [pattern, label] of COMMAND_INTENT) {
    if (pattern.test(text)) return label
  }
  return '执行一条命令'
}

function pathBase(value) {
  const text = String(value ?? '')
  const parts = text.split(/[\\/]/).filter(Boolean)
  return parts.length > 0 ? parts[parts.length - 1] : text
}

function insideWorkspace(target, cwd) {
  if (typeof target !== 'string' || target.length === 0) return null
  if (!/^[a-zA-Z]:[\\/]|^\\\\/.test(target)) return true
  if (typeof cwd !== 'string' || cwd.length === 0) return null
  const norm = (value) => value.replace(/\//g, '\\').replace(/\\+/g, '\\').toLowerCase()
  const root = norm(cwd).replace(/\\$/, '')
  return norm(target).startsWith(root + '\\') || norm(target) === root
}

/** Build the plain-language description of one tool call. */
export function narrateCall(call, options = {}) {
  const cwd = options.cwd ?? ''
  const findings = options.findings ?? []
  const args = call.arguments ?? {}
  const label = TOOL_LABEL[call.name] ?? (call.name ? `调用 ${call.name}` : '调用工具')

  const reads = []
  const writes = []
  const queries = []
  const domains = []
  const commands = []

  for (const key of ['file_path', 'path', 'dir', 'filePath', 'target']) {
    const value = args[key]
    if (typeof value !== 'string' || value.length === 0) continue
    if (['write', 'edit', 'append'].includes(call.name)) writes.push(value)
    else reads.push(value)
  }
  for (const key of ['query', 'pattern', 'q']) {
    if (typeof args[key] === 'string' && args[key].length > 0) queries.push(args[key])
  }
  for (const key of ['url', 'uri']) {
    if (typeof args[key] === 'string' && args[key].length > 0) domains.push(hostOf(args[key]) || args[key])
  }
  for (const key of ['command', 'cmd', 'script', 'code']) {
    if (typeof args[key] === 'string' && args[key].length > 0) commands.push(args[key])
  }

  const command = commands[0] ?? ''
  const action = command.length > 0 ? commandIntent(command) : label

  // A command body may embed secrets, so only its shape is surfaced:
  // which hosts it talks to, which file names it mentions.
  const commandHosts = command.length > 0
    ? [...command.matchAll(/https?:\/\/([^\s'"`<>)]+)/gi)].map((match) => hostOf(match[1]) || match[1].split('/')[0])
    : []
  const commandFiles = command.length > 0
    ? [...command.matchAll(/[A-Za-z]:\\\\[^\\s'\"`;|)]+/g)].map((match) => pathBase(match[0]))
    : []
  for (const host of commandHosts) if (!domains.includes(host)) domains.push(host)

  const outside = [...reads, ...writes].filter((target) => insideWorkspace(target, cwd) === false)

  const request = (() => {
    if (command.length > 0) {
      const hosts = commandHosts.filter((host) => host.length > 0)
      if (hosts.length > 0) return `${action}（访问 ${[...new Set(hosts)].slice(0, 3).join('、')}）`
      if (commandFiles.length > 0) return `${action}（涉及 ${[...new Set(commandFiles)].slice(0, 3).join('、')}）`
      return action
    }
    if (reads.length > 0) return `${label} ${reads.map(pathBase).join('、')}`
    if (writes.length > 0) return `${label} ${writes.map(pathBase).join('、')}`
    if (queries.length > 0) return `${label}「${firstLine(queries[0], 60)}」`
    if (domains.length > 0) return `${label} ${domains.join('、')}`
    return label
  })()

  const resultText = String(call.resultText ?? '')
  const result = (() => {
    if (call.isError === true) {
      const reason = firstLine(resultText, 100)
      return { status: 'failed', kind: '执行失败', detail: reason.length > 0 ? reason : '工具报告失败' }
    }
    if (call.resultText === null || call.resultText === undefined) {
      return { status: 'unknown', kind: '没有记录到结果', detail: '' }
    }
    if (resultText.trim().length === 0) return { status: 'empty', kind: '成功，但没有任何输出', detail: '' }
    return { status: 'ok', kind: '成功', detail: `返回 ${resultText.length} 个字符的文本` }
  })()

  // Risk comes from the rule findings anchored at this call, plus the cheap
  // structural signals the rules already rely on.
  const own = findings.filter((item) => item.callId === call.callId)
  let level = 'none'
  for (const item of own) {
    const mapped = SEVERITY_TO_RISK[item.severity] ?? 'none'
    if (RISK_ORDER[mapped] > RISK_ORDER[level]) level = mapped
  }
  const codes = [...new Set(own.map((item) => item.code))].sort()
  const sensitive = codes.some((code) => code.startsWith('D')) || /\.(env|pem|key)$|id_rsa|credentials/i.test([...reads, ...writes].join(' '))
  const compliant = level === 'none' || level === '低'

  const reasons = []
  if (own.length > 0) {
    reasons.push(own.map((item) => `${item.code} ${item.codeName}`).join('；'))
  } else {
    reasons.push('本步未命中任何规则')
  }
  if (outside.length > 0) reasons.push(`${outside.length} 个路径在 workspace 之外`)
  if (domains.length > 0) reasons.push(domains.every(isLoopback) ? '只访问了本机地址' : '访问了外部地址')
  if (command.length > 0 && reads.length === 0 && writes.length === 0) reasons.push('命令内部的文件访问无法从日志判断')

  let verdict = '未发现风险'
  if (level === '严重') verdict = '有严重风险，不应该这样做'
  else if (level === '高') verdict = '有较高风险，需要人工确认'
  else if (level === '中') verdict = '有轻微风险，属于边界行为'
  else if (level === '低') verdict = '基本合规'
  if (own.length === 0) verdict = '规则未发现风险（不等于已证明安全）'

  return {
    callId: call.callId,
    seq: call.callSeq,
    tool: call.name,
    toolLabel: label,
    action,
    request,
    result,
    access: {
      reads,
      writes,
      queries,
      domains,
      command: command.length > 0 ? firstLine(command, 120) : '',
    },
    risk: {
      level,
      verdict,
      compliant,
      sensitive,
      codes,
      reasons,
    },
  }
}

/** Aggregate a whole step (or turn) into one sentence plus the worst risk. */
export function narrateGroup(calls, options = {}) {
  const items = calls.map((call) => narrateCall(call, options))
  if (items.length === 0) {
    return { items, headline: '这一步没有调用工具', level: 'none', failures: 0 }
  }
  const failures = items.filter((item) => item.result.status === 'failed').length
  let level = 'none'
  for (const item of items) {
    if (RISK_ORDER[item.risk.level] > RISK_ORDER[level]) level = item.risk.level
  }
  const verbs = [...new Set(items.map((item) => item.action))]
  const headline = items.length === 1
    ? items[0].request
    : (verbs.length === 1
        ? `${verbs[0]} ×${items.length}`
        : `${verbs.slice(0, 3).join('、')}${verbs.length > 3 ? ' 等' : ''}，共 ${items.length} 个动作`)
  return { items, headline, level, failures }
}
