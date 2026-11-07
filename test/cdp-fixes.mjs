// CDP checks for the three regressions reported in the desktop app:
//   1. an assistant message must show its TURN's calls, not "无工具调用"
//   2. the risk score must not be a meaningless 0
//   3. a finding row / severity chip must actually open something
// Usage: node test/cdp-fixes.mjs <appUrl> <token> <cdpBase> <sessionId>
const [appUrl, token, cdpBase = 'http://127.0.0.1:9333', sessionId = 'e3a7ff48-dc85-4d45-9a9d-8c94a1e4a0b8'] = process.argv.slice(2)
const apiBase = appUrl.replace(/\/\?.*$/, '')

const headers = { authorization: `Bearer ${token}` }
const report = await (await fetch(`${apiBase}/api/agent-safety/session?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()
const chain = await (await fetch(`${apiBase}/api/agent-safety/chain?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()
const data = report.report
const turns = chain.chain.turns
const withCalls = turns.find((turn) => (turn.calls || []).length > 0 && (turn.assistants || []).some((item) => item.id))
if (!withCalls) throw new Error('no turn with calls and an assistant message')
const messageId = withCalls.assistants[withCalls.assistants.length - 1].id
const turnCallCount = withCalls.calls.length
console.log(`fixture: T${withCalls.turn} calls=${turnCallCount} message=${messageId}`)
console.log(`risk: score=${data.riskScore} level=${data.riskLevel} critical=${data.counts.critical}`)

const targets = await (await fetch(cdpBase + '/json/list')).json()
const page = targets.find((t) => t.type === 'page')
const ws = new WebSocket(page.webSocketDebuggerUrl)
await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject })
let nextId = 1
const pending = new Map()
ws.onmessage = (event) => {
  const message = JSON.parse(event.data)
  if (message.id !== undefined && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id)
    pending.delete(message.id)
    if (message.error) reject(new Error(JSON.stringify(message.error)))
    else resolve(message.result)
  }
}
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = nextId++
  pending.set(id, { resolve, reject })
  ws.send(JSON.stringify({ id, method, params }))
})
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (result.exceptionDetails) throw new Error('eval failed: ' + JSON.stringify(result.exceptionDetails).slice(0, 300))
  return result.result.value
}
async function waitFor(expression, timeoutMs = 20000) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    try { const value = await evaluate(expression); if (value) return value } catch { /* retry */ }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error('timeout: ' + expression)
}
const results = []
const check = (name, ok, detail) => {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`)
}

await send('Page.enable')
await send('Runtime.enable')
await send('Page.navigate', { url: appUrl })
await waitFor("document.querySelector('style[data-plugin=\"dsh-safety-inspector\"]') !== null", 25000)

// 1 — risk score is meaningful
check('风险分不再是 0', data.riskScore > 0 && data.riskScore < 100, `${data.riskLevel} · ${data.riskScore}`)

// 2 — assistant message shows the turn chain
await evaluate(`(() => { history.replaceState(null, '', location.pathname + location.search); location.hash = '#safety?session=${sessionId}&message=${messageId}'; window.dispatchEvent(new HashChangeEvent('hashchange')); return true })()`)
await waitFor("document.querySelector('.sf-overlay .sf-drawer') !== null", 15000)
await waitFor("(() => { const b = document.querySelector('.sf-overlay .sf-drawer .body'); if (!b) return false; const t = b.innerText; return t.includes('次调用') && !t.includes('系统与收件'); })()", 25000)
const drawer = JSON.parse(await evaluate(`(() => {
  const el = document.querySelector('.sf-overlay .sf-drawer .body');
  const text = el.innerText;
  return JSON.stringify({
    text: text.slice(0, 400),
    calls: document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn').length,
    empty: text.includes('这一轮没有工具调用'),
    header: (text.match(/这条回答的执行链[^\\n]*/) || [''])[0],
  });
})()`))
check('消息深链显示本轮调用', drawer.empty !== true && drawer.calls > 0, drawer.header + ' · ' + drawer.calls + ' 个按钮')
check('不再出现「无工具调用」', drawer.empty !== true, '')
console.log('   drawer text:', drawer.text.replace(/\n/g, ' ⏎ ').slice(0, 220))

// 3 — panel: severity chip filters, finding row opens the drawer
await evaluate(`(() => { history.replaceState(null, '', location.pathname + location.search); window.dispatchEvent(new HashChangeEvent('hashchange')); return true })()`)
await new Promise((resolve) => setTimeout(resolve, 400))
const openedPanel = await evaluate(`(() => {
  const nodes = [...document.querySelectorAll('button,[role="button"],a')];
  const hit = nodes.find((node) => (node.getAttribute('aria-label') || node.textContent || '').trim() === '安全巡检' && node.offsetParent !== null);
  if (!hit) return false; hit.click(); return true;
})()`)
await waitFor("document.querySelector('.sf-root') !== null", 15000)
await waitFor("document.querySelectorAll('.sf-srow').length > 0", 20000)
// select the session under test (rows show the first 8 chars of the id)
const picked = await evaluate(`(() => {
  const rows = [...document.querySelectorAll('.sf-srow')];
  const hit = rows.find((row) => row.textContent.replace(/\\s/g, '').toLowerCase().includes('${sessionId.slice(0, 8)}'));
  if (!hit) return false;
  hit.click();
  return true;
})()`)
check('选中目标会话', picked === true, sessionId.slice(0, 8))
await waitFor("document.querySelector('.sf-heat') !== null && document.querySelectorAll('.sf-bar').length > 0", 25000)
check('面板可用', openedPanel === true, '')

const chip = await evaluate(`(() => {
  const nodes = [...document.querySelectorAll('.sf-chip')];
  const hit = nodes.find((node) => node.textContent.trim().startsWith('严重'));
  if (!hit) return false;
  hit.click();
  return true;
})()`)
await new Promise((resolve) => setTimeout(resolve, 600))
const filtered = JSON.parse(await evaluate(`(() => JSON.stringify({
  rows: document.querySelectorAll('.sf-finding').length,
  tab: [...document.querySelectorAll('.sf-tab')].find((n) => n.className.includes('on'))?.textContent ?? '',
}))()`))
check('点「严重」可筛选', chip === true && filtered.rows > 0, `${filtered.rows} 条 · tab=${filtered.tab}`)

const clickRow = await evaluate(`(() => {
  const row = document.querySelector('.sf-finding');
  if (!row) return false;
  row.click();
  return true;
})()`)
let drawer2 = false
try {
  drawer2 = await waitFor("document.querySelector('.sf-overlay .sf-drawer') !== null", 8000)
} catch { drawer2 = false }
const detailText = drawer2 ? await evaluate("document.querySelector('.sf-overlay .sf-drawer .body').innerText.slice(0, 300)") : ''
check('点发现打开详情浮层', drawer2 === true && detailText.length > 20, detailText.split('\n')[0] ?? '')

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
ws.close()
process.exit(failed.length === 0 ? 0 : 1)
