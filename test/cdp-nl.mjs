// Browser checks for the plain-language layer, failure affordance and the
// opt-in AI button. Usage: node test/cdp-nl.mjs <appUrl> <token> <cdpBase> <sessionId>
const [appUrl, token, cdpBase = 'http://127.0.0.1:9333', sessionId = '8aa373c4-264d-4d23-9afe-c8b37d4a39d4'] = process.argv.slice(2)
const apiBase = appUrl.replace(/\/\?.*$/, '')
const headers = { authorization: `Bearer ${token}` }

const chainRes = await (await fetch(`${apiBase}/api/agent-safety/chain?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()
const chain = chainRes.chain
const failTurn = chain.turns.find((turn) => (turn.calls || []).some((call) => call.isError === true))
if (!failTurn) throw new Error('no failing call in this session')
const failCall = failTurn.calls.find((call) => call.isError === true)
const failSteps = chain.turns.filter((turn) => (turn.calls || []).some((call) => call.isError === true)).length
console.log(`fixture: T${failTurn.turn} failStep=S${failCall.step} ${failCall.name} · failing steps=${failSteps}`)

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
async function waitFor(expression, timeoutMs = 25000) {
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
await waitFor("document.querySelector('style[data-plugin=\"dsh-safety-inspector\"]') !== null", 30000)

// open panel on the target session
await evaluate(`(() => {
  const nodes = [...document.querySelectorAll('button,[role="button"],a')];
  const hit = nodes.find((n) => (n.getAttribute('aria-label') || n.textContent || '').trim() === '安全巡检' && n.offsetParent !== null);
  if (hit) hit.click(); return true;
})()`)
await waitFor("document.querySelectorAll('.sf-srow').length > 0", 25000)
await evaluate(`(() => {
  const rows = [...document.querySelectorAll('.sf-srow')];
  const hit = rows.find((r) => r.textContent.replace(/\\s/g, '').toLowerCase().includes('${sessionId.slice(0, 8)}'));
  if (hit) hit.click(); return true;
})()`)
await waitFor("document.querySelectorAll('.sf-bar').length > 0", 25000)
await evaluate(`(() => { const tab = [...document.querySelectorAll('.sf-tab')].find((n) => n.textContent.includes('执行链')); if (tab) tab.click(); return true })()`)
await waitFor("document.querySelectorAll('.sf-step').length > 0", 25000)

// 1. steps carry a plain-language headline instead of a tool list
const stepText = await evaluate(`(() => {
  const step = document.querySelector('.sf-step.on') || document.querySelector('.sf-step');
  const head = step.querySelector('.hd') ? step.querySelector('.hd').innerText : '';
  const tail = step.querySelector('.tl') ? step.querySelector('.tl').innerText : '';
  return JSON.stringify({ head, tail });
})()`)
const parsedStep = JSON.parse(stepText)
check('步骤显示自然语言摘要', /读|执行|写|访问|搜索|列/.test(parsedStep.tail) && !/^[\w-]+( [\w-]+)*$/.test(parsedStep.tail.trim()), parsedStep.tail.slice(0, 60))

// 2. the failing step is marked
const failMark = await evaluate(`(() => {
  const badges = [...document.querySelectorAll('.sf-badge-fail')];
  return JSON.stringify({ count: badges.length, text: badges[0] ? badges[0].textContent : '' });
})()`)
const failState = JSON.parse(failMark)
check('失败的那一步有标记', failState.count > 0 && failState.text.includes('失败'), `${failState.count} 处`)

// 3. only-failed filter jumps to it
await evaluate(`(() => { const btn = [...document.querySelectorAll('.sf-btn')].find((b) => b.textContent.includes('只看失败')); if (btn) btn.click(); return true })()`)
await new Promise((resolve) => setTimeout(resolve, 500))
const filtered = await evaluate("document.querySelectorAll('.sf-step').length")
check('只看失败可过滤', filtered === failSteps, filtered + ' 步 / 期望 ' + failSteps)

// 4. inspector shows request/result/risk in words, and raw is available
const inspector = JSON.parse(await evaluate(`(() => {
  const el = document.querySelector('.sf-insp');
  const text = el ? el.innerText : '';
  return JSON.stringify({ text: text.slice(0, 700), hasRisk: /风险判定/.test(text), hasRawToggle: /看原始数据/.test(text) });
})()`))
check('Inspector 用通俗语言', inspector.hasRisk === true && /访问的数据/.test(inspector.text), '')
console.log('   inspector:', inspector.text.replace(/\n/g, ' ⏎ ').slice(0, 320))

const toggled = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-insp .sf-btn')].find((b) => b.textContent.includes('看原始数据'));
  if (!btn) return false;
  btn.click();
  return true;
})()`)
await new Promise((resolve) => setTimeout(resolve, 400))
const rawShown = await evaluate("document.querySelectorAll('.sf-insp .sf-code-box').length")
check('可切换看原始数据', toggled === true && rawShown > 0, rawShown + ' 个代码块')

// 5. AI button exists and is opt-in
const aiButton = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-btn')].find((b) => b.textContent.includes('AI 详细分析'));
  return btn ? btn.textContent : '';
})()`)
check('AI 分析按钮存在且标注消耗 token', aiButton.includes('消耗 token'), aiButton)

await evaluate(`(() => { const btn = [...document.querySelectorAll('.sf-btn')].find((b) => b.textContent.includes('AI 详细分析')); if (btn) btn.click(); return true })()`)
let analysisShown = false
try {
  analysisShown = await waitFor("document.querySelector('.sf-insp').innerText.includes('本次消耗')", 40000)
} catch { analysisShown = false }
const analysisText = analysisShown
  ? await evaluate("(document.querySelector('.sf-insp').innerText.match(/本次消耗[^\\n]*/) || [''])[0]")
  : ''
check('点击后展示 AI 分析与 token 用量', analysisShown === true, analysisText)

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
ws.close()
process.exit(failed.length === 0 ? 0 : 1)
