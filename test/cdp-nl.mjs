// Plain-language checks, now against the answer overlay (the panel no longer
// carries a per-turn chain). Usage:
//   node test/cdp-nl.mjs <appUrl> <token> <cdpBase> <sessionId>
const [appUrl, token, cdpBase = 'http://127.0.0.1:9333', sessionId = '8aa373c4-264d-4d23-9afe-c8b37d4a39d4'] = process.argv.slice(2)
const apiBase = appUrl.split('?')[0].replace(/\/$/, '')
const headers = { authorization: `Bearer ${token}` }

const chain = (await (await fetch(`${apiBase}/api/agent-safety/chain?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()).chain
const failTurn = chain.turns.find((turn) => (turn.calls || []).some((call) => call.isError === true))
if (!failTurn) throw new Error('no failing call in this session')
const failCall = failTurn.calls.find((call) => call.isError === true)
console.log(`fixture: T${failTurn.turn} failStep=S${failCall.step} ${failCall.name}`)

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

await evaluate(`(() => { location.hash = '#safety?session=${sessionId}&turn=${failTurn.turn}'; window.dispatchEvent(new HashChangeEvent('hashchange')); return true })()`)
await waitFor("document.querySelector('.sf-overlay .sf-drawer') !== null", 20000)
await waitFor("document.querySelectorAll('.sf-overlay .sf-drawer .sf-card').length > 1", 25000)

const text = await evaluate("document.querySelector('.sf-overlay .sf-drawer .body').innerText")
check('请求 / 结果 用自然语言', text.includes('请求') && text.includes('结果') && !text.includes('{"command"'), text.replace(/\n/g, ' ⏎ ').slice(0, 150))
check('访问的数据可见', text.includes('访问的数据'), '')
check('风险判定可见', text.includes('风险判定'), '')

const failedChip = await evaluate(`(() => {
  const chip = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')].find((b) => b.textContent.includes('✕'));
  return chip ? JSON.stringify({ text: chip.textContent.trim(), border: chip.style.borderColor }) : '';
})()`)
const failState = failedChip === '' ? { text: '', border: '' } : JSON.parse(failedChip)
check('失败调用用红色标出', failState.text !== '' && /e5484d|229, 72, 77/.test(failState.border), `${failState.text} ${failState.border}`)

const failureRow = await evaluate("(document.querySelector('.sf-overlay .sf-drawer .body').innerText.match(/失败的那一步[^\\n]*/) || [''])[0]")
check('有「失败的那一步」快捷入口', failureRow.includes('失败的那一步'), failureRow.slice(0, 60))

const toggled = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')].find((b) => b.textContent.includes('看原始数据'));
  if (!btn) return false;
  btn.click();
  return true;
})()`)
await new Promise((resolve) => setTimeout(resolve, 500))
const rawShown = await evaluate("document.querySelectorAll('.sf-overlay .sf-drawer .sf-code-box').length")
check('可切换看原始数据', toggled === true && rawShown > 0, rawShown + ' 个代码块')

const aiButton = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')].find((b) => b.textContent.includes('AI 详细分析'));
  return btn ? btn.textContent.trim() : '';
})()`)
check('AI 按钮标注消耗 token', aiButton.includes('消耗 token'), aiButton)

await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')].find((b) => b.textContent.includes('AI 详细分析'));
  if (btn) btn.click();
  return true;
})()`)
let analysisShown = false
try {
  analysisShown = await waitFor("document.querySelector('.sf-overlay .sf-drawer').innerText.includes('本次消耗')", 45000)
} catch { analysisShown = false }
const usage = analysisShown
  ? await evaluate("(document.querySelector('.sf-overlay .sf-drawer').innerText.match(/本次消耗[^\\n]*/) || [''])[0]")
  : ''
check('点击后展示 AI 分析与 token 用量', analysisShown === true, usage)

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
ws.close()
process.exit(failed.length === 0 ? 0 : 1)
