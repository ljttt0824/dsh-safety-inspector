// v1.2 checks: no per-turn chain in the panel, grouped risk list, local overall
// judgement, colour-coded steps, and the "click another call stays put" fix.
// Usage: node test/cdp-v12.mjs <appUrl> <token> <cdpBase> <sessionId>
const [appUrl, token, cdpBase = 'http://127.0.0.1:9333', sessionId = 'e3a7ff48-dc85-4d45-9a9d-8c94a1e4a0b8'] = process.argv.slice(2)
const apiBase = appUrl.replace(/\/\?.*$/, '')
const headers = { authorization: `Bearer ${token}` }

const report = (await (await fetch(`${apiBase}/api/agent-safety/session?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()).report
const chain = (await (await fetch(`${apiBase}/api/agent-safety/chain?sessionId=${encodeURIComponent(sessionId)}`, { headers })).json()).chain
const busyTurn = chain.turnGroups.slice().sort((a, b) => b.calls - a.calls)[0]
console.log(`fixture: session ${sessionId.slice(0, 8)} · critical=${report.counts.critical} · busiest turn T${busyTurn.turn} (${busyTurn.calls} calls)`)

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

await evaluate(`(() => {
  const n = [...document.querySelectorAll('button,[role="button"],a')].find((b) => (b.getAttribute('aria-label') || b.textContent || '').trim() === '安全巡检' && b.offsetParent !== null);
  if (n) n.click(); return true;
})()`)
await waitFor("document.querySelectorAll('.sf-srow').length > 0", 25000)
await evaluate(`(() => {
  const rows = [...document.querySelectorAll('.sf-srow')];
  const hit = rows.find((r) => r.textContent.replace(/\\s/g, '').toLowerCase().includes('${sessionId.slice(0, 8)}'));
  if (hit) hit.click(); return true;
})()`)
await waitFor("document.querySelectorAll('.sf-bar').length > 0", 30000)

// 1 — tabs no longer include the per-turn chain
const tabs = JSON.parse(await evaluate("JSON.stringify([...document.querySelectorAll('.sf-tab')].map((n) => n.textContent.trim()))"))
check('面板不再有「执行链」页', tabs.every((t) => !t.includes('执行链')), tabs.join(' / '))
check('面板有「风险清单」页', tabs.some((t) => t.includes('风险清单')), tabs.join(' / '))

// 2 — local overall judgement
const verdict = await evaluate(`(() => {
  const cards = [...document.querySelectorAll('.sf-card')];
  const card = cards.find((c) => c.innerText.startsWith('整体判断'));
  return card ? card.innerText.replace(/\\n/g, ' ').slice(0, 160) : '';
})()`)
check('总览有整体判断', verdict.includes('次工具调用') && verdict.includes('条风险'), verdict)

// 3 — severity row opens the grouped list
const opened = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-chip')].find((b) => b.textContent.trim().startsWith('严重'));
  if (!btn) return false;
  btn.click();
  return true;
})()`)
await new Promise((resolve) => setTimeout(resolve, 700))
const grouped = JSON.parse(await evaluate(`(() => {
  const on = [...document.querySelectorAll('.sf-tab')].find((n) => n.className.includes('on'));
  return JSON.stringify({
    tab: on ? on.textContent.trim() : '',
    rows: document.querySelectorAll('.sf-finding').length,
    verdicts: [...document.querySelectorAll('.sf-view b')].map((n) => n.textContent).filter((t) => ['已确认', '待验证', '已排除'].includes(t)),
    segments: [...document.querySelectorAll('.sf-seg button')].map((n) => n.textContent.trim()),
  });
})()`))
check('点「严重」进入分组风险清单', opened === true && grouped.tab.includes('风险清单') && grouped.rows > 0, `tab=${grouped.tab} rows=${grouped.rows}`)
check('清单按判定分组', grouped.verdicts.length >= 1, grouped.verdicts.join(' / '))
check('有判定筛选', grouped.segments.some((t) => t.startsWith('已确认')) && grouped.segments.some((t) => t.startsWith('待验证')), grouped.segments.join(' / '))

// 3b — coverage ledger and markdown export live on the overview tab
await evaluate(`(() => { const tab = [...document.querySelectorAll('.sf-tab')].find((n) => n.textContent.includes('总览')); if (tab) tab.click(); return true })()`)
await waitFor("document.querySelectorAll('.sf-bar').length > 0", 20000)
await new Promise((resolve) => setTimeout(resolve, 300))
const ledger = await evaluate(`(() => {
  const cards = [...document.querySelectorAll('.sf-card')];
  const card = cards.find((c) => c.innerText.startsWith('覆盖台账'));
  if (!card) return '';
  return card.innerText.split(String.fromCharCode(10)).join(' ').slice(0, 140);
})()`)
check('覆盖台账按四态展示', ledger.includes('已覆盖') && ledger.includes('未覆盖'), ledger)

const mdButton = await evaluate(`(() => {
  const btn = [...document.querySelectorAll('.sf-btn')].find((b) => b.textContent.includes('导出 Markdown'));
  return btn ? btn.textContent.trim() : '';
})()`)
check('可导出 Markdown 报告', mdButton.length > 0, mdButton)

// 4 — colour-coded steps in the answer overlay
const turnLink = apiBase + '/#safety?session=' + encodeURIComponent(sessionId) + '&turn=' + busyTurn.turn
await evaluate(`(() => { location.hash = '#safety?session=${sessionId}&turn=${busyTurn.turn}'; window.dispatchEvent(new HashChangeEvent('hashchange')); return true })()`)
await waitFor("document.querySelector('.sf-overlay .sf-drawer') !== null", 20000)
await waitFor("(() => { const b = document.querySelector('.sf-overlay .sf-drawer .body'); return b && b.innerText.includes('次调用'); })()", 30000)

const colour = await evaluate(`(() => {
  const buttons = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')];
  const coloured = buttons.filter((b) => /rgb|#/.test(b.style.borderColor || '') && b.style.borderColor !== 'rgb(0, 0, 0)');
  return JSON.stringify({ total: buttons.length, coloured: coloured.length, sample: coloured.slice(0, 3).map((b) => b.style.borderColor) });
})()`)
const colourState = JSON.parse(colour)
check('调用按钮按风险着色', colourState.coloured > 0, `${colourState.coloured}/${colourState.total} 上色 ${colourState.sample.join(' ')}`)

// 5 — clicking another call must stay selected (no bounce back to S1)
await waitFor("document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn').length > 5", 20000)
await new Promise((resolve) => setTimeout(resolve, 400))
const clicked = await evaluate(`(() => {
  const buttons = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')];
  const primary = buttons.find((b) => b.className.includes('primary'));
  const target = buttons.find((b) => b !== primary && b.textContent.trim().startsWith('S') && b.textContent.includes(' '));
  if (!target) return null;
  target.click();
  return target.textContent.trim();
})()`)
await new Promise((resolve) => setTimeout(resolve, 2600))
const after = await evaluate(`(() => {
  const primary = [...document.querySelectorAll('.sf-overlay .sf-drawer .sf-btn')].find((b) => b.className.includes('primary'));
  return primary ? primary.textContent.trim() : '';
})()`)
check('点其他调用后不再弹回 S1', clicked !== null && after === clicked, `clicked=${clicked} · after=${after}`)

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
ws.close()
process.exit(failed.length === 0 ? 0 : 1)
