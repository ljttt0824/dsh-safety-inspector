// CDP driver: verify the safety-inspector client half in a real browser.
// Usage: node test/cdp-verify.mjs <appUrl> <cdpBase>
const appUrl = process.argv[2]
const cdpBase = process.argv[3] ?? 'http://127.0.0.1:9333'

const targets = await (await fetch(cdpBase + '/json/list')).json()
const page = targets.find((t) => t.type === 'page')
if (page === undefined) throw new Error('no page target')
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

function send(method, params = {}) {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    ws.send(JSON.stringify({ id, method, params }))
  })
}

async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (result.exceptionDetails) throw new Error('eval failed: ' + JSON.stringify(result.exceptionDetails).slice(0, 400))
  return result.result.value
}

async function waitFor(expression, timeoutMs = 20000) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await evaluate(expression)
      if (value) return value
    } catch { /* keep waiting */ }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error('timeout waiting for: ' + expression)
}

const results = []
function check(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`)
}

await send('Page.enable')
await send('Runtime.enable')
await send('Page.navigate', { url: appUrl })
await waitFor("document.readyState === 'complete'", 30000)
await waitFor("document.body && document.body.innerText.length > 0", 30000)

// The plugin bundle registers a style tag as soon as its apply() runs.
const style = await waitFor("document.querySelector('style[data-plugin=\"dsh-safety-inspector\"]') !== null", 25000)
check('客户端 bundle 已加载', style === true, 'style tag present')

// Sidebar entry (the panel row exposes the label as text or aria-label).
const label = await evaluate(`(() => {
  const nodes = [...document.querySelectorAll('button,[role="button"],a,div,span')];
  const hit = nodes.find((node) => {
    const text = (node.textContent || '').trim();
    const aria = node.getAttribute('aria-label') || '';
    return (text === '安全巡检' || aria === '安全巡检') && node.offsetParent !== null;
  });
  return hit ? hit.tagName + ':' + (hit.getAttribute('aria-label') || hit.textContent.trim().slice(0, 8)) : '';
})()`)
check('左侧栏出现「安全巡检」入口', label !== '', label || '未找到')

// Click the panel entry and wait for the panel root.
const clicked = await evaluate(`(() => {
  const nodes = [...document.querySelectorAll('button,[role="button"],a')];
  const hit = nodes.find((node) => {
    const text = (node.textContent || '').trim();
    const aria = node.getAttribute('aria-label') || '';
    return (text === '安全巡检' || aria === '安全巡检') && node.offsetParent !== null;
  });
  if (!hit) return false;
  hit.click();
  return true;
})()`)
check('点击入口', clicked === true, '')
let panelOk = false
try {
  panelOk = await waitFor("document.querySelector('.sf-root') !== null", 15000)
} catch { panelOk = false }
check('面板渲染 .sf-root', panelOk === true, '')

if (panelOk) {
  let rowsOk = false
  try {
    rowsOk = await waitFor("document.querySelectorAll('.sf-srow').length > 0", 20000)
  } catch { rowsOk = false }
  const stats = await evaluate(`(() => {
    const rows = document.querySelectorAll('.sf-srow').length;
    const tabs = [...document.querySelectorAll('.sf-tab')].map((node) => node.textContent);
    return JSON.stringify({ rows, tabs });
  })()`)
  const parsed = JSON.parse(stats)
  check('会话列表渲染', rowsOk === true && parsed.rows > 0, parsed.rows + ' 行')
  check('四个视图 tab', parsed.tabs.length >= 4, parsed.tabs.join(' / '))

  // Click the first session row and wait for the overview to render.
  await evaluate("document.querySelector('.sf-srow').click()")
  const overview = await waitFor("document.querySelector('.sf-heat') !== null && document.querySelectorAll('.sf-bar').length > 0", 20000)
  check('总览渲染（分类条 + 时间轴）', overview === true, '')

  const timing = await evaluate(`(async () => {
    const t0 = performance.now();
    const tabs = [...document.querySelectorAll('.sf-tab')];
    const chainTab = tabs.find((node) => node.textContent.includes('执行链'));
    if (chainTab) chainTab.click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => requestAnimationFrame(() => resolve()));
    return Math.round(performance.now() - t0);
  })()`)
  check('执行链切换耗时可测', typeof timing === 'number', timing + 'ms')

  const chainOk = await waitFor("document.querySelector('.sf-chain') !== null && document.querySelectorAll('.sf-step').length > 0", 20000)
  check('执行链渲染（步骤 + 调用）', chainOk === true, '')

  const inspector = await evaluate(`(() => {
    const steps = document.querySelectorAll('.sf-step');
    if (steps.length === 0) return 'no-steps';
    steps[Math.min(3, steps.length - 1)].click();
    const accessRows = document.querySelectorAll('.sf-access').length;
    const callButtons = document.querySelectorAll('.sf-insp .sf-btn').length;
    return JSON.stringify({ steps: steps.length, accessRows, callButtons });
  })()`)
  const insp = JSON.parse(inspector)
  check('Inspector 三段（调用/数据访问/策略）', insp.accessRows >= 2, JSON.stringify(insp))
}

// Dock badge + assistant action are rendered by the conversation surfaces.
const surfaces = await evaluate(`(() => {
  const badge = document.querySelector('.sf-badge-line');
  const action = document.querySelector('.sf-assist');
  return JSON.stringify({ badge: badge ? badge.textContent : '', action: action !== null });
})()`)
const surfaceState = JSON.parse(surfaces)
check('输入框上方徽章', surfaceState.badge.length > 0, surfaceState.badge)
check('助手消息下方图标', surfaceState.action === true, '')

// Perf: switch to the 2060-event session and time the overview render.
const perf = await evaluate(`(async () => {
  const tabs = [...document.querySelectorAll('.sf-tab')];
  const overviewTab = tabs.find((node) => node.textContent.includes('总览'));
  if (overviewTab) overviewTab.click();
  await new Promise((resolve) => setTimeout(resolve, 60));
  const rows = [...document.querySelectorAll('.sf-srow')];
  const target = rows.find((row) => row.textContent.includes('47cd3ca7')) || rows[0];
  if (!target) return JSON.stringify({ ok: false });
  const before = document.querySelectorAll('.sf-heat').length;
  const t0 = performance.now();
  target.click();
  for (let i = 0; i < 400; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    const heat = document.querySelector('.sf-heat');
    const bars = document.querySelectorAll('.sf-bar').length;
    if (heat !== null && heat.children.length > 0 && bars > 0) {
      await new Promise((resolve) => requestAnimationFrame(() => resolve()));
      return JSON.stringify({ ok: true, ms: Math.round(performance.now() - t0), ticks: heat.children.length });
    }
  }
  return JSON.stringify({ ok: false });
})()`)
const perfState = JSON.parse(perf)
check('总览渲染 < 1.5s（真实会话）', perfState.ok === true && perfState.ms < 1500, perfState.ok ? perfState.ms + 'ms / ' + perfState.ticks + ' ticks' : '未渲染')

// Deep link: open overlay straight from the hash.
await evaluate(`(() => {
  location.hash = '#safety?session=e3a7ff48-dc85-4d45-9a9d-8c94a1e4a0b8';
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  return true;
})()`)
let deep = false
try {
  deep = await waitFor("document.querySelector('.sf-overlay .sf-drawer') !== null", 8000)
} catch { deep = false }
check('深链打开浮层', deep === true, '#safety?session=...')

let drawerState = { hasRisk: false, len: 0 }
try {
  await waitFor("(() => { const b = document.querySelector('.sf-overlay .sf-drawer .body'); return b !== null && b.innerText.trim().length > 50; })()", 15000)
  drawerState = JSON.parse(await evaluate(`(() => {
    const body = document.querySelector('.sf-overlay .sf-drawer .body');
    const text = body ? body.innerText : '';
    return JSON.stringify({ hasRisk: /风险|覆盖/.test(text), len: text.length });
  })()`))
} catch { drawerState = { hasRisk: false, len: 0 } }
check('浮层渲染报告与调用链', drawerState.len > 50 && drawerState.hasRisk, drawerState.len + ' 字符')

// Close restores the app.
const closed = await evaluate(`(async () => {
  history.replaceState(null, '', location.pathname + location.search);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  await new Promise((resolve) => setTimeout(resolve, 300));
  return document.querySelector('.sf-overlay') === null;
})()`)
check('关闭浮层无残留', closed === true, '')

const failed = results.filter((row) => row.ok !== true)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
ws.close()
process.exit(failed.length === 0 ? 0 : 1)
