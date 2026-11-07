// Unit test for the client half without a browser: a fake module loader, a fake
// React with just the hooks the components use, and a recorded slot registry.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const source = readFileSync(path.join(here, '..', 'lib', 'client.js'), 'utf8')

function makeReact() {
  const React = {
    createElement(type, props, ...children) {
      return { type, props: { ...(props ?? {}), children: children.length <= 1 ? children[0] : children } }
    },
    Fragment: 'Fragment',
    useState(initial) {
      const value = typeof initial === 'function' ? initial() : initial
      return [value, () => {}]
    },
    useEffect() {},
    useLayoutEffect() {},
    useCallback(fn) { return fn },
    useMemo(fn) { return fn() },
    useRef(initial) { return { current: initial } },
  }
  return React
}

function loadClient() {
  let loaded = null
  const sandbox = {
    window: {
      __ModuleLoader__: { load: (definition) => { loaded = definition } },
      addEventListener() {},
      clearInterval() {},
      setInterval() { return 1 },
      dispatchEvent() {},
      getSelection: () => null,
    },
    document: {
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => ({ setAttribute() {}, appendChild() {}, style: {}, textContent: '', remove() {}, addEventListener() {} }),
      head: { appendChild() {} },
      body: { appendChild() {} },
      addEventListener() {},
      removeEventListener() {},
    },
    location: { hash: '', pathname: '/', search: '', origin: 'http://127.0.0.1:7801' },
    history: { replaceState() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    fetch: async () => ({ ok: true, status: 200, text: async () => '{"ok":true}' }),
    HashChangeEvent: class { constructor(type) { this.type = type } },
    URLSearchParams,
    URL,
    Blob: class { constructor(parts) { this.parts = parts } },
    performance: { now: () => 0 },
    console,
    setTimeout,
    clearTimeout,
  }
  sandbox.globalThis = sandbox
  vm.createContext(sandbox)
  vm.runInContext(source, sandbox, { filename: 'client.js' })
  assert.ok(loaded !== null, 'module loader was called')
  const module = { exports: {} }
  const exports = loaded.factory((id) => {
    if (id === 'react') return makeReact()
    throw new Error('unexpected require: ' + id)
  })
  return { exports, sandbox }
}

test('client half registers every surface', () => {
  const { exports, sandbox } = loadClient()
  assert.equal(exports.name, 'dsh-safety-inspector')
  const registered = []
  const ctx = {
    slots: {
      inject(name, run) { registered.push({ name, result: run() }) },
      register(options, component) { return { options, component } },
    },
    inject(name, run) { run({ get: () => ({ register() { return () => {} } }), effect: (fn) => fn() }) },
    effect(fn) { return fn() },
  }
  exports.apply(ctx)
  const names = registered.map((row) => row.name)
  for (const expected of ['sidebar.panellist', 'main', 'conversation.input.dock', 'conversation.chat.assistant-actions', 'shell.overlay']) {
    assert.ok(names.includes(expected), 'missing slot ' + expected)
  }
  assert.equal(registered.length, 5)
})

test('assistant action opens the deep link for its message', () => {
  const { exports, sandbox } = loadClient()
  const registered = []
  const ctx = {
    slots: {
      inject(name, run) { registered.push({ name, result: run() }) },
      register(options, component) { return { options, component } },
    },
    inject(name, run) { run({ get: () => ({ register() { return () => {} } }), effect: (fn) => fn() }) },
    effect(fn) { return fn() },
  }
  exports.apply(ctx)
  const entry = registered.find((row) => row.name === 'conversation.chat.assistant-actions')
  const element = entry.result.component({ messageId: 'msg-1', sessionId: 'session-abc' })
  assert.equal(element.type, 'button')
  element.props.onClick({ preventDefault() {} })
  assert.match(sandbox.location.hash, /^#safety\?/)
  assert.match(sandbox.location.hash, /session=session-abc/)
  assert.match(sandbox.location.hash, /message=msg-1/)
})

test('dock badge renders nothing without a session id', () => {
  const { exports } = loadClient()
  const registered = []
  const ctx = {
    slots: {
      inject(name, run) { registered.push({ name, result: run() }) },
      register(options, component) { return { options, component } },
    },
    inject(name, run) { run({ get: () => ({ register() { return () => {} } }), effect: (fn) => fn() }) },
    effect(fn) { return fn() },
  }
  exports.apply(ctx)
  const entry = registered.find((row) => row.name === 'conversation.input.dock')
  assert.equal(entry.result.component({}), null)
})
