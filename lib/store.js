/**
 * Store — everything the plugin persists lives under $DSH_HOME/agent-safety.
 *
 * Writes are limited to this directory: the audited sessions are opened
 * read-only and never rewritten.
 */

import { createHash, createHmac, randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'

export const STORE_SUBDIR = 'agent-safety'
export const DEFAULT_SETTINGS = {
  autoScan: true,
  judge: false,
  retentionDays: 90,
  maxSessions: 200,
  thresholds: {},
  labelBenefits: true,
  showPass: true,
  taxonomyPath: 'D:/DSH/agent-safety/taxonomy.json',
}

async function exists(file) {
  try {
    await fs.access(file)
    return true
  } catch {
    return false
  }
}

export function resolveHome(env = process.env) {
  if (typeof env.DSH_HOME === 'string' && env.DSH_HOME.trim().length > 0) return path.resolve(env.DSH_HOME.trim())
  const home = env.USERPROFILE ?? env.HOME
  return path.join(home ?? process.cwd(), '.dsh')
}

export function storePaths(home) {
  const root = path.join(home, STORE_SUBDIR)
  return {
    root,
    sessions: path.join(root, 'sessions'),
    index: path.join(root, 'index.json'),
    findings: path.join(root, 'findings.jsonl'),
    labels: path.join(root, 'labels.jsonl'),
    settings: path.join(root, 'settings.json'),
    log: path.join(root, 'plugin.log'),
    key: path.join(root, '.fingerprint-key'),
  }
}

export async function ensureLayout(paths) {
  await fs.mkdir(paths.sessions, { recursive: true })
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'))
  } catch {
    return fallback
  }
}

async function writeJsonAtomic(file, value) {
  const temp = `${file}.${process.pid}.${Date.now()}.tmp`
  await fs.writeFile(temp, JSON.stringify(value, null, 2), 'utf8')
  await fs.rename(temp, file)
}

export class Store {
  constructor(home) {
    this.home = home
    this.paths = storePaths(home)
    this.settingsCache = null
    this.indexCache = null
    this.keyCache = null
  }

  async ready() {
    await ensureLayout(this.paths)
    return this
  }

  /* ------------------------------------------------------------ settings */

  async settings() {
    if (this.settingsCache !== null) return this.settingsCache
    const stored = await readJson(this.paths.settings, {})
    this.settingsCache = { ...DEFAULT_SETTINGS, ...(stored !== null && typeof stored === 'object' ? stored : {}) }
    return this.settingsCache
  }

  async updateSettings(patch) {
    const current = await this.settings()
    const next = { ...current }
    for (const [key, value] of Object.entries(patch ?? {})) {
      if (!Object.hasOwn(DEFAULT_SETTINGS, key)) continue
      if (key === 'thresholds' || key === 'taxonomyPath') {
        if (key === 'thresholds' && value !== null && typeof value === 'object') next.thresholds = { ...current.thresholds, ...value }
        if (key === 'taxonomyPath' && typeof value === 'string' && value.trim().length > 0) next.taxonomyPath = value.trim()
        continue
      }
      if (typeof value === typeof DEFAULT_SETTINGS[key]) next[key] = value
    }
    this.settingsCache = next
    await writeJsonAtomic(this.paths.settings, next)
    return next
  }

  /* ---------------------------------------------------------- fingerprint */

  async fingerprintKey() {
    if (this.keyCache !== null) return this.keyCache
    try {
      const text = (await fs.readFile(this.paths.key, 'utf8')).trim()
      if (text.length >= 32) {
        this.keyCache = Buffer.from(text, 'hex')
        return this.keyCache
      }
    } catch {
      /* fall through */
    }
    const fresh = randomBytes(32)
    await fs.writeFile(this.paths.key, fresh.toString('hex'), { mode: 0o600 })
    this.keyCache = fresh
    return fresh
  }

  /** Irreversible fingerprint for a secret: kind/length/fingerprint, never the value. */
  async fingerprint(kind, value) {
    const key = await this.fingerprintKey()
    const digest = createHmac('sha256', key).update(kind).update('\u0000').update(String(value)).digest('hex').slice(0, 16)
    return { kind, length: String(value).length, fingerprint: digest }
  }

  /* ---------------------------------------------------------------- index */

  async readIndex() {
    if (this.indexCache !== null) return this.indexCache
    const stored = await readJson(this.paths.index, null)
    this.indexCache = { version: 1, updatedAt: null, sessions: {}, ...(stored ?? {}) }
    return this.indexCache
  }

  async writeIndex(entries) {
    const index = await this.readIndex()
    if (entries !== undefined) index.sessions = entries
    index.updatedAt = new Date().toISOString()
    this.indexCache = index
    await writeJsonAtomic(this.paths.index, index)
    return index
  }

  async touchSession(sessionId, patch) {
    const index = await this.readIndex()
    index.sessions[sessionId] = { ...(index.sessions[sessionId] ?? {}), ...patch }
    index.updatedAt = new Date().toISOString()
    await writeJsonAtomic(this.paths.index, index)
    return index.sessions[sessionId]
  }

  /* ---------------------------------------------------------- per session */

  sessionFile(sessionId) {
    return path.join(this.paths.sessions, `${sessionId}.json`)
  }

  async readSessionCache(sessionId) {
    return readJson(this.sessionFile(sessionId), null)
  }

  async writeSessionCache(sessionId, value) {
    await writeJsonAtomic(this.sessionFile(sessionId), value)
    return value
  }

  /* -------------------------------------------------------------- labels */

  async readLabels() {
    try {
      const text = await fs.readFile(this.paths.labels, 'utf8')
      const rows = []
      for (const line of text.split('\n')) {
        const trimmed = line.trim()
        if (trimmed.length === 0) continue
        try {
          const value = JSON.parse(trimmed)
          if (value !== null && typeof value === 'object') rows.push(value)
        } catch {
          /* skip a torn line */
        }
      }
      return rows
    } catch {
      return []
    }
  }

  async appendLabel(row) {
    await fs.appendFile(this.paths.labels, JSON.stringify(row) + '\n', 'utf8')
    return row
  }

  async appendFindings(rows) {
    if (rows.length === 0) return 0
    const text = rows.map((row) => JSON.stringify(row)).join('\n') + '\n'
    await fs.appendFile(this.paths.findings, text, 'utf8')
    return rows.length
  }

  /* ------------------------------------------------------------------ log */

  async log(message) {
    const line = `${new Date().toISOString()} ${message}\n`
    try {
      await fs.appendFile(this.paths.log, line, 'utf8')
    } catch {
      /* never let logging break a scan */
    }
  }

  /** Generate a stable finding id from its anchor and rule. */
  findingId(sessionId, ruleId, seq, callId) {
    return 'f_' + createHash('sha1').update(`${sessionId}\u0000${ruleId}\u0000${seq}\u0000${callId ?? ''}`).digest('hex').slice(0, 16)
  }

  async prune() {
    const settings = await this.settings()
    const index = await this.readIndex()
    const entries = Object.entries(index.sessions)
    const keep = new Set()
    const cutoff = Date.now() - settings.retentionDays * 24 * 3600 * 1000
    for (const [id, meta] of entries) {
      const scanned = Date.parse(meta.scannedAt ?? meta.startedAt ?? '') || 0
      if (scanned >= cutoff) keep.add(id)
    }
    const survivors = [...keep].slice(0, settings.maxSessions)
    let removed = 0
    for (const id of Object.keys(index.sessions)) {
      if (survivors.includes(id)) continue
      delete index.sessions[id]
      try {
        await fs.unlink(this.sessionFile(id))
        removed += 1
      } catch {
        /* already gone */
      }
    }
    await this.writeIndex(index.sessions)
    return removed
  }

  async exists(file) {
    return exists(file)
  }
}
