/**
 * Session reader — discover DSH session logs, decode multi-frame zstd, parse JSONL.
 *
 * The persisted log is a *concatenation of independent zstd frames* (the writer
 * flushes one frame per append), so a whole-buffer decompress silently stops at
 * the first frame. We therefore split on the frame magic and decode frame by
 * frame; a frame that fails to decode (the live session is mid-append) is
 * dropped and reported as a trailing partial rather than failing the scan.
 */

import { createHash } from 'node:crypto'
import { promises as fs } from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'

const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])

export const SESSION_FILE_CANDIDATES = ['session.v4.jsonl.zstd', 'session.v4.jsonl', 'session.jsonl.zstd', 'session.jsonl']

/** Locate the zstd decoder, or null when the runtime has none. */
export function zstdSupport() {
  return typeof zlib.zstdDecompressSync === 'function'
}

/** Offsets of every zstd frame magic in the buffer. */
function frameOffsets(buffer) {
  const offsets = []
  let index = buffer.indexOf(ZSTD_MAGIC, 0)
  while (index !== -1) {
    offsets.push(index)
    index = buffer.indexOf(ZSTD_MAGIC, index + ZSTD_MAGIC.length)
  }
  if (offsets.length === 0 || offsets[0] !== 0) offsets.unshift(0)
  return [...new Set(offsets)].sort((a, b) => a - b)
}

/**
 * Decode every zstd frame in a buffer.
 * @returns {{ text: string, frames: number, droppedFrames: number, error: string | null }}
 */
export function decodeZstdFrames(buffer) {
  if (!zstdSupport()) return { text: '', frames: 0, droppedFrames: 0, error: 'zstd-unsupported' }
  if (buffer.length === 0) return { text: '', frames: 0, droppedFrames: 0, error: null }
  const offsets = frameOffsets(buffer)
  const chunks = []
  let frames = 0
  let dropped = 0
  let index = 0
  while (index < offsets.length) {
    const start = offsets[index]
    let end = index + 1 < offsets.length ? offsets[index + 1] : buffer.length
    let decoded = null
    // A magic byte sequence can occur inside compressed data; on failure extend
    // the slice to the next candidate boundary (merging the false split).
    for (let attempt = index + 1; attempt <= offsets.length; attempt += 1) {
      const stop = attempt < offsets.length ? offsets[attempt] : buffer.length
      end = stop
      try {
        decoded = zlib.zstdDecompressSync(buffer.subarray(start, stop))
        index = attempt
        break
      } catch {
        decoded = null
      }
    }
    if (decoded === null) {
      dropped += 1
      index += 1
      continue
    }
    frames += 1
    chunks.push(decoded)
  }
  return {
    text: Buffer.concat(chunks).toString('utf8'),
    frames,
    droppedFrames: dropped,
    error: null,
  }
}

/**
 * Parse JSONL text into events. A trailing line without a newline is treated as
 * a partially written record and dropped.
 */
export function parseEventLines(text) {
  const events = []
  let malformed = 0
  const lines = text.split('\n')
  const tail = lines.pop() ?? ''
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.length === 0) continue
    try {
      const value = JSON.parse(trimmed)
      if (value !== null && typeof value === 'object' && typeof value.type === 'string') events.push(value)
      else malformed += 1
    } catch {
      malformed += 1
    }
  }
  return { events, malformed, partialTail: tail.trim().length > 0 }
}

/** Read one session file into decoded events plus decode diagnostics. */
export async function readSessionFile(file) {
  let buffer
  try {
    buffer = await fs.readFile(file)
  } catch (error) {
    return { ok: false, error: `read-failed: ${String(error?.message ?? error)}`, events: [], size: 0 }
  }
  const size = buffer.length
  const sha1 = createHash('sha1').update(buffer.subarray(0, Math.min(size, 64 * 1024))).digest('hex')
  if (!file.toLowerCase().endsWith('.zstd')) {
    const parsed = parseEventLines(buffer.toString('utf8'))
    return {
      ok: true,
      events: parsed.events,
      size,
      sha1,
      frames: 0,
      droppedFrames: 0,
      malformed: parsed.malformed,
      partialTail: parsed.partialTail,
      error: null,
    }
  }
  const decoded = decodeZstdFrames(buffer)
  if (decoded.error !== null) return { ok: false, error: decoded.error, events: [], size, sha1 }
  if (decoded.frames === 0) return { ok: false, error: 'zstd-decode-failed', events: [], size, sha1 }
  const parsed = parseEventLines(decoded.text)
  if (parsed.events.length === 0) {
    return { ok: false, error: 'no-parseable-events', events: [], size, sha1, frames: decoded.frames, droppedFrames: decoded.droppedFrames }
  }
  return {
    ok: true,
    events: parsed.events,
    size,
    sha1,
    frames: decoded.frames,
    droppedFrames: decoded.droppedFrames,
    malformed: parsed.malformed,
    partialTail: parsed.partialTail,
    error: null,
  }
}

/** Compare the cached key against the on-disk identity. */
export async function fileIdentity(file) {
  try {
    const stat = await fs.stat(file)
    return { mtimeMs: stat.mtimeMs, size: stat.size }
  } catch {
    return null
  }
}

/**
 * Enumerate sessions under $DSH_HOME/sessions.
 * Directory layout: sessions/<workspace-key>/session-<uuid>/session.v4.jsonl.zstd
 */
export async function listSessionDirs(home) {
  const root = path.join(home, 'sessions')
  let workspaces
  try {
    workspaces = await fs.readdir(root, { withFileTypes: true })
  } catch {
    return []
  }
  const found = []
  for (const workspace of workspaces) {
    if (!workspace.isDirectory()) continue
    const workspaceDir = path.join(root, workspace.name)
    let sessions
    try {
      sessions = await fs.readdir(workspaceDir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const session of sessions) {
      if (!session.isDirectory()) continue
      const dir = path.join(workspaceDir, session.name)
      for (const candidate of SESSION_FILE_CANDIDATES) {
        const file = path.join(dir, candidate)
        const identity = await fileIdentity(file)
        if (identity !== null) {
          found.push({
            sessionId: session.name.replace(/^session-/, ''),
            dirName: session.name,
            workspaceKey: workspace.name,
            dir,
            file,
            compressed: candidate.endsWith('.zstd'),
            ...identity,
          })
          break
        }
      }
    }
  }
  return found.sort((a, b) => b.mtimeMs - a.mtimeMs)
}
