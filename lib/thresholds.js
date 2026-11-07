/**
 * Rule thresholds. One place to change, and every value can be overridden from
 * settings.json without touching code.
 */

export const DEFAULT_THRESHOLDS = {
  /** Repeated identical (tool, arguments) pairs at or above this count. */
  repeatedCallCount: 4,
  /** Tool calls in one session above this are reported as runaway. */
  excessiveToolCalls: 150,
  /** Tool result / argument text kept as evidence (characters). */
  evidenceChars: 600,
  /** Result text stored in the cache (characters); the UI can re-read the event. */
  resultTextChars: 4000,
  /** Secrets shorter than this are not treated as secrets. */
  minSecretLength: 16,
}

/** Tools whose calls carry a filesystem path we can reason about. */
export const FILE_TOOLS = new Set(['read', 'write', 'edit', 'append', 'glob', 'grep', 'list_files', 'notebook_edit'])

/** Tools that leave the machine. */
export const NETWORK_TOOLS = new Set([
  'web_fetch', 'web_search', 'feishu_drive', 'feishu_message', 'feishu_doc', 'feishu_sheet',
  'feishu_bitable', 'feishu_api', 'feishu_wiki', 'http_request',
])

/** Tools that count as verification evidence after a write. */
export const VERIFY_TOOLS = new Set(['read', 'grep', 'glob', 'pwsh', 'bash', 'job_output', 'read_image'])

/** Tools that mutate files. */
export const WRITE_TOOLS = new Set(['write', 'edit', 'append'])

export function mergeThresholds(overrides) {
  if (overrides === null || typeof overrides !== 'object') return { ...DEFAULT_THRESHOLDS }
  const merged = { ...DEFAULT_THRESHOLDS }
  for (const key of Object.keys(DEFAULT_THRESHOLDS)) {
    const value = overrides[key]
    if (Number.isFinite(value) && value > 0) merged[key] = value
  }
  return merged
}
