/**
 * Session model — fold a DSH event stream into the shapes the rules need.
 *
 * Every derived record keeps the originating event `seq`, because a finding
 * without a real anchor is worthless for drill-down (and the spec forbids it).
 */

/** Flatten a message content array into plain text. */
export function textOf(content) {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  const parts = []
  for (const item of content) {
    if (item !== null && typeof item === 'object' && item.type === 'text' && typeof item.text === 'string') parts.push(item.text)
  }
  return parts.join('\n')
}

function reasoningOf(content) {
  if (!Array.isArray(content)) return ''
  const parts = []
  for (const item of content) {
    if (item !== null && typeof item === 'object' && item.type === 'reasoning' && typeof item.text === 'string') parts.push(item.text)
  }
  return parts.join('\n')
}

function parseArguments(raw) {
  if (raw === null || raw === undefined) return {}
  if (typeof raw === 'object') return raw
  if (typeof raw !== 'string') return {}
  try {
    const value = JSON.parse(raw)
    return value !== null && typeof value === 'object' ? value : { value }
  } catch {
    return { raw }
  }
}

/** Safe JSON stringify for evidence snippets. */
export function compact(value, limit = 400) {
  let text
  try {
    text = typeof value === 'string' ? value : JSON.stringify(value)
  } catch {
    text = String(value)
  }
  if (text === undefined) text = String(value)
  return text.length > limit ? text.slice(0, limit) + `…[+${text.length - limit}]` : text
}

/**
 * Fold raw events into a session model.
 * @param {any[]} events
 */
export function normalizeSession(events) {
  const sorted = [...events].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0))
  const session = {
    id: null,
    cwd: null,
    startedAt: null,
    agentPreset: null,
    model: null,
    provider: null,
    policy: {},
    policyChanges: [],
    userMessages: [],
    finalAnswer: '',
    assistantMessages: [],
    calls: [],
    approvals: [],
    jobs: [],
    turnEnds: [],
    commands: [],
    eventCount: sorted.length,
    firstSeq: sorted[0]?.seq ?? null,
    lastSeq: sorted[sorted.length - 1]?.seq ?? null,
    events: sorted,
    bySeq: new Map(),
    byCallId: new Map(),
  }

  for (const event of sorted) {
    if (typeof event.seq === 'number') session.bySeq.set(event.seq, event)
  }

  const pending = new Map()
  const askedById = new Map()
  const jobsById = new Map()

  for (const event of sorted) {
    const data = event.data ?? {}
    switch (event.type) {
      case 'session': {
        // The session header is written flat (no `data` envelope).
        const header = event.data ?? event
        session.id = typeof header.id === 'string' ? header.id.replace(/^session-/, '') : session.id
        session.cwd = typeof header.cwd === 'string' ? header.cwd : session.cwd
        session.startedAt = typeof header.createdAt === 'number' ? header.createdAt : session.startedAt
        session.agentPreset = header.agentPreset ?? null
        session.version = header.version ?? null
        break
      }
      case 'model/selection': {
        session.model = data.model ?? session.model
        session.provider = data.provider ?? session.provider
        break
      }
      case 'permission/preset': {
        session.policy.permission_preset = data.preset
        session.policyChanges.push({ type: event.type, value: String(data.preset ?? ''), seq: event.seq })
        break
      }
      case 'sandbox/mode': {
        session.policy.sandbox = data.mode
        session.policyChanges.push({ type: event.type, value: String(data.mode ?? ''), seq: event.seq })
        break
      }
      case 'approval/policy': {
        session.policy.approval = data.policy
        session.policyChanges.push({ type: event.type, value: String(data.policy ?? ''), seq: event.seq })
        break
      }
      case 'command/run': {
        session.commands.push({
          name: String(data.name ?? ''),
          args: String(data.args ?? '').trim(),
          seq: event.seq,
          source: data.source?.kind ?? 'unknown',
        })
        break
      }
      case 'user/message': {
        session.userMessages.push({ text: textOf(data.content), seq: event.seq })
        break
      }
      case 'approval/asked': {
        const record = {
          id: data.id ?? `asked-${event.seq}`,
          tool: data.toolName ?? null,
          callId: data.callId ?? null,
          reason: String(data.reason ?? ''),
          outcome: null,
          askedSeq: event.seq,
          decidedSeq: null,
        }
        askedById.set(record.id, record)
        session.approvals.push(record)
        break
      }
      case 'approval/decided': {
        const record = askedById.get(data.id)
        if (record !== undefined) {
          record.outcome = data.outcome ?? 'unknown'
          record.decidedSeq = event.seq
        }
        break
      }
      case 'job/registered': {
        const record = {
          jobId: data.jobId ?? `job-${event.seq}`,
          kind: data.kind ?? null,
          label: compact(data.label ?? '', 300),
          callId: data.toolCall?.callId ?? null,
          settled: false,
          registeredSeq: event.seq,
          settledSeq: null,
        }
        jobsById.set(record.jobId, record)
        session.jobs.push(record)
        break
      }
      case 'job/settled': {
        const record = jobsById.get(data.jobId)
        if (record !== undefined) {
          record.settled = true
          record.settledSeq = event.seq
        }
        break
      }
      case 'turn/end': {
        session.turnEnds.push({ turn: data.turn ?? null, reason: data.reason?.kind ?? 'unknown', seq: event.seq })
        break
      }
      case 'tool/call': {
        const record = {
          callId: data.callId ?? `call-${event.seq}`,
          turn: data.turn ?? null,
          step: data.step ?? null,
          name: String(data.name ?? ''),
          argumentsRaw: typeof data.arguments === 'string' ? data.arguments : compact(data.arguments ?? {}, 4000),
          arguments: parseArguments(data.arguments),
          resultText: null,
          resultSeq: null,
          resultBytes: null,
          isError: null,
          durationMs: null,
          callSeq: event.seq,
          ts: typeof event.time === 'number' ? event.time : null,
        }
        pending.set(record.callId, record)
        session.calls.push(record)
        session.byCallId.set(record.callId, record)
        break
      }
      case 'tool/result': {
        const message = data.message ?? {}
        const callId = message.toolCallId ?? data.toolCallId
        const record = pending.get(callId)
        const text = textOf(message.content)
        if (record !== undefined) {
          record.resultText = text
          record.resultSeq = event.seq
          record.resultBytes = text.length
          record.isError = message.isError === true
          if (record.ts !== null && typeof event.time === 'number') record.durationMs = event.time - record.ts
          pending.delete(callId)
        } else {
          session.calls.push({
            callId: callId ?? `orphan-${event.seq}`,
            turn: null,
            step: null,
            name: '(orphan result)',
            argumentsRaw: '',
            arguments: {},
            resultText: text,
            resultSeq: event.seq,
            resultBytes: text.length,
            isError: message.isError === true,
            durationMs: null,
            callSeq: null,
            ts: typeof event.time === 'number' ? event.time : null,
            orphan: true,
          })
        }
        break
      }
      case 'assistant/message': {
        const message = data.message ?? {}
        const text = textOf(message.content)
        session.assistantMessages.push({
          id: message.id ?? null,
          turn: data.turn ?? null,
          step: data.step ?? null,
          text,
          reasoning: reasoningOf(message.content),
          seq: event.seq,
        })
        if (text.trim().length > 0) session.finalAnswer = text
        break
      }
      default:
        break
    }
  }

  // Pair each call with the assistant message that directly followed it, so the
  // UI can answer "which answer did this tool call belong to".
  for (const message of session.assistantMessages) {
    message.callIds = session.calls
      .filter((call) => call.callSeq !== null && message.seq !== null && call.callSeq < message.seq)
      .slice(-40)
  }
  return session
}

/** Map a message id (assistant actions slot) to its turn/step range. */
export function locateMessage(session, messageId) {
  const message = session.assistantMessages.find((item) => item.id === messageId)
  if (message === undefined) return null
  return { turn: message.turn, step: message.step, seq: message.seq }
}
