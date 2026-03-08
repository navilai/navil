import { useState, useRef, useCallback } from 'react'

const BASE = '/api/local'

/**
 * SSE event types emitted by Navil's LLM streaming endpoints.
 *
 * Protocol:
 *   event: chunk  → { text: string; cached?: boolean }
 *   event: done   → structured JSON result (type varies per endpoint)
 *   event: error  → { error: string; message: string }
 */

export interface UseNavilStreamOptions<T> {
  /** Endpoint path relative to /api/local, e.g. "/llm/analyze-config" */
  endpoint: string
  /** JSON-serializable request body */
  body: unknown
  /** Called on each text chunk (for progressive display) */
  onChunk?: (text: string, accumulated: string) => void
  /** Called once with the final parsed result from the `done` event */
  onDone?: (result: T) => void
  /** Called on error (SSE error event or network failure) */
  onError?: (error: string) => void
  /** Milliseconds of silence before we abort. Default: 60 000 */
  readTimeoutMs?: number
}

export interface NavilStreamState<T> {
  /** Accumulated text from all chunk events so far */
  text: string
  /** The final structured result from the `done` event, or null */
  result: T | null
  /** Error message, or null */
  error: string | null
  /** True while the stream is active */
  streaming: boolean
  /** True if the response came from server-side cache */
  cached: boolean
}

export interface UseNavilStreamReturn<T> extends NavilStreamState<T> {
  /** Start the SSE stream. Safe to call multiple times (aborts prior). */
  start: (opts: UseNavilStreamOptions<T>) => void
  /** Abort the current stream. */
  abort: () => void
}

/**
 * Parse a raw SSE text buffer into discrete events.
 * Each event is separated by a blank line (\n\n).
 */
function parseSSEEvents(raw: string): { event?: string; data: string }[] {
  const events: { event?: string; data: string }[] = []
  // Split on double-newlines (event boundaries)
  const blocks = raw.split(/\n\n+/)
  for (const block of blocks) {
    if (!block.trim()) continue
    let eventType: string | undefined
    const dataLines: string[] = []
    for (const line of block.split('\n')) {
      if (line.startsWith('event: ')) {
        eventType = line.slice(7).trim()
      } else if (line.startsWith('data: ')) {
        dataLines.push(line.slice(6))
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice(5))
      }
    }
    if (dataLines.length > 0) {
      events.push({ event: eventType, data: dataLines.join('\n') })
    }
  }
  return events
}

export default function useNavilStream<T = unknown>(): UseNavilStreamReturn<T> {
  const [text, setText] = useState('')
  const [result, setResult] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [streaming, setStreaming] = useState(false)
  const [cached, setCached] = useState(false)

  const abortRef = useRef<AbortController | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const optsRef = useRef<UseNavilStreamOptions<T> | null>(null)

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const abort = useCallback(() => {
    clearTimer()
    abortRef.current?.abort()
    abortRef.current = null
  }, [clearTimer])

  const start = useCallback(() => {
    const opts = optsRef.current
    if (!opts) return

    // Abort any in-flight stream
    abort()

    const controller = new AbortController()
    abortRef.current = controller

    const timeoutMs = opts.readTimeoutMs ?? 60_000

    // Reset state
    setText('')
    setResult(null)
    setError(null)
    setStreaming(true)
    setCached(false)

    let accumulated = ''
    let buffer = ''

    const resetReadTimer = () => {
      clearTimer()
      timerRef.current = setTimeout(() => {
        controller.abort()
        const msg = `Stream timed out: no data received for ${timeoutMs / 1000}s`
        setError(msg)
        setStreaming(false)
        opts.onError?.(msg)
      }, timeoutMs)
    }

    // Start the read timer immediately
    resetReadTimer()

    fetch(`${BASE}${opts.endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opts.body),
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          clearTimer()
          let msg = `HTTP ${response.status}`
          try {
            const body = await response.json()
            msg = body.detail || body.message || msg
          } catch { /* ignore */ }
          setError(msg)
          setStreaming(false)
          opts.onError?.(msg)
          return
        }

        const reader = response.body?.getReader()
        if (!reader) {
          clearTimer()
          const msg = 'No response body'
          setError(msg)
          setStreaming(false)
          opts.onError?.(msg)
          return
        }

        const decoder = new TextDecoder()

        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          // Reset read timer on each chunk of data
          resetReadTimer()

          buffer += decoder.decode(value, { stream: true })

          // Process complete SSE events in the buffer
          // Keep the last partial block (no trailing \n\n)
          const lastBoundary = buffer.lastIndexOf('\n\n')
          if (lastBoundary === -1) continue

          const complete = buffer.slice(0, lastBoundary + 2)
          buffer = buffer.slice(lastBoundary + 2)

          const events = parseSSEEvents(complete)
          for (const evt of events) {
            if (evt.event === 'chunk') {
              try {
                const payload = JSON.parse(evt.data) as { text: string; cached?: boolean }
                accumulated += payload.text
                setText(accumulated)
                if (payload.cached) setCached(true)
                opts.onChunk?.(payload.text, accumulated)
              } catch { /* malformed chunk, skip */ }
            } else if (evt.event === 'done') {
              try {
                const parsed = JSON.parse(evt.data) as T
                setResult(parsed)
                opts.onDone?.(parsed)
              } catch { /* malformed done, skip */ }
            } else if (evt.event === 'error') {
              try {
                const payload = JSON.parse(evt.data) as { error: string; message: string }
                const msg = payload.message || payload.error || 'Stream error'
                setError(msg)
                opts.onError?.(msg)
              } catch {
                setError('Stream error')
                opts.onError?.('Stream error')
              }
            }
          }
        }

        // Process any remaining buffer
        if (buffer.trim()) {
          const events = parseSSEEvents(buffer)
          for (const evt of events) {
            if (evt.event === 'done') {
              try {
                const parsed = JSON.parse(evt.data) as T
                setResult(parsed)
                opts.onDone?.(parsed)
              } catch { /* ignore */ }
            } else if (evt.event === 'error') {
              try {
                const payload = JSON.parse(evt.data) as { error: string; message: string }
                setError(payload.message || payload.error || 'Stream error')
              } catch { /* ignore */ }
            }
          }
        }

        clearTimer()
        setStreaming(false)
      })
      .catch((err: Error) => {
        clearTimer()
        if (err.name === 'AbortError') {
          // Timeout handler already set its own error message; don't overwrite
          setStreaming(false)
          return
        }
        const msg = err.message || 'Network error'
        setError(msg)
        setStreaming(false)
        opts.onError?.(msg)
      })
  }, [abort, clearTimer])

  /** Configure and start a stream in one call. */
  const startWithOpts = useCallback(
    (opts: UseNavilStreamOptions<T>) => {
      optsRef.current = opts
      start()
    },
    [start],
  )

  return {
    text,
    result,
    error,
    streaming,
    cached,
    start: startWithOpts,
    abort,
  }
}

/**
 * Convenience wrapper: imperatively start a stream and return a promise
 * that resolves with the final `done` result or rejects on error.
 *
 * Useful for one-shot calls where you don't need progressive text display.
 */
export function streamOnce<T>(
  endpoint: string,
  body: unknown,
  opts?: { readTimeoutMs?: number; onChunk?: (text: string, accumulated: string) => void },
): { promise: Promise<T>; abort: () => void } {
  const controller = new AbortController()
  const timeoutMs = opts?.readTimeoutMs ?? 60_000

  const promise = new Promise<T>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | null = null
    let accumulated = ''
    let buffer = ''

    const clearTimer = () => {
      if (timer) { clearTimeout(timer); timer = null }
    }

    const resetTimer = () => {
      clearTimer()
      timer = setTimeout(() => {
        controller.abort()
        reject(new Error(`Stream timed out: no data received for ${timeoutMs / 1000}s`))
      }, timeoutMs)
    }

    resetTimer()

    fetch(`${BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          clearTimer()
          let msg = `HTTP ${response.status}`
          try { const b = await response.json(); msg = b.detail || b.message || msg } catch { /* */ }
          reject(new Error(msg))
          return
        }

        const reader = response.body?.getReader()
        if (!reader) { clearTimer(); reject(new Error('No response body')); return }

        const decoder = new TextDecoder()

        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          resetTimer()
          buffer += decoder.decode(value, { stream: true })

          const lastBoundary = buffer.lastIndexOf('\n\n')
          if (lastBoundary === -1) continue

          const complete = buffer.slice(0, lastBoundary + 2)
          buffer = buffer.slice(lastBoundary + 2)

          const events = parseSSEEvents(complete)
          for (const evt of events) {
            if (evt.event === 'chunk') {
              try {
                const p = JSON.parse(evt.data) as { text: string }
                accumulated += p.text
                opts?.onChunk?.(p.text, accumulated)
              } catch { /* */ }
            } else if (evt.event === 'done') {
              clearTimer()
              try { resolve(JSON.parse(evt.data) as T) } catch { reject(new Error('Malformed done event')) }
              return
            } else if (evt.event === 'error') {
              clearTimer()
              try {
                const p = JSON.parse(evt.data) as { message: string }
                reject(new Error(p.message || 'Stream error'))
              } catch { reject(new Error('Stream error')) }
              return
            }
          }
        }

        // Process remaining buffer
        if (buffer.trim()) {
          const events = parseSSEEvents(buffer)
          for (const evt of events) {
            if (evt.event === 'done') {
              clearTimer()
              try { resolve(JSON.parse(evt.data) as T) } catch { reject(new Error('Malformed done event')) }
              return
            } else if (evt.event === 'error') {
              clearTimer()
              try {
                const p = JSON.parse(evt.data) as { message: string }
                reject(new Error(p.message || 'Stream error'))
              } catch { reject(new Error('Stream error')) }
              return
            }
          }
        }

        clearTimer()
        reject(new Error('Stream ended without done event'))
      })
      .catch((err: Error) => {
        clearTimer()
        if (err.name === 'AbortError') {
          reject(new Error('Request aborted'))
        } else {
          reject(err)
        }
      })
  })

  return { promise, abort: () => controller.abort() }
}
