import { Connection } from './connection'

/** All primitive types accepted as query parameters */
export type SqlPrimitive =
  | string
  | number
  | bigint
  | boolean
  | null
  | undefined
  | Date
  | Buffer

// ─── Connection options ───────────────────────────────────────────────────────
export interface ConnectionOptions {
  host?: string
  port?: number
  user?: string
  password?: string
  database?: string
  connectTimeout?: number
}

export interface PoolOptions extends ConnectionOptions {
  /** Maximum number of pooled connections (default: 10) */
  max?: number
  /** Milliseconds before an idle connection is closed (default: 30_000) */
  idleTimeout?: number
  /** Milliseconds to wait for an available connection (default: 30_000) */
  acquireTimeout?: number
}

// ─── Pool stats ───────────────────────────────────────────────────────────────

export interface PoolStats {
  total: number
  idle: number
  waiting: number
}

// ─── Internal types ───────────────────────────────────────────────────────────

interface IdleEntry {
  conn: Connection
  timer: ReturnType<typeof setTimeout>
}

interface Waiter {
  resolve: (conn: Connection) => void
  reject: (err: Error) => void
  timeout: ReturnType<typeof setTimeout>
}

// ─── Pool ─────────────────────────────────────────────────────────────────────

export class Pool {
  readonly options: PoolOptions

  private readonly _max: number
  private readonly _idleTimeout: number
  private readonly _connectTimeout: number
  private readonly _acquireTimeout: number

  /** Connections currently checked-out to callers. */
  _active = new Set<Connection>()
  /** Idle connections waiting to be reused, each with an expiry timer. */
  private _idle: IdleEntry[] = []
  /** Callers waiting for a connection to become available. */
  private _waiting: Waiter[] = []

  _closed = false

  constructor(options: PoolOptions) {
    this.options = options
    this._max = options.max ?? 10
    this._idleTimeout = options.idleTimeout ?? 30_000
    this._connectTimeout = options.connectTimeout ?? 10_000
    this._acquireTimeout = options.acquireTimeout ?? 30_000
  }

  // ─── Connection factory (overridable in tests) ─────────────────────────────

  async _createConnection(): Promise<Connection> {
    const conn = new Connection(this.options as ConnectionOptions)

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error('Connection timeout')),
        this._connectTimeout
      )
    )

    await Promise.race([conn.connect(), timeoutPromise])

    conn.on('error', () => {
      this._active.delete(conn)
      this._removeIdle(conn)
    })

    return conn
  }

  // ─── Acquire ───────────────────────────────────────────────────────────────

  async acquire(): Promise<Connection> {
    if (this._closed) throw new Error('Pool is closed')

    // Try to reuse an idle connection
    while (this._idle.length > 0) {
      const { conn, timer } = this._idle.shift()!
      clearTimeout(timer)
      try {
        await conn.ping()
        this._active.add(conn)
        return conn
      } catch {
        // Dead connection — discard and try the next one
      }
    }

    // Create a fresh connection if under the cap
    if (this._active.size + this._idle.length < this._max) {
      const conn = await this._createConnection()
      this._active.add(conn)
      return conn
    }

    // Wait for a connection to be released
    return new Promise<Connection>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this._waiting.indexOf(waiter)
        if (idx !== -1) this._waiting.splice(idx, 1)
        reject(new Error('Pool acquire timeout: no connection available'))
      }, this._acquireTimeout)

      const waiter: Waiter = { resolve, reject, timeout }
      this._waiting.push(waiter)
    })
  }

  // ─── Release ───────────────────────────────────────────────────────────────

  release(conn: Connection): void {
    this._active.delete(conn)

    // Hand off directly to a waiting caller
    if (this._waiting.length > 0) {
      const { resolve, timeout } = this._waiting.shift()!
      clearTimeout(timeout)
      this._active.add(conn)
      resolve(conn)
      return
    }

    // Park in the idle list with an expiry timer
    const timer = setTimeout(() => {
      this._removeIdle(conn)
      conn.end().catch(() => {
        /* swallow */
      })
    }, this._idleTimeout)
    timer.unref()

    this._idle.push({ conn, timer })
  }

  private _removeIdle(conn: Connection): void {
    const idx = this._idle.findIndex((e) => e.conn === conn)
    if (idx !== -1) {
      clearTimeout(this._idle[idx].timer)
      this._idle.splice(idx, 1)
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  async query(sql: string, values?: unknown[]): Promise<unknown> {
    const conn = await this.acquire()
    try {
      return await conn.query(sql, values as SqlPrimitive[])
    } finally {
      this.release(conn)
    }
  }

  /** Run a callback with a dedicated connection (for transactions). */
  async withConnection<T>(fn: (conn: Connection) => Promise<T>): Promise<T> {
    const conn = await this.acquire()
    try {
      return await fn(conn)
    } finally {
      this.release(conn)
    }
  }

  // ─── Shutdown ──────────────────────────────────────────────────────────────

  async end(): Promise<void> {
    this._closed = true

    for (const { reject, timeout } of this._waiting) {
      clearTimeout(timeout)
      reject(new Error('Pool is closing'))
    }
    this._waiting = []

    const all: Connection[] = [
      ...this._idle.map(({ conn, timer }) => {
        clearTimeout(timer)
        return conn
      }),
      ...this._active
    ]
    this._idle = []
    this._active.clear()

    // Destroy immediately — socket already has unref() so process can exit
    for (const conn of all) conn.destroy()
  }

  /** Immediately destroy all connections without waiting for graceful close. */
  destroy(): void {
    this._closed = true

    for (const { reject, timeout } of this._waiting) {
      clearTimeout(timeout)
      reject(new Error('Pool is closing'))
    }
    this._waiting = []

    const all: Connection[] = [
      ...this._idle.map(({ conn, timer }) => {
        clearTimeout(timer)
        return conn
      }),
      ...this._active
    ]
    this._idle = []
    this._active.clear()

    for (const conn of all) conn.destroy()
  }

  // ─── Stats ─────────────────────────────────────────────────────────────────

  get totalCount(): number {
    return this._active.size + this._idle.length
  }
  get idleCount(): number {
    return this._idle.length
  }
  get waitingCount(): number {
    return this._waiting.length
  }

  get stats(): PoolStats {
    return {
      total: this.totalCount,
      idle: this.idleCount,
      waiting: this.waitingCount
    }
  }
}
