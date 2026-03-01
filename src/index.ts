/**
 * mysql2-native — MySQL client for Node.js
 *
 * Uses raw TCP (node:net), ES6 tagged templates, and the binary prepared-
 * statement protocol for complete SQL-injection protection.
 *
 * @example
 * import mysql from 'mysql2-native'
 *
 * const sql = mysql({ host: 'localhost', user: 'root', password: 'secret', database: 'mydb' })
 *
 * // Simple query — all interpolated values become ? parameters
 * const users = await sql`SELECT * FROM users WHERE active = ${true}`
 *
 * // INSERT with object helper
 * await sql`INSERT INTO users ${sql({ name: 'Alice', email: 'alice@example.com' })}`
 *
 * // UPDATE with object helper
 * await sql`UPDATE users SET ${sql({ name: 'Bob' }, 'update')} WHERE id = ${1}`
 *
 * // IN clause
 * const ids = [1, 2, 3]
 * await sql`SELECT * FROM users WHERE id IN ${sql(ids)}`
 *
 * // Transaction
 * await sql.begin(async tx => {
 *   await tx`INSERT INTO orders ${sql({ userId: 1, total: 99.99 })}`
 *   await tx`UPDATE users SET balance = balance - ${99.99} WHERE id = ${1}`
 * })
 *
 * // Close pool when done
 * await sql.end()
 */

import { Connection } from './connection'
import { Pool } from './pool'
import {
  buildQuery,
  createSqlHelper,
  type SqlHelper,
  type TemplateInterpolation
} from './sql'
import { withTransaction, withSavepoint } from './transaction'

// ─── Result type re-exported for convenience ──────────────────────────────────

export type { SqlHelper } from './sql.ts'
export { escapeValue, escapeIdentifier } from './sql'
export { Connection, Pool, buildQuery, withTransaction, withSavepoint }

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

// ─── Pool stats ───────────────────────────────────────────────────────────────

export interface PoolStats {
  total: number
  idle: number
  waiting: number
}

// ─── Bound sql tag type ───────────────────────────────────────────────────────

/** A sql-tagged-template function bound to a single connection. */
export interface BoundSql extends SqlHelper {
  (
    strings: TemplateStringsArray,
    ...values: TemplateInterpolation[]
  ): Promise<unknown>

  /** Nested transaction via a savepoint on this connection. */
  begin<T>(fn: (tx: BoundSql) => Promise<T>): Promise<T>
  /** Create a named savepoint within the current transaction. */
  savepoint<T>(name: string, fn: () => Promise<T>): Promise<T>
  /** Verify the connection is alive. */
  ping(): Promise<void>
}

/** A BoundSql that returns a connection to the pool when released. */
export interface ReservedSql extends BoundSql {
  release(): void
  end(): void
}

// ─── Root Sql type ────────────────────────────────────────────────────────────

export interface Sql extends SqlHelper {
  (
    strings: TemplateStringsArray,
    ...values: TemplateInterpolation[]
  ): Promise<unknown>

  /** Run a transaction; commits on success, rolls back on error. */
  begin<T>(fn: (tx: BoundSql) => Promise<T>): Promise<T>
  /** Reserve a dedicated connection from the pool. */
  reserve(): Promise<ReservedSql>
  /** Pool connection statistics. */
  readonly connections: PoolStats
  /** Drain all pool connections. */
  end(): Promise<void>
  /** Immediately destroy all connections without waiting for graceful close. */
  destroy(): void
  /** Create a direct (non-pooled) connection. */
  connect(): Promise<BoundSql & { end(): Promise<void>; destroy(): void }>
}

// ─── createBoundSql ──────────────────────────────────────────────────────────

function createBoundSql(conn: Connection, helper: SqlHelper): BoundSql {
  async function execute(
    strings: TemplateStringsArray,
    ...interpolations: TemplateInterpolation[]
  ): Promise<unknown> {
    const { text, values } = buildQuery(strings, ...interpolations)
    return conn.query(text, values as SqlPrimitive[])
  }

  return Object.assign(execute, {
    // Forward all SqlHelper methods
    ...helper,
    identifier: helper.identifier,
    unsafe: helper.unsafe,
    fragment: helper.fragment,

    begin<T>(fn: (tx: BoundSql) => Promise<T>): Promise<T> {
      return withTransaction(conn, (c) =>
        fn(createBoundSql(c as Connection, helper))
      )
    },

    savepoint<T>(name: string, fn: () => Promise<T>): Promise<T> {
      return withSavepoint(conn, name, fn)
    },

    ping(): Promise<void> {
      return conn.ping()
    }
  }) as BoundSql
}

// ─── mysql() factory ─────────────────────────────────────────────────────────

function mysql(options: PoolOptions = {}): Sql {
  const pool = new Pool(options)
  const helper = createSqlHelper(null)

  async function execute(
    strings: TemplateStringsArray,
    ...interpolations: TemplateInterpolation[]
  ): Promise<unknown> {
    const { text, values } = buildQuery(strings, ...interpolations)
    return pool.query(text, values as SqlPrimitive[])
  }

  const sql: Sql = Object.assign(execute, {
    // SqlHelper methods
    ...helper,
    identifier: helper.identifier,
    unsafe: helper.unsafe,
    fragment: helper.fragment,

    begin<T>(fn: (tx: BoundSql) => Promise<T>): Promise<T> {
      return pool.withConnection((conn) =>
        withTransaction(conn, (c) =>
          fn(createBoundSql(c as Connection, helper))
        )
      )
    },

    async reserve(): Promise<ReservedSql> {
      const conn = await pool.acquire()
      const bound = createBoundSql(conn, helper)
      const reserved = Object.assign(bound, {
        release(): void {
          pool.release(conn)
        },
        end(): void {
          pool.release(conn)
        }
      }) as ReservedSql
      return reserved
    },

    get connections(): PoolStats {
      return {
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount
      }
    },

    end(): Promise<void> {
      return pool.end()
    },

    destroy(): void {
      pool.destroy()
    },

    async connect(): Promise<
      BoundSql & { end(): Promise<void>; destroy(): void }
    > {
      const conn = new Connection(options as ConnectionOptions)
      await conn.connect()
      const bound = createBoundSql(conn, helper)
      return Object.assign(bound, {
        end(): Promise<void> {
          return conn.end()
        },
        destroy(): void {
          conn.destroy()
        }
      })
    }
  }) as Sql

  return sql
}

export default mysql
export { mysql }
