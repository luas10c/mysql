/**
 * SQL injection protection and tagged template literal support.
 *
 * All user-supplied values are sent through the binary protocol as parameters,
 * never concatenated into the query string.
 *
 * Usage:
 *   sql`SELECT * FROM users WHERE id = ${userId}`
 *   sql`INSERT INTO t ${sql(obj)}`           → (col, …) VALUES (?, …)
 *   sql`UPDATE t SET ${sql(obj, 'update')}`  → col = ?, …
 *   sql`SELECT * FROM ${sql.identifier('t')}`
 *   sql`WHERE id IN ${sql([1, 2, 3])}`       → (?, ?, ?)
 */

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

// ─── SQL Fragment / Identifier ────────────────────────────────────────────────

/** An opaque SQL fragment with pre-collected parameter values */
export interface ISqlFragment {
  readonly sql: string
  readonly values: SqlPrimitive[]
}

/** A safely-quoted SQL identifier (table/column name) */
export interface ISqlIdentifier {
  readonly name: string
}

// ─── Safe identifier regex ────────────────────────────────────────────────────

const SAFE_IDENTIFIER_RE = /^[a-zA-Z_][a-zA-Z0-9_$.]*$/

// ─── Internal value types ─────────────────────────────────────────────────────

/** An opaque, pre-built SQL fragment carrying its own parameter values. */
export class SqlFragment implements ISqlFragment {
  readonly sql: string
  readonly values: SqlPrimitive[]

  constructor(sql: string, values: SqlPrimitive[]) {
    this.sql = sql
    this.values = values
  }
}

/** A safely-quoted SQL identifier (table / column name). */
export class SqlIdentifier implements ISqlIdentifier {
  readonly name: string

  constructor(raw: string) {
    const clean = raw.replace(/`/g, '')
    if (!SAFE_IDENTIFIER_RE.test(clean))
      throw new Error(`Unsafe SQL identifier: ${raw}`)
    this.name = `\`${clean}\``
  }
}

// ─── Value normalisation ──────────────────────────────────────────────────────

/** Convert a user-supplied value to a form safe to send as a protocol parameter. */
function normalizeValue(val: unknown): SqlPrimitive {
  if (val === undefined) return null
  if (val instanceof Date)
    return val.toISOString().slice(0, 19).replace('T', ' ')
  if (Buffer.isBuffer(val)) return val
  if (typeof val === 'object' && val !== null) return JSON.stringify(val)
  return val as SqlPrimitive
}

// ─── escapeValue (string fallback — prefer parameterised queries) ──────────────

export type EscapableValue =
  | string
  | number
  | bigint
  | boolean
  | null
  | undefined
  | Date
  | Buffer

export function escapeValue(val: EscapableValue): string {
  if (val === null || val === undefined) return 'NULL'
  if (typeof val === 'boolean') return val ? '1' : '0'
  if (typeof val === 'number') {
    if (!isFinite(val))
      throw new Error('Non-finite numbers cannot be used in SQL')
    return String(val)
  }
  if (typeof val === 'bigint') return String(val)
  if (val instanceof Date)
    return `'${val.toISOString().slice(0, 19).replace('T', ' ')}'`
  if (Buffer.isBuffer(val)) return `X'${val.toString('hex')}'`

  return `'${String(val)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\0/g, '\\0')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    // eslint-disable-next-line no-control-regex
    .replace(/\x1a/g, '\\Z')}'`
}

export function escapeIdentifier(name: string): string {
  return `\`${name.replace(/`/g, '``')}\``
}

// ─── buildQuery ───────────────────────────────────────────────────────────────

/** Any value that may appear inside a tagged template interpolation. */
export type TemplateInterpolation =
  | SqlPrimitive
  | SqlFragment
  | SqlIdentifier
  | SqlPrimitive[]
  | Record<string, SqlPrimitive>

export interface BuiltQuery {
  text: string
  values: SqlPrimitive[]
}

/**
 * Build a parameterised query from a tagged template literal.
 * Returns the SQL text (with `?` placeholders) and the ordered values array.
 */
export function buildQuery(
  strings: TemplateStringsArray,
  ...interpolations: TemplateInterpolation[]
): BuiltQuery {
  let text = ''
  const values: SqlPrimitive[] = []

  for (let i = 0; i < strings.length; i++) {
    text += strings[i]

    if (i < interpolations.length) {
      const val = interpolations[i]

      if (val instanceof SqlFragment) {
        // Pre-built fragment — splice its SQL and values in
        text += val.sql
        values.push(...val.values)
      } else if (val instanceof SqlIdentifier) {
        // Already-escaped identifier — emit directly, no placeholder
        text += val.name
      } else if (Array.isArray(val)) {
        // Raw array → IN list: (?, ?, ?)
        text += `(${val.map(() => '?').join(', ')})`
        values.push(...val.map(normalizeValue))
      } else {
        text += '?'
        values.push(normalizeValue(val))
      }
    }
  }

  return { text: text.trim(), values }
}

// ─── SqlHelper callable type ──────────────────────────────────────────────────

type InsertMode = undefined
type UpdateMode = 'update'

export interface SqlHelper {
  /** Object → INSERT fragment: `(col1, col2) VALUES (?, ?)` */
  (obj: Record<string, SqlPrimitive>, mode?: InsertMode): SqlFragment
  /** Object → UPDATE SET fragment: `col1 = ?, col2 = ?` */
  (obj: Record<string, SqlPrimitive>, mode: UpdateMode): SqlFragment
  /** Array → IN list fragment: `(?, ?, ?)` */
  (arr: SqlPrimitive[]): SqlFragment

  /** Wrap a column/table name in backticks, validates characters. */
  identifier: (name: string) => SqlIdentifier

  /**
   * Emit a raw SQL string with no escaping. Use only for trusted, static SQL.
   * @example sql.unsafe('NOW()')
   */
  unsafe: (rawSql: string) => SqlFragment

  /** Build a reusable parameterised SQL fragment. */
  fragment: (
    strings: TemplateStringsArray,
    ...args: TemplateInterpolation[]
  ) => SqlFragment
}

// ─── createSqlHelper ──────────────────────────────────────────────────────────

/**
 * Creates the `sql(…)` helper function used to build INSERT / UPDATE / IN-list
 * fragments inside tagged template literals.
 *
 * @param _execute  Reserved for future use (pool execute fn); currently unused.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function createSqlHelper(_execute: unknown): SqlHelper {
  function sqlHelper(
    obj: Record<string, SqlPrimitive> | SqlPrimitive[],
    mode?: 'update'
  ): SqlFragment {
    // ── Array → IN list ──────────────────────────────────────────────────────
    if (Array.isArray(obj)) {
      return new SqlFragment(
        `(${obj.map(() => '?').join(', ')})`,
        obj.map(normalizeValue)
      )
    }

    // ── Object → INSERT or UPDATE ────────────────────────────────────────────
    if (typeof obj === 'object' && obj !== null) {
      const keys = Object.keys(obj)
      if (keys.length === 0) throw new Error('Empty object passed to sql()')

      if (mode === 'update') {
        const parts = keys.map((k) => `${escapeIdentifier(k)} = ?`).join(', ')
        return new SqlFragment(
          parts,
          keys.map((k) => normalizeValue(obj[k]))
        )
      }

      const cols = keys.map((k) => escapeIdentifier(k)).join(', ')
      const placeholders = keys.map(() => '?').join(', ')
      return new SqlFragment(
        `(${cols}) VALUES (${placeholders})`,
        keys.map((k) => normalizeValue(obj[k]))
      )
    }

    throw new TypeError('sql() expects an object or array')
  }

  sqlHelper.identifier = (name: string): SqlIdentifier =>
    new SqlIdentifier(name)

  sqlHelper.unsafe = (rawSql: string): SqlFragment => {
    console.warn(
      '[mysql2-native] sql.unsafe() used — ensure this value is safe!'
    )
    return new SqlFragment(rawSql, [])
  }

  sqlHelper.fragment = (
    strings: TemplateStringsArray,
    ...args: TemplateInterpolation[]
  ): SqlFragment => {
    const { text, values } = buildQuery(strings, ...args)
    return new SqlFragment(text, values)
  }

  return sqlHelper as SqlHelper
}
