import { readLengthEncodedInt, readLengthEncodedString } from './buffer'
import { Types, FieldFlags } from './constants'

// ─── Internal protocol types ──────────────────────────────────────────────────

export interface OkPacket {
  affectedRows: number
  lastInsertId: number
  statusFlags: number
  warnings: number
  message: string
}

/** Column metadata returned with every SELECT result */
export interface ColumnInfo {
  name: string
  nameAlias: string
  table: string
  tableAlias: string
  schema: string
  catalog: string
  columnType: number
  columnLength: number
  charsetNr: number
  flags: number
  decimals: number
}

// ─── MySQL error with protocol extensions ─────────────────────────────────────

export class MySQLError extends Error {
  readonly code: number
  readonly sqlState: string

  constructor(code: number, sqlState: string, message: string) {
    super(`MySQL Error [${code}] (${sqlState}): ${message}`)
    this.name = 'MySQLError'
    this.code = code
    this.sqlState = sqlState
  }
}

// ─── Packet decoders ──────────────────────────────────────────────────────────

export function decodeOK(payload: Buffer): OkPacket {
  let offset = 1 // skip 0x00 header byte

  const { value: affectedRows, bytesRead: ar } = readLengthEncodedInt(
    payload,
    offset
  )
  offset += ar
  const { value: lastInsertId, bytesRead: li } = readLengthEncodedInt(
    payload,
    offset
  )
  offset += li

  const statusFlags = payload.readUInt16LE(offset)
  offset += 2
  const warnings = payload.readUInt16LE(offset)
  offset += 2
  const message =
    offset < payload.length ? payload.toString('utf8', offset) : ''

  return {
    affectedRows: (affectedRows ?? 0) as number,
    lastInsertId: (lastInsertId ?? 0) as number,
    statusFlags,
    warnings,
    message
  }
}

export function decodeERR(payload: Buffer): MySQLError {
  let offset = 1 // skip 0xff
  const code = payload.readUInt16LE(offset)
  offset += 2

  let sqlState = ''
  if (payload[offset] === 0x23 /* '#' */) {
    sqlState = payload.toString('ascii', offset + 1, offset + 6)
    offset += 6
  }

  const message = payload.toString('utf8', offset)
  return new MySQLError(code, sqlState, message)
}

export function decodeColumnDefinition(payload: Buffer): ColumnInfo {
  let offset = 0

  const catalog = readLengthEncodedString(payload, offset)
  offset += catalog.bytesRead
  const schema = readLengthEncodedString(payload, offset)
  offset += schema.bytesRead
  const tableAlias = readLengthEncodedString(payload, offset)
  offset += tableAlias.bytesRead
  const table = readLengthEncodedString(payload, offset)
  offset += table.bytesRead
  const nameAlias = readLengthEncodedString(payload, offset)
  offset += nameAlias.bytesRead
  const name = readLengthEncodedString(payload, offset)
  offset += name.bytesRead

  offset += 1 // 0x0c fixed-fields length byte
  const charsetNr = payload.readUInt16LE(offset)
  offset += 2
  const columnLength = payload.readUInt32LE(offset)
  offset += 4
  const columnType = payload[offset]
  offset += 1
  const flags = payload.readUInt16LE(offset)
  offset += 2
  const decimals = payload[offset]

  return {
    catalog: catalog.value ?? '',
    schema: schema.value ?? '',
    table: table.value ?? '',
    tableAlias: tableAlias.value ?? '',
    name: name.value ?? '',
    nameAlias: nameAlias.value ?? '',
    charsetNr,
    columnLength,
    columnType,
    flags,
    decimals
  }
}

// ─── Row decoders ─────────────────────────────────────────────────────────────

type Row = Record<string, unknown>

/** Decode a text-protocol result row (used for COM_QUERY). */
export function decodeTextRow(payload: Buffer, columns: ColumnInfo[]): Row {
  const row: Row = {}
  let offset = 0

  for (const col of columns) {
    if (payload[offset] === 0xfb) {
      row[col.name] = null
      offset += 1
    } else {
      const { value, bytesRead } = readLengthEncodedString(payload, offset)
      offset += bytesRead
      row[col.name] = castTextValue(value, col)
    }
  }

  return row
}

function castTextValue(raw: string | null, col: ColumnInfo): unknown {
  if (raw === null) return null

  const t = col.columnType

  if (
    t === Types.TINY ||
    t === Types.SHORT ||
    t === Types.LONG ||
    t === Types.INT24 ||
    t === Types.YEAR
  ) {
    return parseInt(raw, 10)
  }

  if (t === Types.LONGLONG) {
    const n = BigInt(raw)
    return n >= BigInt(Number.MIN_SAFE_INTEGER) &&
      n <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(n)
      : n
  }

  if (
    t === Types.FLOAT ||
    t === Types.DOUBLE ||
    t === Types.DECIMAL ||
    t === Types.NEWDECIMAL
  ) {
    return parseFloat(raw)
  }

  if (t === Types.JSON) {
    try {
      return JSON.parse(raw)
    } catch {
      return raw
    }
  }

  if (t === Types.DATE || t === Types.DATETIME || t === Types.TIMESTAMP) {
    if (!raw || raw.startsWith('0000')) return null
    return new Date(raw.replace(' ', 'T') + (raw.includes('T') ? '' : 'Z'))
  }

  return raw
}

// ─── Binary protocol row decoder (COM_STMT_EXECUTE) ───────────────────────────

interface BinaryValueResult {
  value: unknown
  bytesRead: number
}

/** Decode a binary-protocol result row (used for prepared statements). */
export function decodeBinaryRow(payload: Buffer, columns: ColumnInfo[]): Row {
  const row: Row = {}
  let offset = 1 // skip 0x00 packet header

  // NULL bitmap: ceil((columnCount + 2) / 8) bytes
  const nullBitmapSize = Math.ceil((columns.length + 2) / 8)
  const nullBitmap = payload.slice(offset, offset + nullBitmapSize)
  offset += nullBitmapSize

  for (let i = 0; i < columns.length; i++) {
    const byteIndex = Math.floor((i + 2) / 8)
    const bitIndex = (i + 2) % 8

    if (nullBitmap[byteIndex] & (1 << bitIndex)) {
      row[columns[i].name] = null
      continue
    }

    const { value, bytesRead } = readBinaryValue(payload, offset, columns[i])
    row[columns[i].name] = value
    offset += bytesRead
  }

  return row
}

function readBinaryValue(
  buf: Buffer,
  offset: number,
  col: ColumnInfo
): BinaryValueResult {
  const t = col.columnType

  if (t === Types.NULL) return { value: null, bytesRead: 0 }

  if (t === Types.TINY) {
    const v =
      col.flags & FieldFlags.UNSIGNED
        ? buf.readUInt8(offset)
        : buf.readInt8(offset)
    return { value: v, bytesRead: 1 }
  }

  if (t === Types.SHORT || t === Types.YEAR) {
    const v =
      col.flags & FieldFlags.UNSIGNED
        ? buf.readUInt16LE(offset)
        : buf.readInt16LE(offset)
    return { value: v, bytesRead: 2 }
  }

  if (t === Types.LONG || t === Types.INT24) {
    const v =
      col.flags & FieldFlags.UNSIGNED
        ? buf.readUInt32LE(offset)
        : buf.readInt32LE(offset)
    return { value: v, bytesRead: 4 }
  }

  if (t === Types.LONGLONG) {
    const v =
      col.flags & FieldFlags.UNSIGNED
        ? buf.readBigUInt64LE(offset)
        : buf.readBigInt64LE(offset)
    return { value: v, bytesRead: 8 }
  }

  if (t === Types.FLOAT) return { value: buf.readFloatLE(offset), bytesRead: 4 }
  if (t === Types.DOUBLE)
    return { value: buf.readDoubleLE(offset), bytesRead: 8 }

  // All remaining types are length-encoded strings
  const { value: len, bytesRead: lb } = readLengthEncodedInt(buf, offset)
  const rawLen = (len ?? 0) as number
  const raw = buf.toString('utf8', offset + lb, offset + lb + rawLen)
  return { value: castTextValue(raw, col), bytesRead: lb + rawLen }
}
