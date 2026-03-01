import { createConnection, type Socket } from 'node:net'
import { EventEmitter } from 'node:events'
import { PacketParser } from './parser'
import { buildPacket } from './buffer'
import { nativePassword, cachingSha2Password } from './auth'
import {
  decodeOK,
  decodeERR,
  decodeColumnDefinition,
  decodeTextRow,
  decodeBinaryRow
} from './packets'
import { Capabilities, Commands, Types } from './constants'

// ─── Connection options ───────────────────────────────────────────────────────
export interface ConnectionOptions {
  host?: string
  port?: number
  user?: string
  password?: string
  database?: string
  connectTimeout?: number
}

// ─── Internal protocol types ──────────────────────────────────────────────────

export interface Packet {
  sequenceId: number
  payload: Buffer
}

export interface OkPacket {
  affectedRows: number
  lastInsertId: number
  statusFlags: number
  warnings: number
  message: string
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

// ─── Client capability flags sent in the handshake response ──────────────────

const CLIENT_FLAGS =
  Capabilities.CLIENT_LONG_PASSWORD |
  Capabilities.CLIENT_PROTOCOL_41 |
  Capabilities.CLIENT_SECURE_CONNECTION |
  Capabilities.CLIENT_TRANSACTIONS |
  Capabilities.CLIENT_MULTI_RESULTS |
  Capabilities.CLIENT_PS_MULTI_RESULTS |
  Capabilities.CLIENT_PLUGIN_AUTH |
  Capabilities.CLIENT_LONG_FLAG |
  Capabilities.CLIENT_DEPRECATE_EOF

// ─── Internal state types ─────────────────────────────────────────────────────

type QueryResult =
  | (Record<string, unknown>[] & { columns?: ColumnInfo[]; count: number })
  | (OkPacket & { count: number })

type ResolveQuery = (result: QueryResult) => void
type RejectQuery = (err: Error) => void

interface HandshakeInfo {
  serverVersion: string
  connectionId: number
  scramble: Buffer
  authPlugin: string
  capabilities: number
}

type ConnectionState =
  | 'handshake'
  | 'auth_response'
  | 'auth_switch'
  | 'caching_sha2_extra'

interface PendingOp {
  state?: ConnectionState
  resolve?: ResolveQuery | ((v: unknown) => void)
  reject?: RejectQuery
  handler?: (packet: Packet) => void
  start?: () => void
}

// ─── Binary protocol helpers ─────────────────────────────────────────────────

function getMysqlType(val: SqlPrimitive): number {
  if (val === null || val === undefined) return Types.NULL
  if (typeof val === 'boolean') return Types.TINY
  if (Number.isInteger(val)) return Types.LONG
  if (typeof val === 'number') return Types.DOUBLE
  if (typeof val === 'bigint') return Types.LONGLONG
  if (val instanceof Date) return Types.DATETIME
  if (Buffer.isBuffer(val)) return Types.BLOB
  return Types.VAR_STRING
}

function buildTypeBuffer(values: SqlPrimitive[]): Buffer {
  const buf = Buffer.alloc(values.length * 2)
  values.forEach((v, i) => {
    buf.writeUInt8(getMysqlType(v), i * 2)
    buf.writeUInt8(0, i * 2 + 1) // unsigned flag = 0
  })
  return buf
}

function writeLengthEncodedIntInline(len: number): Buffer {
  if (len < 0xfb) return Buffer.from([len])
  if (len <= 0xffff) {
    const b = Buffer.alloc(3)
    b[0] = 0xfc
    b.writeUInt16LE(len, 1)
    return b
  }
  const b = Buffer.alloc(4)
  b[0] = 0xfd
  b[1] = len & 0xff
  b[2] = (len >> 8) & 0xff
  b[3] = (len >> 16) & 0xff
  return b
}

function buildValuesBuffer(values: SqlPrimitive[]): Buffer {
  const parts: Buffer[] = []
  for (const val of values) {
    if (val === null || val === undefined) continue

    if (typeof val === 'boolean') {
      const b = Buffer.alloc(1)
      b[0] = val ? 1 : 0
      parts.push(b)
    } else if (typeof val === 'number' && Number.isInteger(val)) {
      const b = Buffer.alloc(4)
      b.writeInt32LE(val, 0)
      parts.push(b)
    } else if (typeof val === 'number') {
      const b = Buffer.alloc(8)
      b.writeDoubleLE(val, 0)
      parts.push(b)
    } else if (typeof val === 'bigint') {
      const b = Buffer.alloc(8)
      b.writeBigInt64LE(val, 0)
      parts.push(b)
    } else if (Buffer.isBuffer(val)) {
      parts.push(writeLengthEncodedIntInline(val.length), val)
    } else {
      const strBuf = Buffer.from(String(val), 'utf8')
      parts.push(writeLengthEncodedIntInline(strBuf.length), strBuf)
    }
  }
  return Buffer.concat(parts)
}

// ─── Connection ───────────────────────────────────────────────────────────────

export class Connection extends EventEmitter {
  readonly options: ConnectionOptions

  private _socket: Socket | null = null
  private _parser: PacketParser = new PacketParser()
  private _queue: PendingOp[] = []
  private _current: PendingOp | null = null
  private _connected = false
  private _closed = false
  private _sequenceId = 0
  private _handshakeInfo: HandshakeInfo | null = null

  constructor(options: ConnectionOptions) {
    super()
    this.options = options
  }

  // ─── Connect / handshake ────────────────────────────────────────────────────

  connect(): Promise<this> {
    return new Promise((resolve, reject) => {
      const { host = '127.0.0.1', port = 3306 } = this.options
      this._socket = createConnection({ host, port })
      this._socket.unref()

      this._socket.on('data', (chunk: Buffer) => this._parser.push(chunk))
      this._socket.on('error', (err: Error) => this._handleError(err))
      this._socket.on('close', () => {
        this._closed = true
        this.emit('close')
      })

      this._parser.on('packet', (pkt: Packet) => this._handlePacket(pkt))

      this._current = {
        state: 'handshake',
        resolve: resolve as (v: unknown) => void,
        reject
      }
    })
  }

  private _handlePacket(packet: Packet): void {
    if (!this._current) return

    switch (this._current.state) {
      case 'handshake':
        return this._handleHandshakePacket(packet)
      case 'auth_response':
        return this._handleAuthResponse(packet)
      case 'auth_switch':
        return this._handleAuthSwitch(packet)
      case 'caching_sha2_extra':
        return this._handleCachingSha2Extra(packet)
      default:
        if (this._current.handler) this._current.handler(packet)
    }
  }

  private _handleHandshakePacket(packet: Packet): void {
    const { payload } = packet
    this._sequenceId = packet.sequenceId + 1

    if (payload[0] === 0xff) {
      this._current!.reject!(decodeERR(payload))
      return
    }

    let offset = 1 // skip protocol-version byte
    const versionEnd = payload.indexOf(0, offset)
    const serverVersion = payload.toString('ascii', offset, versionEnd)
    offset = versionEnd + 1

    const connectionId = payload.readUInt32LE(offset)
    offset += 4
    const scramble1 = payload.slice(offset, offset + 8)
    offset += 8
    offset += 1 // filler

    const capLow = payload.readUInt16LE(offset)
    offset += 2
    offset += 1 // charset
    offset += 2 // status flags
    const capHigh = payload.readUInt16LE(offset)
    offset += 2
    const capabilities = capLow | (capHigh << 16)
    const authPluginDataLen = payload[offset]
    offset += 1
    offset += 10 // reserved

    const scramble2Len = Math.max(13, authPluginDataLen - 8)
    const scramble2 = payload.slice(offset, offset + scramble2Len - 1)
    offset += scramble2Len

    const scramble = Buffer.concat([scramble1, scramble2])

    let authPlugin = 'mysql_native_password'
    if (capabilities & Capabilities.CLIENT_PLUGIN_AUTH) {
      const pluginEnd = payload.indexOf(0, offset)
      authPlugin = payload.toString(
        'ascii',
        offset,
        pluginEnd === -1 ? undefined : pluginEnd
      )
    }

    this._handshakeInfo = {
      serverVersion,
      connectionId,
      scramble,
      authPlugin,
      capabilities
    }
    this._sendHandshakeResponse(scramble, authPlugin)
  }

  private _sendHandshakeResponse(scramble: Buffer, authPlugin: string): void {
    const user = this.options.user ?? 'root'
    const password = this.options.password ?? ''
    const database = this.options.database ?? ''

    let flags = CLIENT_FLAGS
    if (database) flags |= Capabilities.CLIENT_CONNECT_WITH_DB

    const authResponse =
      authPlugin === 'caching_sha2_password'
        ? cachingSha2Password(password, scramble)
        : nativePassword(password, scramble)

    const flagsBuf = Buffer.alloc(4)
    flagsBuf.writeUInt32LE(flags, 0)
    const maxPktBuf = Buffer.alloc(4)
    maxPktBuf.writeUInt32LE(0xffffff, 0)

    const authLen = Buffer.alloc(1)
    authLen[0] = authResponse.length

    const parts: Buffer[] = [
      flagsBuf,
      maxPktBuf,
      Buffer.from([45]), // charset: utf8mb4
      Buffer.alloc(23), // reserved
      Buffer.from(user + '\0', 'utf8'),
      authLen,
      authResponse
    ]

    if (database) parts.push(Buffer.from(database + '\0', 'utf8'))
    parts.push(Buffer.from(authPlugin + '\0', 'ascii'))

    this._sendPacket(Buffer.concat(parts))
    this._current = {
      state: 'auth_response',
      resolve: this._current!.resolve,
      reject: this._current!.reject
    }
  }

  private _handleAuthResponse(packet: Packet): void {
    const { payload } = packet
    this._sequenceId = packet.sequenceId + 1

    if (payload[0] === 0x00) {
      this._connected = true
      const resolve = this._current!.resolve as (v: unknown) => void
      this._current = null
      this._drainQueue()
      resolve(this)
      return
    }

    if (payload[0] === 0xff) {
      this._current!.reject!(decodeERR(payload))
      this._current = null
      return
    }

    if (payload[0] === 0xfe) {
      this._handleAuthSwitchRequest(packet)
      return
    }

    if (payload[0] === 0x01) {
      if (payload[1] === 0x03) {
        // caching_sha2 fast-auth OK — wait for the final OK packet
        this._current = {
          state: 'auth_response',
          resolve: this._current!.resolve,
          reject: this._current!.reject
        }
      } else if (payload[1] === 0x04) {
        // Full auth required (no cached hash). Rather than sending plaintext
        // password (which requires SSL), respond with mysql_native_password hash
        // using the original scramble. The server accepts this because we
        // already negotiated CLIENT_PLUGIN_AUTH.
        this._current = {
          state: 'caching_sha2_extra',
          resolve: this._current!.resolve,
          reject: this._current!.reject
        }
        const scramble = this._handshakeInfo!.scramble
        const authResponse = nativePassword(
          this.options.password ?? '',
          scramble
        )
        this._sendPacket(authResponse)
      }
    }
  }

  private _handleAuthSwitchRequest(packet: Packet): void {
    const { payload } = packet
    let offset = 1 // skip 0xfe

    const pluginEnd = payload.indexOf(0, offset)
    const pluginName = payload.toString('ascii', offset, pluginEnd)
    offset = pluginEnd + 1

    const newScramble = payload.slice(offset, payload.length - 1) // strip null terminator

    const authResponse =
      pluginName === 'caching_sha2_password'
        ? cachingSha2Password(this.options.password ?? '', newScramble)
        : nativePassword(this.options.password ?? '', newScramble)

    this._current = {
      state: 'auth_switch',
      resolve: this._current!.resolve,
      reject: this._current!.reject
    }
    this._sendPacket(authResponse)
  }

  private _handleAuthSwitch(packet: Packet): void {
    this._handleAuthResponse(packet)
  }
  private _handleCachingSha2Extra(packet: Packet): void {
    this._handleAuthResponse(packet)
  }

  // ─── Packet I/O ─────────────────────────────────────────────────────────────

  private _sendPacket(payload: Buffer): void {
    const pkt = buildPacket(payload, this._sequenceId++)
    this._socket!.write(pkt)
  }

  private _drainQueue(): void {
    if (this._current || this._queue.length === 0) return
    const next = this._queue.shift()!
    this._current = next
    next.start!()
  }

  // ─── Public query API ────────────────────────────────────────────────────────

  query(sql: string, values: SqlPrimitive[] = []): Promise<QueryResult> {
    return new Promise((resolve, reject) => {
      const start = () => {
        this._sequenceId = 0
        if (values.length > 0) {
          this._executePrepared(sql, values, resolve, reject)
        } else {
          this._executeTextQuery(sql, resolve, reject)
        }
      }

      if (!this._connected || this._current) {
        this._queue.push({
          start,
          resolve: resolve as (v: unknown) => void,
          reject
        })
      } else {
        this._current = {
          start,
          resolve: resolve as (v: unknown) => void,
          reject
        }
        start()
      }
    })
  }

  // ─── Text query (COM_QUERY) ──────────────────────────────────────────────────

  private _executeTextQuery(
    sql: string,
    resolve: ResolveQuery,
    reject: RejectQuery
  ): void {
    const sqlBuf = Buffer.from(sql, 'utf8')
    const payload = Buffer.concat([Buffer.from([Commands.COM_QUERY]), sqlBuf])
    this._sendPacket(payload)
    this._readQueryResult(resolve, reject, false)
  }

  // ─── Prepared statement (COM_STMT_PREPARE + COM_STMT_EXECUTE) ────────────────

  private _executePrepared(
    sql: string,
    values: SqlPrimitive[],
    resolve: ResolveQuery,
    reject: RejectQuery
  ): void {
    const preparePayload = Buffer.concat([
      Buffer.from([Commands.COM_STMT_PREPARE]),
      Buffer.from(sql, 'utf8')
    ])
    this._sequenceId = 0
    this._sendPacket(preparePayload)

    type PrepareState =
      | 'prepare_response'
      | 'param_defs'
      | 'col_defs'
      | 'execute'
    let state: PrepareState = 'prepare_response'
    let stmtId = 0,
      numParams = 0,
      numColumns = 0
    const paramDefs: ColumnInfo[] = []
    const colDefs: ColumnInfo[] = []

    const handler = (packet: Packet): void => {
      const { payload } = packet
      this._sequenceId = packet.sequenceId + 1

      if (state === 'prepare_response') {
        if (payload[0] === 0xff) {
          this._finishCurrent()
          reject(decodeERR(payload))
          return
        }
        stmtId = payload.readUInt32LE(1)
        numColumns = payload.readUInt16LE(5)
        numParams = payload.readUInt16LE(7)

        if (numParams === 0 && numColumns === 0) {
          this._executeStmt(stmtId, values, paramDefs, colDefs, resolve, reject)
          return
        }
        state = numParams > 0 ? 'param_defs' : 'col_defs'
      } else if (state === 'param_defs') {
        const isEof = payload[0] === 0xfe && payload.length < 9
        if (isEof) {
          // Classic EOF terminator — explicit signal from server
          state = numColumns > 0 ? 'col_defs' : 'execute'
          if (state === 'execute')
            this._executeStmt(
              stmtId,
              values,
              paramDefs,
              colDefs,
              resolve,
              reject
            )
          return
        }
        paramDefs.push(decodeColumnDefinition(payload))
        // CLIENT_DEPRECATE_EOF: no EOF packet, transition when count is reached
        if (paramDefs.length >= numParams) {
          state = numColumns > 0 ? 'col_defs' : 'execute'
          if (state === 'execute')
            this._executeStmt(
              stmtId,
              values,
              paramDefs,
              colDefs,
              resolve,
              reject
            )
        }
      } else if (state === 'col_defs') {
        const isEof = payload[0] === 0xfe && payload.length < 9
        if (isEof) {
          // Classic EOF terminator
          this._executeStmt(stmtId, values, paramDefs, colDefs, resolve, reject)
          return
        }
        colDefs.push(decodeColumnDefinition(payload))
        // CLIENT_DEPRECATE_EOF: transition when count is reached
        if (colDefs.length >= numColumns) {
          this._executeStmt(stmtId, values, paramDefs, colDefs, resolve, reject)
        }
      }
    }

    this._current!.handler = handler
  }

  private _executeStmt(
    stmtId: number,
    values: SqlPrimitive[],
    _paramDefs: ColumnInfo[],
    _colDefs: ColumnInfo[],
    resolve: ResolveQuery,
    reject: RejectQuery
  ): void {
    this._sequenceId = 0

    const nullBitmapSize = Math.ceil(values.length / 8)
    const nullBitmap = Buffer.alloc(nullBitmapSize, 0)
    values.forEach((v, i) => {
      if (v === null || v === undefined)
        nullBitmap[Math.floor(i / 8)] |= 1 << (i % 8)
    })

    const stmtIdBuf = Buffer.alloc(4)
    stmtIdBuf.writeUInt32LE(stmtId, 0)

    const payload = Buffer.concat([
      Buffer.from([Commands.COM_STMT_EXECUTE]),
      stmtIdBuf,
      Buffer.from([0x00]), // flags: CURSOR_TYPE_NO_CURSOR
      Buffer.from([0x01, 0x00, 0x00, 0x00]), // iteration-count = 1
      nullBitmap,
      Buffer.from([0x01]), // new-params-bound flag
      buildTypeBuffer(values),
      buildValuesBuffer(values)
    ])

    this._sendPacket(payload)
    this._readQueryResult(resolve, reject, true, stmtId)
  }

  // ─── Result reader ───────────────────────────────────────────────────────────

  private _readQueryResult(
    resolve: ResolveQuery,
    reject: RejectQuery,
    binary: boolean,
    stmtId: number | null = null
  ): void {
    type ResultState = 'field_count' | 'columns' | 'rows'
    let state: ResultState = 'field_count'
    const columns: ColumnInfo[] = []
    const rows: Record<string, unknown>[] = []

    let fieldCount = 0 // number of column definitions expected

    const handler = (packet: Packet): void => {
      const { payload } = packet
      this._sequenceId = packet.sequenceId + 1

      if (state === 'field_count') {
        if (payload[0] === 0x00) {
          // Mutation result (INSERT/UPDATE/DELETE) — no columns will follow
          const ok = decodeOK(payload)
          this._finishCurrent()
          if (stmtId !== null) this._closeStmt(stmtId)
          const result = Object.assign([], {
            count: ok.affectedRows,
            ...ok
          }) as unknown as QueryResult
          resolve(result)
          return
        }
        if (payload[0] === 0xff) {
          this._finishCurrent()
          reject(decodeERR(payload))
          return
        }
        // Column-count packet: payload[0] is a length-encoded integer
        fieldCount = payload[0]
        state = 'columns'
        return
      }

      if (state === 'columns') {
        // Distinguish a real EOF/OK terminator from a column definition whose
        // catalog string starts with 0x00 (length 0) or 0xfe (rare but valid).
        //
        // Safe rule: an EOF packet is always < 9 bytes.
        // An OK terminator (CLIENT_DEPRECATE_EOF) only arrives AFTER we have
        // already received all expected column definitions.
        const isEof = payload[0] === 0xfe && payload.length < 9
        const isOk = payload[0] === 0x00 && columns.length >= fieldCount

        if (isEof || isOk) {
          state = 'rows'
          return
        }

        columns.push(decodeColumnDefinition(payload))

        // With CLIENT_DEPRECATE_EOF the server sends no separate EOF between
        // columns and rows — transition as soon as the expected count is reached.
        if (fieldCount > 0 && columns.length >= fieldCount) {
          state = 'rows'
          // Do NOT return — fall through so the next packet is awaited normally.
        }
        return
      }

      if (state === 'rows') {
        // Classic EOF: 0xfe with payload < 9 bytes
        // Deprecate-EOF OK: 0x00 with payload < 9 bytes
        // Binary row packets also start with 0x00 but are always longer (null bitmap + data)
        // Text row packets never start with 0x00 or 0xfe (those are length-encoded strings)
        const isEof = payload[0] === 0xfe && payload.length < 9
        const isOk = payload[0] === 0x00 && payload.length < 9

        if (isEof || isOk) {
          this._finishCurrent()
          if (stmtId !== null) this._closeStmt(stmtId)
          const result = rows as unknown as QueryResult
          resolve(result)
          return
        }
        if (payload[0] === 0xff) {
          this._finishCurrent()
          reject(decodeERR(payload))
          return
        }
        rows.push(
          binary
            ? decodeBinaryRow(payload, columns)
            : decodeTextRow(payload, columns)
        )
      }
    }

    this._current!.handler = handler
  }

  private _closeStmt(stmtId: number): void {
    this._sequenceId = 0
    const payload = Buffer.alloc(5)
    payload[0] = Commands.COM_STMT_CLOSE
    payload.writeUInt32LE(stmtId, 1)
    this._sendPacket(payload)
  }

  private _finishCurrent(): void {
    this._current = null
    this._drainQueue()
  }

  private _handleError(err: Error): void {
    if (this._current?.reject) {
      const { reject } = this._current
      this._current = null
      reject(err)
    }
    this.emit('error', err)
  }

  // ─── ping / end / destroy ────────────────────────────────────────────────────

  ping(): Promise<void> {
    return new Promise((resolve, reject) => {
      const start = () => {
        this._sequenceId = 0
        this._sendPacket(Buffer.from([Commands.COM_PING]))
        this._current!.handler = (packet: Packet) => {
          const { payload } = packet
          this._finishCurrent()
          if (payload[0] === 0x00) resolve()
          else reject(decodeERR(payload))
        }
      }

      if (!this._connected || this._current) {
        this._queue.push({
          start,
          resolve: resolve as (v: unknown) => void,
          reject
        })
      } else {
        this._current = {
          start,
          resolve: resolve as (v: unknown) => void,
          reject
        }
        start()
      }
    })
  }

  end(): Promise<void> {
    return new Promise((resolve) => {
      const start = () => {
        this._sequenceId = 0
        this._sendPacket(Buffer.from([Commands.COM_QUIT]))
        this._socket!.end()
        this._current = null
        resolve()
      }

      const noop = () => {}
      if (!this._connected || this._current) {
        this._queue.push({
          start,
          resolve: resolve as (v: unknown) => void,
          reject: noop
        })
      } else {
        this._current = {
          start,
          resolve: resolve as (v: unknown) => void,
          reject: noop
        }
        start()
      }
    })
  }

  destroy(): void {
    this._socket?.destroy()
    this._closed = true
  }
}
