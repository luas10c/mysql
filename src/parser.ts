import { EventEmitter } from 'node:events'
import { readUInt24LE } from './buffer'

const HEADER_SIZE = 4

/**
 * Reads a continuous TCP stream and emits complete MySQL packets.
 * Each packet: { sequenceId, payload: Buffer }
 */
export class PacketParser extends EventEmitter {
  _chunks: Buffer[]
  _bytesBuffered: number

  constructor() {
    super()
    this._chunks = []
    this._bytesBuffered = 0
  }

  push(chunk: Buffer) {
    this._chunks.push(chunk)
    this._bytesBuffered += chunk.length
    this._parse()
  }

  _concat() {
    if (this._chunks.length === 1) return this._chunks[0]
    return Buffer.concat(this._chunks)
  }

  _parse() {
    while (this._bytesBuffered >= HEADER_SIZE) {
      const buf = this._concat()
      const payloadLen = readUInt24LE(buf, 0)
      const packetLen = HEADER_SIZE + payloadLen

      if (this._bytesBuffered < packetLen) break

      const sequenceId = buf[3]
      const payload = buf.slice(HEADER_SIZE, packetLen)
      const remaining = buf.slice(packetLen)

      this._chunks = remaining.length ? [remaining] : []
      this._bytesBuffered = remaining.length

      this.emit('packet', { sequenceId, payload })
    }
  }
}
