export function readUInt24LE(buffer: Buffer, offset: number) {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16)
}

export function writeUInt24LE(buffer: Buffer, value: number, offset: number) {
  buffer[offset] = value & 0xff
  buffer[offset + 1] = (value >> 8) & 0xff
  buffer[offset + 2] = (value >> 16) & 0xff
}

export function readLengthEncodedInt(buffer: Buffer, offset: number) {
  const first = buffer[offset]
  if (first < 0xfb) return { value: first, bytesRead: 1 }
  if (first === 0xfc)
    return { value: buffer.readUInt16LE(offset + 1), bytesRead: 3 }
  if (first === 0xfd)
    return { value: readUInt24LE(buffer, offset + 1), bytesRead: 4 }
  if (first === 0xfe)
    return { value: Number(buffer.readBigUInt64LE(offset + 1)), bytesRead: 9 }
  return { value: null, bytesRead: 1 } // 0xfb = NULL
}

export function writeLengthEncodedInt(value: number) {
  if (value < 0xfb) {
    const buffer = Buffer.alloc(1)
    buffer[0] = value
    return buffer
  }
  if (value <= 0xffff) {
    const buffer = Buffer.alloc(3)
    buffer[0] = 0xfc
    buffer.writeUInt16LE(value, 1)
    return buffer
  }
  if (value <= 0xffffff) {
    const buffer = Buffer.alloc(4)
    buffer[0] = 0xfd
    writeUInt24LE(buffer, value, 1)
    return buffer
  }
  const buffer = Buffer.alloc(9)
  buffer[0] = 0xfe
  buffer.writeBigUInt64LE(BigInt(value), 1)
  return buffer
}

export function writeLengthEncodedString(str: string) {
  const strBuf = Buffer.from(str, 'utf8')
  return Buffer.concat([writeLengthEncodedInt(strBuf.length), strBuf])
}

export function readLengthEncodedString(buffer: Buffer, offset: number) {
  const { value: len, bytesRead } = readLengthEncodedInt(buffer, offset)
  if (len === null) return { value: null, bytesRead }
  return {
    value: buffer.toString(
      'utf8',
      offset + bytesRead,
      offset + bytesRead + len
    ),
    bytesRead: bytesRead + len
  }
}

export function readNullTerminatedString(buffer: Buffer, offset: number) {
  const end = buffer.indexOf(0, offset)
  return {
    value: buffer.toString('utf8', offset, end),
    bytesRead: end - offset + 1
  }
}

export function buildPacket(payload: Buffer, sequenceId: number) {
  const header = Buffer.alloc(4)
  writeUInt24LE(header, payload.length, 0)
  header[3] = sequenceId & 0xff
  return Buffer.concat([header, payload])
}
