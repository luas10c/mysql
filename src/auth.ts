import { createHash } from 'node:crypto'

/**
 * mysql_native_password
 * SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
 */
export function nativePassword(password: string, scramble: Buffer) {
  if (!password) return Buffer.alloc(0)
  const pass = Buffer.from(password, 'utf8')
  const stage1 = createHash('sha1').update(pass).digest()
  const stage2 = createHash('sha1').update(stage1).digest()
  const stage3 = createHash('sha1').update(scramble).update(stage2).digest()
  return xor(stage1, stage3)
}

/**
 * caching_sha2_password (fast auth path)
 * XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))
 */
export function cachingSha2Password(password: string, scramble: Buffer) {
  if (!password) return Buffer.alloc(0)
  const pass = Buffer.from(password, 'utf8')
  const p1 = createHash('sha256').update(pass).digest()
  const p2 = createHash('sha256').update(p1).digest()
  const p3 = createHash('sha256').update(p2).update(scramble).digest()
  return xor(p1, p3)
}

function xor(a: Buffer, b: Buffer) {
  const result = Buffer.alloc(a.length)
  for (let i = 0; i < a.length; i++) result[i] = a[i] ^ b[i % b.length]
  return result
}
