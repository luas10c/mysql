import type { Connection } from './connection'

export type FunctionWithArgs<T> = (connection: Connection) => Promise<T>
export type FunctionWithoutArgs<T> = () => Promise<T>

/**
 * Transaction wrapper.
 * Automatically commits on success, rolls back on error.
 */
export async function withTransaction<T>(
  connection: Connection,
  fn: FunctionWithArgs<T>
) {
  await connection.query('START TRANSACTION')
  try {
    const result = await fn(connection)
    await connection.query('COMMIT')
    return result
  } catch (err) {
    try {
      await connection.query('ROLLBACK')
    } catch {
      //
    }
    throw err
  }
}

/**
 * Savepoint support for nested transactions.
 */
export async function withSavepoint<T>(
  connection: Connection,
  name: string,
  fn: FunctionWithoutArgs<T>
) {
  const sp = `sp_${name}`
  await connection.query(`SAVEPOINT ${sp}`)
  try {
    const result = await fn()
    await connection.query(`RELEASE SAVEPOINT ${sp}`)
    return result
  } catch (err) {
    try {
      await connection.query(`ROLLBACK TO SAVEPOINT ${sp}`)
    } catch {
      //
    }
    throw err
  }
}
