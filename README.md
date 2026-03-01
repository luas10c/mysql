# node-mysql

A MySQL client for Node.js using **raw TCP (`node:net`)** with **ES6 tagged template literals** and built-in SQL injection protection — inspired by the [`postgres`](https://www.npmjs.com/package/postgres) package.

Zero dependencies. Pure Node.js.

---

## Features

- ✅ Raw TCP connection via `node:net` — zero dependencies
- ✅ ES6 tagged template literal API
- ✅ Automatic SQL injection protection (parameterized queries via `COM_STMT_EXECUTE`)
- ✅ Connection pooling
- ✅ Transactions with automatic rollback on error
- ✅ Savepoints (nested transactions)
- ✅ Object INSERT/UPDATE helpers
- ✅ IN-list helpers for arrays
- ✅ Safe identifier quoting
- ✅ Type casting (numbers, dates, JSON, BigInt)
- ✅ `mysql_native_password` and `caching_sha2_password` auth plugins
- ✅ Binary protocol for prepared statements

---

## Installation

```bash
npm install mysql2-native
```

---

## Quick Start

```js
import mysql from 'node-mysql'

const sql = mysql({
  host:     'localhost',
  port:     3306,
  user:     'root',
  password: 'secret',
  database: 'mydb',
  max:      10,          // pool size (default: 10)
})

// Simple query — values are automatically parameterized
const users = await sql`SELECT * FROM users WHERE active = ${true}`
console.log(users) // Array of plain objects

await sql.end()
```

---

## API

### `mysql(options)` → `sql`

Creates a connection pool and returns a tagged template function.

| Option           | Default       | Description                        |
|------------------|---------------|------------------------------------|
| `host`           | `'127.0.0.1'` | MySQL server host                  |
| `port`           | `3306`        | MySQL server port                  |
| `user`           | `'root'`      | Username                           |
| `password`       | `''`          | Password                           |
| `database`       | `''`          | Default database                   |
| `max`            | `10`          | Max pool connections               |
| `idleTimeout`    | `30000`       | Idle connection timeout (ms)       |
| `connectTimeout` | `10000`       | TCP connect timeout (ms)           |
| `acquireTimeout` | `30000`       | Pool acquire timeout (ms)          |

---

### Tagged Template Queries

```js
// All interpolated values are sent as prepared statement parameters
const id = 42
const rows = await sql`SELECT * FROM users WHERE id = ${id}`

// rows is an Array with extra metadata:
rows.columns   // column definitions
rows.count     // number of rows
```

### Insert

```js
await sql`INSERT INTO users ${sql({ name: 'Alice', email: 'alice@example.com' })}`
// → INSERT INTO users (`name`, `email`) VALUES (?, ?)
```

### Update

```js
await sql`UPDATE users SET ${sql({ name: 'Bob' }, 'update')} WHERE id = ${1}`
// → UPDATE users SET `name` = ? WHERE id = ?
```

### IN Lists

```js
const ids = [1, 2, 3]
const rows = await sql`SELECT * FROM users WHERE id IN ${sql(ids)}`
// → SELECT * FROM users WHERE id IN (?, ?, ?)
```

### Safe Identifiers

```js
const table = 'users'
const rows = await sql`SELECT * FROM ${sql.identifier(table)}`
// → SELECT * FROM `users`
```

### Raw SQL (escape hatch)

```js
// Only use with values you fully control
const rows = await sql`SELECT ${sql.unsafe('NOW()')} AS time`
```

### Reusable Fragments

```js
const filter = sql.fragment`WHERE active = ${true} AND role = ${'admin'}`
const rows = await sql`SELECT * FROM users ${filter} LIMIT ${10}`
```

---

### Transactions

```js
const result = await sql.begin(async sql => {
  const [order] = await sql`INSERT INTO orders ${sql({ userId: 1, total: 99.99 })}`
  await sql`UPDATE users SET balance = balance - ${99.99} WHERE id = ${1}`
  return order
})
// Automatically commits on success, rolls back on any thrown error
```

### Savepoints (Nested Transactions)

```js
await sql.begin(async sql => {
  await sql`INSERT INTO logs ${sql({ event: 'start' })}`

  await sql.savepoint('checkout', async () => {
    await sql`UPDATE inventory SET stock = stock - ${1} WHERE id = ${productId}`
    // If this throws, only the savepoint is rolled back
  })
})
```

---

### Reserved Connections

```js
const reserved = await sql.reserve()
try {
  await reserved`SET @counter = 0`
  const [{ counter }] = await reserved`SELECT @counter AS counter`
} finally {
  reserved.release()
}
```

---

### Pool Stats

```js
const { total, idle, waiting } = sql.connections
```

### Close Pool

```js
await sql.end()
```

---

## SQL Injection Protection

All interpolated values in tagged templates go through **prepared statements** (`COM_STMT_PREPARE` + `COM_STMT_EXECUTE`) — they are **never** string-concatenated into SQL.

```js
const userInput = "'; DROP TABLE users; --"
// This is completely safe:
const rows = await sql`SELECT * FROM users WHERE name = ${userInput}`
// Actual SQL sent: SELECT * FROM users WHERE name = ?
// Value sent separately in binary protocol
```

The only exception is `sql.unsafe()`, which is explicitly named to indicate you're opting out of protection.

---

## Type Mapping

| JS Type      | MySQL Type         |
|--------------|--------------------|
| `null`       | NULL               |
| `boolean`    | TINYINT (0/1)      |
| `number`     | INT / DOUBLE       |
| `bigint`     | BIGINT             |
| `string`     | VARCHAR / TEXT     |
| `Date`       | DATETIME           |
| `Buffer`     | BLOB               |
| `object`     | JSON (serialized)  |

---

## Architecture

```
mysql() → Pool → Connection (node:net TCP socket)
                      ↓
              PacketParser (stream → packets)
                      ↓
              Handshake → Auth (sha1 / sha256)
                      ↓
              COM_STMT_PREPARE + COM_STMT_EXECUTE
                      ↓
              Binary protocol decode → plain JS objects
```

---

## License

MIT
