# Mantle Examples

A set of standalone examples covering mantle's typical usage. Each example is an
independent executable and shares the connection and printing helpers in
`common.zig`.

| Example | File | Demonstrates |
| --- | --- | --- |
| 01 connect | `01_connect.zig` | Connect, handshake, `ping`, read server version, graceful close |
| 02 query | `02_query.zig` | Text-protocol queries: single-/multi-row typed scans, `NULL` mapped to optional |
| 03 crud | `03_crud.zig` | Prepared-statement CRUD: parameterized `INSERT`/`SELECT`/`UPDATE`/`DELETE` |
| 04 transaction | `04_transaction.zig` | Transactions: `commit`, `rollback`, partial rollback via `savepoint` |
| 05 pool | `05_pool.zig` | Connection pool: lease/return, concurrent coroutines sharing a limited connection count |
| 06 tls | `06_tls.zig` | TLS (`CLIENT_SSL`) upgrade: encrypted handshake, selectable certificate verification, cipher proof |

## Running

The examples need a reachable MySQL server. Build them all first:

```sh
zig build examples
```

Run a single example (builds automatically):

```sh
zig build example-connect
zig build example-query
zig build example-crud
zig build example-transaction
zig build example-pool
zig build example-tls
```

The TLS example runs with certificate verification disabled by default, so it
works against a stock MySQL's auto-generated self-signed certificate. That is for
local development only. The production path verifies against the OS trust store;
select it (and the other policies) with `MANTLE_TLS_VERIFY`:

```sh
zig build example-tls                              # insecure (default, dev only)
MANTLE_TLS_VERIFY=self-signed zig build example-tls
MANTLE_TLS_VERIFY=system zig build example-tls     # production
```

The zio runtime prints debug logs to stderr. To see only the example output,
redirect stderr:

```sh
zig build example-query 2>/dev/null
```

## Configuring the target server

The default connection is `127.0.0.1:3306`, user `root`, password `root`.
Override via environment variables, no rebuild required:

| Variable | Default |
| --- | --- |
| `MANTLE_HOST` | `127.0.0.1` |
| `MANTLE_PORT` | `3306` |
| `MANTLE_USER` | `root` |
| `MANTLE_PASSWORD` | `root` |
| `MANTLE_DB` | (none; examples create their own `mantle_examples`) |

For example:

```sh
MANTLE_HOST=db.internal MANTLE_PASSWORD=secret zig build example-crud 2>/dev/null
```

Examples that need tables create and use the `mantle_examples` schema; tables are
`TEMPORARY` or `DROP`ped on exit, so no data is left behind — only an empty
`mantle_examples` database remains.
