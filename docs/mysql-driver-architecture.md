# Mantle MySQL Driver 架构设计

> 适用版本：mantle `0.0.0`（Zig `0.16.0`，基于 `zio` async I/O）
> 文档定位：描述**当前代码库的实际架构**，而非理想路线图。所有关键结论均锚定 `src/` 源码 `file:line`。
> 本文合并并取代旧的 `mysql-driver-architecture.md`（通用设计稿）与 `mysql-driver-architecture-survey.md`（跨生态调研稿）。协议字节级细节见 `docs/mysql-protocol-notes.md`，时间类型设计见 `docs/zig-datetime-architecture.md`。

---

## 0. 现状摘要（TL;DR）

mantle 是一个 Zig-native、基于 `zio` coroutine 的 MySQL/MariaDB driver，已落地一条**完整且生产可用的核心链路**：TCP 连接 → 握手认证 → 文本/二进制查询 → 流式或收集式结果解码 → prepared statement（comptime 参数绑定 + per-connection LRU 缓存）→ 事务/savepoint → 生产级连接池（代际失效 + 后台 reaper + 软取消）。

架构上的几个决定性特征：

1. **严格正交分层**，依赖单向向下：`transport` → `session/packet_stream` → `session/connection_phase` → `client/connection` → `result` / `pool`。协议解析层完全不感知 pool 或高层 API。
2. **协议解析全程边界检查、返回 error 而非 panic**：`PayloadReader` 的所有读取都先校验剩余长度（`payload_reader.zig:75-87`），越界返回 `error.EndOfPayload`，不存在 `assert`/`unreachable`。这是相对 myzql 的关键 production 硬化点。
3. **comptime 即多态**：prepared 参数绑定（`prepared_statement.zig:44-74`）与结果 scan-into-struct（`result/row.zig`）全部由 `@typeInfo` 在编译期展开，零运行时分派、零装箱。
4. **borrowed-by-default 的低拷贝解码 + 类型级所有权升级**：行字段默认借用 packet buffer，`scanAlloc` 把 `[]const u8` 复制进 arena 以延长生命周期（`connection.zig:488`、`row.zig`）。
5. **连接池与协议解耦、对 Driver 泛型**：`Pool(Driver)`（`pool.zig:73`）让真实 `TcpDriver` 与离线 mock 共用同一引擎，把代际失效/超时/泄漏核算等难逻辑做成可确定性测试的纯逻辑。
6. **async 由 `zio` 承载**：transport 读写、pool 的锁/条件变量/后台任务/软取消看门狗均走 zio 原语；协议层代码本身不含 async 关键字，I/O 在边界注入。

当前**尚未实现**的部分（详见 §19）：TLS、Unix socket、压缩、caching_sha2 full-auth（RSA）、`CLIENT_DEPRECATE_EOF`、SQL parser / 命名参数 / 文本插值。

---

## 1. 模块地图与依赖方向

```text
src/
  mantle.zig            ── 公共入口，re-export 全部 public API

  transport.zig         ── 字节流边界：zio.net 适配、AnyReader/AnyWriter、16MB 逻辑包读写
  session/
    packet_stream.zig   ── 帧分包 + sequence 计数 + 结果格式状态
    connection_phase.zig── 协议状态机：握手 / 认证 / 命令 / 结果流
  protocol/             ── 无状态 wire codec（纯函数，可独立单测）
    protocol.zig        ──   子系统聚合入口
    types.zig           ──   PacketHeader / SequenceTracker / Error 集
    packet.zig          ──   16MB 分片读写 + length-encoded 帮助
    payload_reader.zig  ──   零拷贝、边界检查的 payload 解析
    payload_writer.zig  ──   payload 构造（ArrayList 复用）
    capability.zig      ──   CLIENT_* / SERVER_STATUS_* 标志
    collation.zig       ──   charset/collation id
    handshake.zig       ──   HandshakeV10 解析 + Response41 编码 + 能力协商
    auth.zig            ──   认证插件、scramble 算法、auth packet 分类
    command.zig         ──   COM_* 命令枚举与编码
    response.zig        ──   OK / ERR / EOF 通用响应解析
    text_result.zig     ──   ColumnDefinition41 + 文本行
    binary_result.zig   ──   二进制行
    prepared_statement.zig ── COM_STMT_* 编码 + comptime 参数绑定
    decimal.zig temporal.zig ── 驱动自有 Decimal / DateTime / Time 类型
  result/               ── 结果解码（面向用户的类型映射）
    type_mapper.zig     ──   MySQL field type → LogicalType
    column_reader.zig   ──   text/binary 对称列读取 + 类型校验
    row.zig             ──   行装饰 + comptime scan + ScanError 诊断
    decode_adapter.zig  ──   用户扩展类型（fromMantle*）桥接
  client/               ── 用户句柄与命令编排
    connection.zig      ──   命令生命周期、broken/closed、错误模型、高层 API
    statement.zig       ──   PreparedStatement + per-conn LRU StatementCache
    transaction.zig     ──   Transaction guard / scoped transact / savepoint
    table.zig           ──   Table(T) owned 结果集（arena-backed）
  pool.zig              ── Pool(Driver) + TcpDriver + Watchdog 软取消
```

**依赖方向不变量**：`protocol/*` 只依赖 `std`，是纯 codec；`session/*` 依赖 `protocol`；`transport` 依赖 `session` + `zio`；`client/*` 依赖 `transport`；`pool` 依赖 `client` + `zio`。`mantle.zig` 在顶层聚合（`mantle.zig:1-27`）。该方向由实际 `@import` 结构保证，不存在反向依赖。

---

## 2. 分层运行时模型

一次查询自上而下穿过五层，每层只承担单一职责：

| 层 | 实现 | 持有状态 | 职责 |
| --- | --- | --- | --- |
| **高层 API / 编排** | `client/connection.zig` | broken/closed、last_error、statement_cache、in_transaction | 命令生命周期、错误归类、结果收集、事务/语句缓存编排 |
| **协议状态机** | `session/connection_phase.zig` | `State`、server_connection_id、negotiated options | 约束合法的包流顺序，握手/认证/命令/结果转移 |
| **帧 + 序列** | `session/packet_stream.zig` | next_sequence_id、result_column_count、result_format | packet 分帧、sequence 计数、结果集格式判定 |
| **字节流** | `transport.zig` | io(reader/writer)、packet_stream | 16MB 逻辑包读写、zio 适配、命令收发 |
| **wire codec** | `protocol/*` | 无（纯函数） | 编解码、边界检查、类型化 |

横切层：`result/*`（被 `client` 调用做类型化解码）、`pool.zig`（管理物理连接复用，包裹 `client/connection`）。

---

## 3. Transport 层（`transport.zig`）

Transport 只处理字节流，不理解 SQL，也不理解 MySQL 类型。

### 3.1 I/O 抽象：手工 vtable

`Transport` 不是 `union(enum) { plain, tls }`，而是组合 `Io { reader: AnyReader, writer: AnyWriter }`（`transport.zig:132-146`）。`AnyReader`/`AnyWriter` 用 `*anyopaque` context + 函数指针实现类型擦除（`transport.zig:7-23`），后端可替换（当前仅 TCP，未来 TLS/Unix socket 包装无需改上层）。

`ZioStream`（`transport.zig:400-441`）把 `zio.net.Stream` 适配成 `AnyReader`/`AnyWriter`，并携带 `zio.Timeout`，在 `stream.read`/`stream.writeAll` 处统一施加读写超时（`transport.zig:434,439`）。

### 3.2 16MB 逻辑包读写

`readLogicalPayload`（`transport.zig:443-469`）循环读取物理包，用 `SequenceTracker` 校验每包 sequence 递增，把 payload 累积进 `ArrayList`，直到某包 `payload_length < max_packet_payload_size`（`0x00ff_ffff`）为止；写侧由 `protocol.packet.writeLogicalPayload` 反向分片。两侧都正确处理「逻辑长度恰为 0xFFFFFF 整数倍需追加空包」的边界。

### 3.3 命令收发与响应分类

- `sendCommand` / `sendCommandPayload` / `sendNoResponseCommand`：经 `PacketStream` 帧化后写出（`transport.zig:167-201`）。
- `receiveNext`：驱动握手/认证阶段，必要时回写客户端响应包（`transport.zig:148-165`）。
- `readQueryResponse` 返回 `QueryResponse = union { ok: OkSummary, err: ServerError, result_set }`；首字节 `0xff` → ERR，其余结合 `GenericResponse` 分类；`LOCAL INFILE` 请求被显式拒绝为 `error.LocalInfileDisabled`（`transport.zig:203-226`）。
- 行/元数据读取：`readTextRow` / `readBinaryRow` / `readTextResultMetadata` / `readColumnDefinitions` / `readPrepareResponse`，供 `client/connection` 调用。

> **现状**：仅 TCP（`zio.net`），无 TLS、无 Unix socket、无压缩。`capability.client_ssl` 常量已定义（`capability.zig:15`）但握手协商不置位、不发 `SSLRequest`。

---

## 4. PacketStream 层（`session/packet_stream.zig`）

`PacketStream`（`packet_stream.zig:6-27`）在 transport 与协议状态机之间承担分帧与计数：

- 持有 `ConnectionPhase`、`next_sequence_id`、`result_column_count`、`result_format(text|binary)`。
- `receiveServerPayload` 按 `phase.state` 路由到握手/认证/命令/结果流处理，并在需要时通过 `writeLogicalPayload` + `nextClientSequence`（u8 wrapping 自增）回写客户端包（`packet_stream.zig:29-70`）。
- `sendCommand` 把新命令的 sequence 复位、`result_format` 默认 `.text`；`sendCommandPayload`（prepared execute）置 `.binary`（`packet_stream.zig:78-92`）。
- 结果流按格式分派到 `receiveTextResultStreamPacket(column_count)` 或 `receiveBinaryResultStreamPacket`（`packet_stream.zig:125-133`）。文本流靠列数判定 EOF/行边界，二进制流靠 `0xfe`/`0xff` 首字节。

---

## 5. 协议状态机（`session/connection_phase.zig`）

MySQL 是有状态串行协议，mantle 用显式状态机约束合法的包流。

### 5.1 状态与动作

```text
State:  awaiting_handshake → authenticating → ready
        ready → command_inflight → (result_streaming) → ready
        任意错位/失败 → failed
Action: none | send_handshake_response | send_auth_response
        | send_command | start_result_stream | local_infile_request
```

（`connection_phase.zig:6-24`）

规则：只有 `ready` 能发新命令；命令进入 `command_inflight`；结果集进入 `result_streaming`，drain 完回 `ready`；`failed` 为不可复用终态。`isBroken()` 把 `phase.state == .failed` 也算作 broken（`connection.zig:221-223`）。

### 5.2 握手与认证

- `receiveInitialHandshake`：解析 `HandshakeV10`、记录 `server_connection_id`（用于跨连接 `KILL QUERY`）、协商 capability、按协商插件算 scramble、写 `HandshakeResponse41`（`connection_phase.zig:47-84`）。
- 能力协商 `negotiateClientFlags`（`handshake.zig:135-165`）：基线 `client_protocol_41 | client_secure_connection`；按 server 支持度叠加 `client_plugin_auth`、`client_plugin_auth_lenenc_client_data`、`client_connect_with_db`。**不**协商 `DEPRECATE_EOF`/`SESSION_TRACK`/`CONNECT_ATTRS`/`OPTIONAL_RESULTSET_METADATA`（常量已定义但未启用）。因此结果集仍走 EOF 包语义。
- `receiveAuthPacket`：按 `AuthPacketTag.classify`（`auth.zig:42-51`）分流 OK/ERR/Auth-Switch/Auth-More-Data。Auth-Switch 重算 scramble 回写；Auth-More-Data 仅识别 caching_sha2 **fast-auth 成功**，其余（full-auth）返回 `error.UnsupportedAuthExchange`（`connection_phase.zig:86-121`）。

### 5.3 命令与多结果集

`receiveCommandResponse` 把 OK/ERR/result_set/local_infile 映射为状态转移（`connection_phase.zig:123-197`）。结果终止符（EOF/OK）携带 `SERVER_MORE_RESULTS_EXISTS` 时保持在 `command_inflight` 而非回到 `ready`，从而原生支持多结果集 drain（`connection_phase.zig:240-249`）。`client/connection.drainRemainingResults` 据此把残留结果读尽，保证连接归还前流已同步（`connection.zig:332-351`）。

---

## 6. Protocol Codec（`protocol/*`）

无状态、可独立单测的纯 codec 层。

### 6.1 零拷贝 + 边界检查的读写

`PayloadReader`（`payload_reader.zig`）所有读取先查 `remaining()`，越界返回 `error.EndOfPayload`；`readLengthEncodedInteger` 对 `0xfb/0xff` 返回 `error.InvalidLengthEncodedInteger`（`payload_reader.zig:32-41`）；`readLengthEncodedString`/`readRemaining`/`readFixedBytes` 返回**指向输入 buffer 的 slice**（借用，零拷贝）。`PayloadWriter` 用 `ArrayList` 复用缓冲构造 payload。

`packet.zig` 负责 4 字节头（3B 小端长度 + 1B sequence）与 16MB 分片；`types.zig` 定义 `PacketHeader`、`SequenceTracker`、统一 `Error` 集合与 `max_packet_payload_size`。

### 6.2 命令与响应

`command.zig` 建模驱动实际发出的 `COM_*` 子集：`quit(0x01)`、`query(0x03)`、`ping(0x0e)`、`reset_connection(0x1f)`、`stmt_prepare(0x16)`、`stmt_execute(0x17)`、`stmt_send_long_data(0x18)`、`stmt_close(0x19)`、`stmt_reset(0x1a)`（`command.zig:21-47`），由 `Command` tagged union + `write` 编码（`command.zig:59-140`）。

`response.zig` 解析 OK/ERR/EOF；server error 保留 code / SQL state / message（`ServerError`，由 `transport` re-export）。

### 6.3 结果集 codec

`text_result.zig` 定义 `ColumnDefinition41` 与文本行；`binary_result.zig` 解析二进制行（null bitmap offset 2，与 execute 参数的 offset 0 区分）。两者均借用 packet buffer。

### 6.4 类型 codec

`decimal.zig` / `temporal.zig` 定义驱动自有 `Decimal`（借用 bytes）、`DateTime`、`Time`，并提供 `validate*` 做范围检查（年/月/日按月校验、TIME 总小时 ≤ 838、微秒 ≤ 999999）。

---

## 7. 认证现状（`protocol/auth.zig` + `connection_phase.zig`）

| 插件 | scramble 实现 | 端到端可用 |
| --- | --- | --- |
| `mysql_native_password` | `scrambleNativePassword`（SHA1，`auth.zig:96-107`） | ✅ |
| `caching_sha2_password` | `scrambleCachingSha2Password`（SHA256，`auth.zig:109-120`） | ✅ 仅 fast-auth / 空密码 |
| `sha256_password` | — | ❌ 未接入 |
| `mysql_clear_password` | — | ❌ 未接入 |

- Auth Switch、Auth More Data 已支持分类与 fast-auth 成功识别（`auth.zig:54-94`）。
- caching_sha2 **full-auth（RSA 公钥加密密码）路径仅有脚手架**：marker 常量、`writePublicKeyRequest`、`isCachingSha2FullAuthenticationStart`/`isCachingSha2PublicKeyResponse` 已存在（`auth.zig:29-33,134-141`），但状态机未驱动它，full-auth 当前返回 `error.UnsupportedAuthExchange`。
- 由于无 TLS，full-auth 与明文密码路径都不可用——**非安全连接下只能走 fast-auth 命中或空密码**。
- 安全约束：scramble 在内部 buffer 原地计算，不记录密码/salt。

---

## 8. Connection 编排层（`client/connection.zig`）

`Connection`（`connection.zig:122-147`）是用户句柄，包裹 `Transport` 并叠加应用级状态：`broken`、`closed`、`last_error`、`statement_cache`、`in_transaction`。

### 8.1 命令生命周期与状态防护

每个命令入口先 `ensureUsable()`（closed→`ConnectionClosed`，broken→`ConnectionBroken`，`connection.zig:251-254`）。错误经 `classifyError` 归类：I/O/协议错位类错误置 `broken=true`，而 server error、参数校验、prepared usage 等「软错误」保持连接可复用（`connection.zig:259-274`）。这条白名单是「连接是否回池」的核心判据。

`canReuse()` 三条同时成立才可回池：非 closed、非 broken、`phase.state == .ready`（`connection.zig:225-227`）。`markBroken()` 供软取消后强制弃用（`connection.zig:247-249`）。

### 8.2 错误模型

- 返回 `QueryResult` union 的路径（`query`/`execute`/`executeParams`）把 server error 作为 `.err` 变体交还调用方并 clone 进 `last_error`。
- 「吞错」路径（`queryRows`/`executeRows`/`exec`/`ping`/`execSimple`）把 server error 收进 `last_error` 并返回 `error.ServerError`，调用方用 `lastError()` 取结构化 code/SQLstate/message（`connection.zig:229-233`）。
- 未 drain 的结果集若出现在期望 OK 的路径，直接 `broken=true`（流已失步，`connection.zig:803-809`）。

### 8.3 高层 API 一览

| API | 协议 | 返回 | 所有权 |
| --- | --- | --- | --- |
| `query` / `queryRows` | 文本 | QueryResult / TextResult(流式) | 行借用 buffer |
| `queryAll(T)` / `queryOne(T)` | 文本 | `Table(T)` | arena owned |
| `prepare` / `execute` / `executeParams` / `executeRows` | 二进制 | PreparedStatement / QueryResult / BinaryResult | 行借用 buffer |
| `exec(sql, params)` | 二进制 | OkSummary | 经缓存的 prepared |
| `queryAllParams(T)` / `queryOneParams(T)` | 二进制 | `Table(T)` | arena owned |
| `ping` / `reset` / `close` | — | — | reset 清 in_transaction + last_error；close 发 `COM_QUIT` |

流式 `TextResult`/`BinaryResult` 提供 `next`/`drain`，并在 drain 后调用 `drainRemainingResults` 处理多结果集（`connection.zig:66-119`）。

---

## 9. Prepared Statement 与语句缓存

### 9.1 comptime 参数绑定（`prepared_statement.zig`）

`ExecuteRequest.writeWithParams`（`prepared_statement.zig:44-74`）按 `@typeInfo(params)` 的 struct/tuple 字段在编译期展开：写 null bitmap → `new_params_bind_flag` → 每参数 `(field_type, unsigned_flag)` → 每参数值。`paramCount`/`fieldTypeForParam`/`unsignedFlagForParam` 全为 comptime，把 Zig 类型映射到 MySQL `FieldType`：

- 整数按位宽映射 tiny/short/long/longlong，带 signed/unsigned flag；float/double；`[]const u8`/数组 → var_string（length-encoded）。
- `optional`/`null` 进 null bitmap（`prepared_statement.zig:89-109`）。
- 驱动自有 `Decimal`/`DateTime`/`Time` 走专用编码（长度码 0/4/7/11、0/8/12），均先 `validate*`。
- **encode adapter**：用户类型声明 `toMantleText`/`toMantleDateTime`/`toMantleTime` 之一即可自定义编码，签名由 `validateEncodeAdapter` 在编译期校验（`prepared_statement.zig:111-219`）。与 result 侧 `fromMantle*` 对称，使驱动对具体 decimal/datetime 库保持中立。

类型不匹配在编译期 `@compileError`，参数个数不匹配在运行时 `error.PreparedParameterCountMismatch`（`connection.zig:843-845`）。

### 9.2 PreparedStatement 归属与安全

`PreparedStatement`（`statement.zig:8-28`）持 `id`、params/columns 元数据、`conn` 反指针、`closed` 标志。`ensureStatementUsable` 拒绝跨连接使用（`PreparedStatementWrongConnection`）与已关闭语句（`connection.zig:292-297`）——statement id 不跨连接复用是硬约束。`deinit` 在语句仍属活连接时发 `COM_STMT_CLOSE`。

### 9.3 per-connection LRU 缓存（`statement.zig:39-129`）

`StatementCache` 用 `StringHashMap`（O(1) 查找）+ 侵入式双向链表（O(1) LRU 移动），默认容量 256（`default_statement_cache_capacity`）。`exec`/`queryAllParams`/`queryOneParams` 透明复用缓存语句，省去重复 prepare/close 往返。缓存严格 per-connection，连接 broken/closed 时整表丢弃（`freeCacheNode` 的 `send_close` 据连接健康度决定是否真的发 `COM_STMT_CLOSE`）。

`ER_NEED_REPREPARE`（1615）处理：缓存语句因 schema 变更失效时，evict 后重 prepare 一次（`connection.zig:529-536,793-798`）——缓存不会把陈旧语句永久卡死。

---

## 10. Result / Row 解码（`result/*`）

### 10.1 类型映射两级拆分

- `type_mapper.zig`：`fromColumn` 把 `(field_type, unsigned_flag, charset)` 映射到 8 个 `LogicalType`（signed/unsigned integer、float、decimal、text、blob、temporal、null）。另有 `DecodeCategory`（datetime/time/bytes/other）供 adapter 选择中间表示。
- `column_reader.zig`：`Context` 集中列索引/列数一致性校验与 `expect*Type` 谓词（`column_reader.zig:12-59`），提供 text/binary **完全对称**的 `readText*`/`readBinary*`（int/float/bool/bytes/decimal/datetime/time）。整数读取按 `comptime T` 特化 + 运行时按字节长度 switch（无单独 fast-path 函数，但路径本身定长直读）。

### 10.2 comptime scan-into-struct（`row.zig`）

`TextRowResult`/`BinaryRowResult` 装饰 transport 行，`scan(&dest, columns)` 用 `inline for` 遍历目标 struct 字段，按字段名查列、按 `@typeInfo(field.type)` 分派到对应 reader（`row.zig` scan 系列）。支持 int/float/bool、`optional`（NULL→null，非 optional 遇 NULL→`error.UnexpectedNullValue`）、`Decimal`/`DateTime`/`Time` struct、`[]const u8` pointer，以及 decode adapter 优先。

### 10.3 借用 vs 拥有

- `scan`：字段借用 packet buffer，下一次 `next`/网络请求即失效。
- `scanAlloc(dest, columns, str_allocator)`：把 `[]const u8` 字段复制进给定 allocator，用于 owned 收集。`queryAll`/`queryAllParams` 据此把每行 scan 进一个 `ArenaAllocator`，整张 `Table(T)` 由单次 `deinit` 释放（`connection.zig:463-495`、`table.zig`）。

### 10.4 诊断与扩展

- `ScanError` 记录失败字段名、列名、列索引、目标类型与底层 reason，存于 `last_scan_error`，便于定位「哪个字段、哪列、转成什么类型时失败」。
- `decode_adapter.zig`：用户类型声明 `fromMantleText`/`fromMantleDateTime`/`fromMantleTime` 即可解码 JSON/GUID/GEOMETRY 等扩展类型，签名 comptime 校验，按列的 `DecodeCategory` 选择 text/binary 中间表示。

---

## 11. 事务（`client/transaction.zig`）

`Transaction` 是连接独占的 guard（`transaction.zig:60-137`）：

- `begin`/`beginWith` 防止嵌套（`in_transaction` 已置位时返回 `error.TransactionActive`，避免 `START TRANSACTION` 触发隐式提交）；可选 isolation level（`SET TRANSACTION ISOLATION LEVEL ...`，仅作用于下个事务）与 access mode。
- `transact`/`transactWith`：scoped 闭包，成功 commit、失败 rollback，是默认安全用法（提交/回滚决策无法遗忘）。
- `deinit`：未 finish 时 best-effort `ROLLBACK`（errdefer 友好的手动 guard 用法）。
- **rollback 失败 → 连接 broken**（状态未知不可信，`transaction.zig:76-84`）。
- savepoint：`savepoint`/`rollbackTo`/`releaseSavepoint`/`withSavepoint`，标识符经 `buildSavepointSql` backtick 转义（内部反引号翻倍），杜绝注入（`transaction.zig:42-55`，含单测）。

---

## 12. 连接池（`pool.zig`）

### 12.1 对 Driver 泛型

`Pool(Driver)`（`pool.zig:73`）要求 Driver 暴露 `Handle`、`open`/`close`/`nowNs`，`Handle` 暴露 `canReuse()`/`isBroken()`。真实 `TcpDriver`（`pool.zig:532-619`）经 `zio.net` 拨号并 `finishHandshake`；离线 mock 注入可控连接与可控时钟，使代际失效、lifetime/idle 过期、复用/销毁判定、容量阻塞、泄漏核算都能**无服务器确定性测试**。`TcpPool = Pool(TcpDriver)`（`pool.zig:622`）是大多数消费者直接用的类型。

### 12.2 并发模型

单 `zio.Mutex` 保护池状态，`zio.Condition`（`idle_available`）在满容量时 park `acquire` 调用方（`pool.zig:110-111,182-236`）。不变量：每次开连接都在 `total_count < max_connections` 守卫下预留槽位，`total_count` 永不超限；`driver.open`/`close` 的 I/O **始终在锁外**执行，慢连接不阻塞持锁协程。`acquire_timeout` 解析为固定 deadline，避免每轮 `timedWait` 重置时钟（`pool.zig:184-185`）。

### 12.3 生产级生命周期管理

- **代际失效**：`clear()` 递增 `generation`，idle 连接立即关闭，leased 连接在 `release` 时按 generation 不匹配淘汰（`pool.zig:284-304`）。
- **后台 reaper**（`startReaper` → `reaperLoop`，`pool.zig:160-172`）：周期性 `reapOnce` 淘汰过期/陈旧 idle，并把 idle 补到 `min_idle`（prewarm）。`reapOnce` 公开，供离线测试同步驱动（`pool.zig:309-387`）。
- **回收判定**：`release` 用「非 closed + generation 匹配 + `canReuse()` + 未超 lifetime」判定可复用，否则销毁（`pool.zig:256-279`）；`canLeaseIdle`/`shouldRetire` 额外考虑 idle timeout（`pool.zig:503-527`）。
- **诊断/泄漏核算**：`Stats { idle, leased, total, generation, closed }`（`pool.zig:50-56,467-477`），`leased_count` 跟踪未归还租约。

### 12.4 软取消（命令超时）

`Watchdog`（`pool.zig:404-437`）`arm` 后起 zio 协程，超时未 `disarm` 则对目标 server thread 发 `KILL QUERY`。`queryTimed`（`pool.zig:444-464`）组合：arm → `conn.query` → disarm；若已 fired 则 `markBroken`（可能残留 pending cancellation，必须弃用）并返回 `error.CommandTimeout`。`killQuery`（`pool.zig:604-618`）开短连接发 `KILL QUERY <thread_id>`，目标线程的 `serverThreadId()` 来自握手。`ER_NO_SUCH_THREAD`（1094，查询已结束）视为成功。

---

## 13. 公共 API 表面（`mantle.zig`）

re-export：`Connection`、`PreparedStatement`、`Transaction`/`IsolationLevel`/`AccessMode`/`TxOptions`、`Table`、`QueryResult`/`OkSummary`/`ServerError`、`DateTime`/`Time`/`Decimal`、`Pool`/`PoolConfig`/`PoolStats`/`TcpDriver`/`TcpPool`、以及 `protocol`/`transport`/`column_reader`/`type_mapper`/`ConnectionPhase`/`PacketStream` 等底层模块（供高级用户与测试用）。`examples/01..05` 覆盖 connect/query/crud/transaction/pool 学习路径。

---

## 14. 错误模型与连接可复用矩阵

| 错误类别 | 代表 | 连接是否可复用 | 处理点 |
| --- | --- | --- | --- |
| I/O / 协议错位 | EOF、invalid sequence、UnexpectedResultSet | 否（broken） | `classifyError` 默认分支 |
| Server error | syntax、duplicate key、ER_NEED_REPREPARE | 通常是（drain 后） | `last_error` / `.err` 变体 |
| Handshake/Auth 失败 | UnsupportedAuthExchange、HandshakeFailed | 否（phase=failed） | `isBroken()` |
| Conversion | UnexpectedNull、类型不符 | drain 后可 | `ScanError` / `last_scan_error` |
| Usage | ConnectionClosed、PreparedStatementWrongConnection、ParamCountMismatch | 视情况（多为软错误） | `ensureUsable`/`ensureStatementUsable` |
| Pool | AcquireTimeout、PoolClosed、CommandTimeout | 无连接 / 软取消后弃用 | `pool.zig` |

server error 始终暴露 code / SQL state / message，调用方无需解析日志。

---

## 15. 安全默认

- `LOCAL INFILE` 默认拒绝（`error.LocalInfileDisabled`，`transport.zig`/`connection_phase.zig`）。
- multi-statements 未启用（不协商相关 capability）。
- 参数化执行优先：`exec`/`*Params` 走 prepared 二进制协议，不做值拼接；savepoint 标识符强制 backtick 转义。
- 认证 scramble 内部计算，不记录敏感值。
- **TLS 缺失是当前最大安全短板**（见 §19）：生产明文 TCP 部署需自行保证网络可信。

---

## 16. 并发模型

- **单连接串行**：MySQL 单连接不可 multiplex，mantle 不在单连接上伪造并发；并发由连接池承载。状态机保证「下一条命令前必须 drain 当前响应」。
- **async via zio**：transport I/O、pool 锁/条件变量/reaper/watchdog 均为 zio 协程友好原语；协议层为纯同步代码，async 在 transport 边界注入，便于单测。
- **pinning 约束**：`Pool` 与 `Driver.Handle` 在 `init` 后不可移动（Lease/reaper 持指针，Handle 内嵌 `Connection` 的 reader/writer 指向内嵌 `ZioStream`）；`TcpDriver.open` 返回堆指针（`pool.zig:18-24,563-579`）。

---

## 17. 测试与 Benchmark 架构（`build.zig`）

- `zig build test`：模块内 `test {}` 块聚合的离线单测（`mantle.zig:29-55`），覆盖 packet/lenenc/握手/auth/result/pool 等纯逻辑；pool 用 mock driver + mock clock 确定性验证。
- `zig build integration_test`：`integration_tests/` 针对真实 MySQL（connection/pool/statement_cache）。
- `zig build benchmark`：`-Doptimize=ReleaseFast` 下跑真实库基准。
- `zig build examples` / `example-<name>`：编译/运行示例（`MANTLE_*` 环境变量配置）。

---

## 18. 当前实现边界（诚实差距）

以下为**尚未落地**、但架构已留位或为已知 roadmap 项：

| 缺口 | 现状 | 影响 |
| --- | --- | --- |
| **TLS** | `client_ssl` 常量在，握手不协商、transport 无实现 | 明文连接；caching_sha2 full-auth 不可用 |
| **caching_sha2 full-auth（RSA）** | marker/helper 脚手架在，状态机未驱动 | 非空密码且未命中 fast-auth 时认证失败 |
| **Unix socket / 压缩** | 无 | 仅 TCP 非压缩 |
| **sha256_password / mysql_clear_password** | 枚举在，无 scramble 接入 | 不支持这些插件 |
| **SQL parser / 命名参数 / 文本插值** | 无；仅 `?` 位置参数 via comptime tuple/struct | 无命名参数、无单轮文本插值选项 |
| **DEPRECATE_EOF / SESSION_TRACK / CONNECT_ATTRS** | 常量在，未协商 | 走 EOF 包；无会话状态跟踪/连接属性 |
| **可观测性指标/ tracing** | 仅 `Pool.Stats` 计数 | 无 query duration / rows / bytes / cache hit 等细粒度指标 |
| **多 host failover / 负载均衡** | 单 host `TcpDriver` | 无 failover/round-robin |

这些差距不影响已实现链路的正确性与可用性，但定义了下一阶段优先级（TLS + full-auth 优先级最高，因其同时是安全与兼容性门槛）。

---

## 19. 设计血统

mantle 的架构决策吸收了跨生态调研结论，并以 Zig 语言优势重新表达：

- **正交分层 + session/connection 概念分离**（对标 .NET MySqlConnector 的 `ServerSession` vs `MySqlConnection`）：mantle 中物理会话状态分布在 `ConnectionPhase`/`PacketStream`/`Transport`，pool 的 `Session` 包裹 `Handle`，与用户句柄 `Connection` 解耦。
- **二进制 prepared 为高性能默认 + per-connection statement cache**（对标 sqlx/MySqlConnector）：`exec`/`*Params` 默认 prepared 路径，缓存生命周期与连接绑定、随 broken 整表失效。
- **把解码热路径从「解释」变「编译」**（mysql2 运行时 codegen / asyncmy Cython / sqlx `Decode<'r>` 的共同目标）：mantle 用 `comptime` 直接 scan-into-struct 与参数绑定，零运行时代价、零装箱。
- **borrowed-by-default + 类型级所有权升级**（继承 myzql 的 `readRef*`，超越其纯文档契约）：`scan` 借用、`scanAlloc` 拥有，由 API 形态强制调用方在数据失效前显式升级。
- **协议解析返回 error 而非 panic**（修复 myzql 用 `assert/unreachable` 的 production 隐患）：`PayloadReader` 全程边界检查，错位连接进入不可复用状态。
- **生产级池直接对标 MySqlConnector**：semaphore 语义（mutex+condition+容量守卫）、idle 链表、租借跟踪、`COM_RESET_CONNECTION` 复用、代际失效、后台 reaper、归还健康检查；泄漏回收用显式 RAII/`Lease.release` + `leased_count` 替代 .NET 的 `WeakReference`（Zig 无 GC，必须改写而非照抄）。
- **软取消是协议问题而非「关 socket」**（对标 MySqlConnector 的 cancellation）：`Watchdog` + `KILL QUERY` 软取消，取消后 `markBroken` 防止 pending cancellation 误伤后续命令。

---

## 20. 生产级检查清单（当前达成度）

- [x] packet sequence id 校验、16MB 大包读写
- [x] 协议解析边界检查、错位连接不可复用
- [x] resultset 流式 + owned 收集双模
- [x] 多结果集 drain（`SERVER_MORE_RESULTS_EXISTS`）
- [x] prepared statement server-side close + per-conn LRU cache + ER_NEED_REPREPARE 重试
- [x] graceful close（`COM_QUIT`）并拒绝后续命令
- [x] structured server error（code/SQLstate/message）
- [x] 读写超时（zio.Timeout）
- [x] pool：代际失效、reaper、min_idle、lifetime/idle timeout、泄漏核算
- [x] 软取消 / 命令超时（`KILL QUERY` + watchdog）
- [x] typed scan 失败诊断（`last_scan_error`：字段/列/索引/目标类型）
- [x] 类型读取由集中 reader/mapper 管理
- [ ] **TLS 真实生效**（未实现）
- [ ] **caching_sha2 full-auth / RSA**（未接入）
- [ ] 细粒度 metrics / tracing（仅 pool 计数）
- [ ] 多 host failover / 负载均衡

---

## 结论

mantle 已是「薄而正确的协议核心 + 清晰高层 API」：协议层零拷贝且边界安全，类型化能力交给 `comptime`，并发交给生产级连接池而非单连接伪 multiplexing，便利 API 保持所有权/drain/错误语义清晰。距离全功能 production-ready 的主要缺口集中在**安全传输（TLS）与完整认证矩阵（caching_sha2 full-auth）**，应作为下一阶段最高优先级。
