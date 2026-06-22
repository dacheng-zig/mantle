# MySQL Client/Server Protocol Notes

> 面向学习 MySQL 协议和实现 MySQL 客户端驱动的技术笔记。本文聚焦经典 MySQL Client/Server Protocol，不覆盖 X Protocol、复制协议的完整细节，也不依赖任何特定客户端项目实现。
>
> 主要依据 MySQL 官方 Source Code Documentation 的 Client/Server Protocol、Protocol Basics、Connection Phase、Command Phase、Text Protocol、Prepared Statements、Capability Flags 等页面整理。协议细节会随 MySQL 版本演进，编写驱动时应以目标 server 版本的官方文档和实际抓包/集成测试为最终依据。

## 1. 协议总体模型

MySQL 经典协议是运行在 TCP 或 Unix domain socket 之上的有状态二进制协议。连接建立后由 server 先发握手包，client 通过握手响应完成能力协商和认证，之后进入命令阶段。

典型生命周期：

1. 传输连接建立。
2. server 发送 Initial Handshake Packet，或者在协商前直接发送一个不含 SQL state 的 `ERR_Packet` 并结束连接。
3. client 根据 server capability flags 决定是否先发送 `SSLRequest` 并升级到 TLS。
4. client 发送 `HandshakeResponse41`。
5. server 和 client 按认证插件继续交换认证包。
6. server 发送 `OK_Packet` 接受连接，或发送 `ERR_Packet` 拒绝连接。
7. 进入 Command Phase，client 发送命令包，server 返回 OK、ERR、结果集或特殊请求。
8. client 发送 `COM_QUIT` 或底层连接关闭后结束。

协议要点：

- 协议是 stateful 的。每个连接一次只能安全地消费一个命令响应流；发送下一条命令前必须完整读取上一条响应。
- 大量字段是否存在由 capability flags 决定，不应使用固定布局解析所有包。
- 现代客户端通常要求 `CLIENT_PROTOCOL_41`，但兼容老 server 时仍会遇到 pre-4.1 分支。
- 结果集、认证、TLS、压缩、多结果集、EOF 替代、session tracking 都依赖能力协商。

## 2. Packet 层

所有非压缩 MySQL packet 都有 4 字节头：

```text
int<3> payload_length   little-endian, 不含 4 字节 packet header
int<1> sequence_id
string<var> payload
```

规则：

- 单个 packet payload 最大长度是 `2^24 - 1`，也就是 `0xFFFFFF`。
- payload 长度大于或等于 `0xFFFFFF` 时，发送方必须拆成多个 packet。每个满长 packet 的 `payload_length` 为 `ff ff ff`，最后以一个 payload 长度小于 `0xFFFFFF` 的 packet 结束。
- 如果逻辑 payload 恰好是 `0xFFFFFF` 字节，后面还会跟一个长度为 0 的 packet 作为结束标记。
- `sequence_id` 从 0 开始，在同一个 packet exchange 内递增并允许回绕；进入 Command Phase 后，每条新命令通常从 sequence id 0 开始。
- client 发送命令包时，命令 packet 的 sequence id 必须是 0。
- 实现 reader 时必须支持短读、粘包、半包和跨 packet 拼接；不能假设一次 socket read 得到完整 packet。

推荐实现方式：

1. 精确读取 4 字节 header。
2. 解析 `payload_length` 和 `sequence_id`。
3. 精确读取 `payload_length` 字节 payload。
4. 如果长度为 `0xFFFFFF`，继续读取下一个 packet 并拼接 logical payload。
5. 在命令/响应上下文中校验 sequence id；错误时关闭连接或进入不可复用状态。

## 3. 基础数据类型

MySQL 协议字段以小端序为主。

### 3.1 固定整数

| 类型 | 长度 | 说明 |
| --- | ---: | --- |
| `int<1>` | 1 | 8-bit |
| `int<2>` | 2 | 16-bit little-endian |
| `int<3>` | 3 | 24-bit little-endian，packet length 常用 |
| `int<4>` | 4 | 32-bit little-endian |
| `int<6>` | 6 | 48-bit little-endian，少见 |
| `int<8>` | 8 | 64-bit little-endian |

### 3.2 Length-encoded integer

`int<lenenc>` 的首字节决定实际长度：

| 首字节 | 含义 |
| --- | --- |
| `0x00` 到 `0xFA` | 值就是首字节 |
| `0xFB` | 在结果集字段值中表示 `NULL`；通常不作为普通 lenenc integer 使用 |
| `0xFC` | 后续 2 字节 little-endian |
| `0xFD` | 后续 3 字节 little-endian |
| `0xFE` | 后续 8 字节 little-endian |
| `0xFF` | 未使用/非法 |

注意：

- `0xFB`、`0xFE` 的语义依赖上下文。`0xFE` 既可能是 lenenc integer 前缀，也可能是 EOF/OK 类包头，必须结合 packet length 和当前解析状态判断。
- 解析器应对越界、非法前缀和整数溢出返回显式错误。

### 3.3 字符串与二进制

常见字符串形态：

| 类型 | 说明 |
| --- | --- |
| `string<NUL>` | 以 `0x00` 终止，不包含终止字节 |
| `string<EOF>` | 读到当前 payload 结束 |
| `string<lenenc>` | 先读 `int<lenenc>` 长度，再读对应字节 |
| `string<fix>` | 固定长度 |
| `binary<var>` | 由外层长度或上下文决定的原始字节 |

协议层只传输字节。字符集解释取决于连接字符集、列 metadata 或具体字段规定。例如 `client_plugin_name` 是 UTF-8，默认数据库名称按 handshake response 中的 character set 解释。

## 4. Capability Flags

Capability flags 是协议实现的核心。server 在 handshake 中公布自己支持的能力，client 在 response 中只声明自己支持且希望启用的能力。双方实际启用能力可视为交集，但某些 flag 还有方向性语义。

重要原则：

- 不要声明自己不能完整处理的 flag。
- 解析任意可选字段前，先确定当前连接协商出的 flags。
- 某些 flag 有前置条件，例如 `CLIENT_PLUGIN_AUTH`、`CLIENT_MULTI_RESULTS`、`CLIENT_PS_MULTI_RESULTS` 依赖 `CLIENT_PROTOCOL_41`。

常见 flags：

| Flag | 位值 | 客户端实现意义 |
| --- | ---: | --- |
| `CLIENT_LONG_PASSWORD` | `1` | 旧认证相关，4.1.1 起通常假定设置 |
| `CLIENT_FOUND_ROWS` | `2` | UPDATE 返回 found rows 而不是 changed rows |
| `CLIENT_LONG_FLAG` | `4` | 期望更完整的 column flags |
| `CLIENT_CONNECT_WITH_DB` | `8` | handshake response 携带初始 database |
| `CLIENT_COMPRESS` | `32` | 启用 zlib 压缩层 |
| `CLIENT_LOCAL_FILES` | `128` | 允许处理 `LOAD DATA LOCAL INFILE` |
| `CLIENT_PROTOCOL_41` | `512` | 使用 4.1+ 协议布局，现代客户端基础 |
| `CLIENT_INTERACTIVE` | `1024` | server 使用 interactive timeout |
| `CLIENT_SSL` | `2048` | 先发 `SSLRequest`，然后升级到 TLS |
| `CLIENT_TRANSACTIONS` | `8192` | OK/EOF 中包含 status flags |
| `CLIENT_MULTI_STATEMENTS` | `1 << 16` | 允许一条 `COM_QUERY` 中包含多语句，同时会带来多结果集 |
| `CLIENT_MULTI_RESULTS` | `1 << 17` | `COM_QUERY` 可返回多个结果集 |
| `CLIENT_PS_MULTI_RESULTS` | `1 << 18` | prepared statement 可返回多个结果集和 OUT parameters |
| `CLIENT_PLUGIN_AUTH` | `1 << 19` | 支持认证插件名和 Auth Switch |
| `CLIENT_CONNECT_ATTRS` | `1 << 20` | handshake response 携带连接属性 |
| `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` | `1 << 21` | auth response 用 lenenc 长度，支持超过 255 字节 |
| `CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS` | `1 << 22` | 支持过期密码处理 |
| `CLIENT_SESSION_TRACK` | `1 << 23` | OK 包可携带 session state changes |
| `CLIENT_DEPRECATE_EOF` | `1 << 24` | 用 OK packet 替代 EOF packet |
| `CLIENT_OPTIONAL_RESULTSET_METADATA` | `1 << 25` | 支持结果集 metadata 被省略 |
| `CLIENT_ZSTD_COMPRESSION_ALGORITHM` | `1 << 26` | 支持 zstd 压缩层和压缩等级 |
| `CLIENT_QUERY_ATTRIBUTES` | `1 << 27` | `COM_QUERY`/`COM_STMT_EXECUTE` 可携带 query attributes |
| `MULTI_FACTOR_AUTHENTICATION` | `1 << 28` | 支持多因素认证认证包 |
| `CLIENT_SSL_VERIFY_SERVER_CERT` | `1 << 30` | 已由 `ssl-mode` 取代，不建议新实现依赖 |

默认安全取舍：

- `CLIENT_LOCAL_FILES` 默认关闭，除非调用方显式允许并提供受控文件读取策略。
- `CLIENT_MULTI_STATEMENTS` 默认关闭，减少 SQL injection 被扩大为多语句执行的风险。
- TLS 在公网、跨主机、云数据库场景应默认启用并校验证书。

## 5. Status Flags

`OK_Packet`、`EOF_Packet` 中的 `status_flags` 描述 server 会话状态。驱动至少应识别：

| Flag | 典型意义 |
| --- | --- |
| `SERVER_STATUS_IN_TRANS` | 当前处于事务中 |
| `SERVER_STATUS_AUTOCOMMIT` | autocommit 开启 |
| `SERVER_MORE_RESULTS_EXISTS` | 后面还有结果集，必须继续读取 |
| `SERVER_STATUS_NO_GOOD_INDEX_USED` | 查询未使用合适索引 |
| `SERVER_STATUS_NO_INDEX_USED` | 查询未使用索引 |
| `SERVER_STATUS_CURSOR_EXISTS` | prepared statement cursor 存在，可 `COM_STMT_FETCH` |
| `SERVER_STATUS_LAST_ROW_SENT` | cursor 已读完 |
| `SERVER_STATUS_DB_DROPPED` | 默认 database 被 drop |
| `SERVER_STATUS_NO_BACKSLASH_ESCAPES` | SQL mode 影响字符串转义 |
| `SERVER_STATUS_METADATA_CHANGED` | prepared statement metadata 已改变 |
| `SERVER_QUERY_WAS_SLOW` | 查询被标记为 slow |
| `SERVER_PS_OUT_PARAMS` | 当前结果集是 stored procedure OUT parameters |
| `SERVER_SESSION_STATE_CHANGED` | OK 包包含 session state info |

驱动必须用 `SERVER_MORE_RESULTS_EXISTS` 控制 multi-result drain，用 `SERVER_SESSION_STATE_CHANGED` 决定是否解析 session tracking 数据。

## 6. Connection Phase

### 6.1 HandshakeV10

现代 server 自 MySQL 3.21.0 起发送 `Protocol::HandshakeV10`。payload 布局：

```text
int<1>      protocol_version        固定 10
string<NUL> server_version
int<4>      connection_id
string[8]   auth_plugin_data_part_1
int<1>      filler                  0x00
int<2>      capability_flags_1
int<1>      character_set
int<2>      status_flags
int<2>      capability_flags_2
if CLIENT_PLUGIN_AUTH:
  int<1>    auth_plugin_data_len
else:
  int<1>    0x00
string[10]  reserved                全 0
string[$n]  auth_plugin_data_part_2 MAX(13, auth_plugin_data_len - 8)
if CLIENT_PLUGIN_AUTH:
  string<NUL> auth_plugin_name
```

解析陷阱：

- `capability_flags_1` 和 `capability_flags_2` 需要合并成 32-bit flags。
- `auth_plugin_data_part_2` 长度和 NUL 终止在不同 server 实现中容易出现边界差异，解析应允许保守兼容，但不能越界读。
- 如果 server 第一个包就是 `ERR_Packet`，此时尚未协商 `CLIENT_PROTOCOL_41`，错误包可能没有 SQL state。
- `server_version` 只能作为诊断和兼容提示，不应用字符串版本号替代 capability 判断。

### 6.2 SSLRequest 与 TLS 升级

如果 server 公布 `CLIENT_SSL` 且 client 决定启用 TLS：

1. client 发送 `SSLRequest`，它包含 `HandshakeResponse41` 的前 32 字节字段：`client_flag`、`max_packet_size`、`character_set`、23 字节 filler。
2. 发送后立即在同一底层连接上进行 TLS 握手。
3. TLS 建立后，client 再发送完整 `HandshakeResponse41`。

TLS 是透明层；TLS 建立后，上层仍按普通 MySQL packet 读写。若同时启用压缩，官方文档描述为压缩层在协议层之上且 TLS 对写入网络前的字节加密；实现时应严格按 server/client 支持的压缩协议和库行为验证。

### 6.3 HandshakeResponse41

现代 client 使用 `Protocol::HandshakeResponse41`：

```text
int<4>      client_flag
int<4>      max_packet_size
int<1>      character_set
string[23]  filler                  全 0
string<NUL> username
if CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
  string<lenenc> auth_response
else:
  int<1>         auth_response_length
  string<length> auth_response
if CLIENT_CONNECT_WITH_DB:
  string<NUL> database
if CLIENT_PLUGIN_AUTH:
  string<NUL> client_plugin_name
if CLIENT_CONNECT_ATTRS:
  int<lenenc> all_key_values_length
  repeated string<lenenc> key, string<lenenc> value
if CLIENT_ZSTD_COMPRESSION_ALGORITHM:
  int<1> zstd_compression_level
```

实现建议：

- `client_flag` 必须只包含 server 公布且 client 实现完整支持的能力。
- `max_packet_size` 是 client 期望的最大 packet 大小，不等于协议 header 的 24-bit payload 限制；仍必须支持 packet 分片。
- `character_set` 应使用 server 支持的字符集 id。常见选择是 `utf8mb4` 对应的 collation id，但应避免写死过时 id。
- `filler` 必须置零。
- 连接属性可能包含 `_client_name`、`_client_version`、`_os`、`_pid`、`program_name` 等，必须按 lenenc key/value 编码。

## 7. Authentication Phase

认证是由插件驱动的状态机，而不是一次 request/response。

server 在 handshake 中用默认认证方法做 optimistic guess。client 可以用 handshake 中公布的插件计算 response，也可以选择其他兼容插件并在 `client_plugin_name` 中声明。server 查询账户真实认证插件后：

- 如果初始方法匹配且认证成功，返回 `OK_Packet`。
- 如果认证失败，返回 `ERR_Packet`。
- 如果需要继续交互，返回 `AuthMoreData`。
- 如果方法不匹配，返回 `AuthSwitchRequest`，要求 client 切换到指定插件。
- 如果启用多因素认证，某一因素成功后可能返回下一因素认证包。

认证相关包：

| 包 | 首字节 | 含义 |
| --- | --- | --- |
| `OK_Packet` | `0x00` 或作为 EOF 的 `0xFE` | 认证完成 |
| `ERR_Packet` | `0xFF` | 认证失败 |
| `AuthSwitchRequest` | `0xFE` | 切换认证插件，包含插件名和新 challenge |
| `AuthMoreData` | `0x01` | 当前插件继续交换数据 |

常见插件：

### 7.1 `mysql_native_password`

MySQL 4.1-5.7 常见默认认证方式。典型算法：

```text
SHA1(password) XOR SHA1(seed || SHA1(SHA1(password)))
```

其中 `seed` 是 handshake 中两段 `auth_plugin_data` 拼接后的 challenge。空密码通常发送空 auth response。

### 7.2 `caching_sha2_password`

MySQL 8.0 起常见默认认证方式。它可能走 fast authentication：

- client 发送 scramble。
- server 返回 `AuthMoreData`，内容可能表示 fast auth success，随后返回 OK。
- 如果需要 full authentication，server 会要求 client 发送明文密码或 RSA 加密后的密码。

安全要求：

- 已建立 TLS 时可以按插件规则发送明文密码。
- 未建立 TLS 时，需要使用 server RSA public key 加密密码；client 可使用预配置 public key，或按插件流程请求 public key。
- 不应在未加密连接上发送明文密码。

### 7.3 未知插件

如果 server 要求的认证插件未知，客户端应断开连接，并返回明确错误。不要回退到不安全或错误的认证方式。

## 8. Compression

压缩是独立协议层，对上层 MySQL packet 透明。启用条件：

- server 在 handshake 中公布 `CLIENT_COMPRESS` 或 `CLIENT_ZSTD_COMPRESSION_ALGORITHM`。
- client 在 handshake response 中声明匹配 flag。
- 认证完成后 server 返回 OK，随后切换到压缩协议。

要点：

- `CLIENT_COMPRESS` 对应 zlib 压缩。
- `CLIENT_ZSTD_COMPRESSION_ALGORITHM` 允许携带 zstd compression level。
- 如果双方同时设置 `CLIENT_COMPRESS` 和 `CLIENT_ZSTD_COMPRESSION_ALGORITHM`，官方文档说明使用 zlib。
- 如果双方压缩能力不匹配，应回落到非压缩模式，而不是单方面启用。

实现压缩层时要单独维护 compressed packet 的序列号和原始 packet 的序列号，不应混用。

## 9. Command Phase

命令阶段中，client 发送一个 payload 首字节为 command code 的 packet，sequence id 为 0。server 根据命令返回响应流。

常见命令：

| 命令 | Code | 说明 |
| --- | ---: | --- |
| `COM_SLEEP` | `0x00` | server 内部使用 |
| `COM_QUIT` | `0x01` | 关闭连接，无需读取普通响应 |
| `COM_INIT_DB` | `0x02` | 切换默认 database |
| `COM_QUERY` | `0x03` | 文本协议执行 SQL |
| `COM_FIELD_LIST` | `0x04` | 列出字段，旧接口 |
| `COM_PING` | `0x0e` | ping，通常返回 OK |
| `COM_CHANGE_USER` | `0x11` | 切换用户并重新认证 |
| `COM_STMT_PREPARE` | `0x16` | 创建 server-side prepared statement |
| `COM_STMT_EXECUTE` | `0x17` | 执行 prepared statement |
| `COM_STMT_SEND_LONG_DATA` | `0x18` | 分片发送大参数数据 |
| `COM_STMT_CLOSE` | `0x19` | 关闭 prepared statement，无响应 |
| `COM_STMT_RESET` | `0x1a` | 重置 prepared statement |
| `COM_SET_OPTION` | `0x1b` | 开关 multi statements 等选项 |
| `COM_STMT_FETCH` | `0x1c` | cursor fetch |
| `COM_RESET_CONNECTION` | `0x1f` | 重置连接状态 |

实现原则：

- 每条命令都要定义响应读取器，直到响应流结束。
- `COM_QUIT`、`COM_STMT_CLOSE`、`COM_STMT_SEND_LONG_DATA` 是特殊命令，通常没有普通 OK 响应。
- 如果响应最后的 OK/EOF 带 `SERVER_MORE_RESULTS_EXISTS`，必须继续读取下一结果集。
- 如果读取中出现协议错误，应把连接标记为不可复用。

## 10. Generic Response Packets

多数命令返回 `OK_Packet`、`ERR_Packet` 或结果集。

### 10.1 OK_Packet

`OK_Packet` 表示命令成功，也可在新协议中替代 EOF。

```text
int<1>      header                  0x00 或 0xFE
int<lenenc> affected_rows
int<lenenc> last_insert_id
if CLIENT_PROTOCOL_41:
  int<2>    status_flags
  int<2>    warnings
else if CLIENT_TRANSACTIONS:
  int<2>    status_flags
if CLIENT_SESSION_TRACK:
  string<lenenc> info
  if status_flags & SERVER_SESSION_STATE_CHANGED:
    string<lenenc> session_state_info
else:
  string<EOF> info
```

判定规则：

- `header == 0x00` 通常是 OK。
- `header == 0xFE` 且 payload length 小于 9，可能是 EOF 或 EOF-as-OK。
- MySQL 5.7.5 起 OK packet 可用于表示 EOF；新 client 通过 `CLIENT_DEPRECATE_EOF` 表示可接受这种行为。

### 10.2 ERR_Packet

```text
int<1>      header                  0xFF
int<2>      error_code
if CLIENT_PROTOCOL_41:
  string[1] sql_state_marker        '#'
  string[5] sql_state
string<EOF> error_message
```

驱动应保留 `error_code`、`sql_state`、`error_message`，并将其暴露给调用方。连接阶段协商前的初始 `ERR_Packet` 可能没有 SQL state。

### 10.3 EOF_Packet

```text
int<1> header                       0xFE
if CLIENT_PROTOCOL_41:
  int<2> warnings
  int<2> status_flags
```

陷阱：

- `EOF_Packet` 会出现在 lenenc integer 也可能出现的位置，所以不能只看首字节 `0xFE`。必须确认 payload length 小于 9，并结合当前解析状态。
- `CLIENT_DEPRECATE_EOF` 设置后，server 可能用 OK packet 替代 EOF。

## 11. Text Protocol 与 `COM_QUERY`

### 11.1 请求

基础 `COM_QUERY` payload：

```text
int<1>      command                 0x03
string<EOF> query
```

如果协商了 `CLIENT_QUERY_ATTRIBUTES`，`COM_QUERY` 会在 SQL 文本前插入 query attributes：

```text
int<1>      command                 0x03
if CLIENT_QUERY_ATTRIBUTES:
  int<lenenc> parameter_count
  int<lenenc> parameter_set_count   当前总是 1
  if parameter_count > 0:
    binary<var> null_bitmap         (parameter_count + 7) / 8
    int<1>      new_params_bind_flag 必须为 1
    repeated:
      int<2>    param_type_and_flag 低字节是 enum_field_type，高 bit 可表示 unsigned
      string<lenenc> parameter_name
    binary<var> parameter_values
string<EOF> query
```

大多数简单驱动可以先不声明 `CLIENT_QUERY_ATTRIBUTES`，保持传统布局。

### 11.2 响应

`COM_QUERY` 响应是 meta packet，可能是：

- `OK_Packet`：`INSERT`、`UPDATE`、DDL、`BEGIN` 等无结果集命令成功。
- `ERR_Packet`：语法、权限、执行错误。
- `LOCAL INFILE Request`：`LOAD DATA LOCAL INFILE` 需要 client 发送本地文件内容。
- Text Resultset：`SELECT`、`SHOW`、`DESCRIBE` 等返回行数据。

## 12. Text Resultset

Text Resultset 由 metadata 和 rows 组成：

```text
if CLIENT_OPTIONAL_RESULTSET_METADATA:
  int<1> metadata_follows
int<lenenc> column_count
if metadata is present:
  column_count * ColumnDefinition
if not CLIENT_DEPRECATE_EOF:
  EOF_Packet
zero or more TextResultsetRow
terminator:
  ERR_Packet              如果生成行期间失败
  OK_Packet               如果 CLIENT_DEPRECATE_EOF
  EOF_Packet              否则
```

要点：

- `column_count` 大于 0 时表示结果集，不是 OK。
- 如果启用 `CLIENT_OPTIONAL_RESULTSET_METADATA`，server 可能省略 column definitions，client 需要使用缓存 metadata 或返回缺少 metadata 的结果。
- metadata 结束包在 `CLIENT_DEPRECATE_EOF` 下可能不存在。
- rows 结束时如果返回 `ERR_Packet`，表示 metadata 已发送但行生成失败。
- terminator 中若有 `SERVER_MORE_RESULTS_EXISTS`，后面还有另一个结果。

### 12.1 ColumnDefinition41

现代列定义布局：

```text
string<lenenc> catalog              通常是 "def"
string<lenenc> schema
string<lenenc> table                virtual table name
string<lenenc> org_table            physical table name
string<lenenc> name                 virtual column name
string<lenenc> org_name             physical column name
int<lenenc>    fixed_length_fields  固定 0x0c
int<2>         character_set
int<4>         column_length
int<1>         type                 enum_field_types
int<2>         flags
int<1>         decimals
```

For `DECIMAL` / `NEWDECIMAL`, the protocol payload is a length-encoded ASCII representation; the driver should keep it borrowed where possible and let higher-level adapters decide whether to parse it into a fixed-precision type.

解释：

- `table`/`name` 可能是 alias，`org_table`/`org_name` 是原始表/列名。
- `column_length` 是协议 metadata 中的最大显示/字节长度，不能直接等同为应用层字符串长度。
- `character_set` 为 63 通常表示 binary。
- `type` 和 `flags` 共同决定无符号整数、binary/string、blob/text、date/time 等解释。

### 12.2 TextResultsetRow

Text row 中每列按顺序编码：

- `NULL` 用单字节 `0xFB`。
- 非 NULL 值全部转换为字符串，用 `string<lenenc>` 发送。

因此文本协议的返回值默认都是字节串。驱动若要暴露类型化结果，需要结合 ColumnDefinition 的 `type`、`flags`、`character_set` 做转换。

## 13. Binary Protocol 与 Prepared Statements

Prepared statement protocol 自 MySQL 4.1 引入，使用更紧凑的 binary row/value 格式。

### 13.1 `COM_STMT_PREPARE`

请求：

```text
int<1>      command                 0x16
string<EOF> query
```

成功响应第一包 `COM_STMT_PREPARE_OK`：

```text
int<1> status                       0x00
int<4> statement_id
int<2> num_columns
int<2> num_params
int<1> reserved                     0x00
if packet_length > 12:
  int<2> warning_count
  if CLIENT_OPTIONAL_RESULTSET_METADATA:
    int<1> metadata_follows
```

后续响应：

1. 如果 `num_params > 0` 且 metadata 未省略，发送 `num_params` 个 ColumnDefinition；若未设置 `CLIENT_DEPRECATE_EOF`，随后 EOF。
2. 如果 `num_columns > 0` 且 metadata 未省略，发送 `num_columns` 个 ColumnDefinition；若未设置 `CLIENT_DEPRECATE_EOF`，随后 EOF。

失败返回 `ERR_Packet`。

限制：

- 不是所有 SQL 都可 prepare。
- 官方文档指出 `LOAD DATA` 当前不支持 `COM_STMT_PREPARE`，因此此处不预期 `LOCAL INFILE Request`。
- `statement_id` 是 server 端资源句柄，必须用 `COM_STMT_CLOSE` 释放。

### 13.2 `COM_STMT_EXECUTE`

请求：

```text
int<1> status                       0x17
int<4> statement_id
int<1> flags                        enum_cursor_type
int<4> iteration_count              当前总是 1
if num_params > 0 or CLIENT_QUERY_ATTRIBUTES with PARAMETER_COUNT_AVAILABLE:
  if CLIENT_QUERY_ATTRIBUTES:
    int<lenenc> parameter_count
  if parameter_count > 0:
    binary<var> null_bitmap         (parameter_count + 7) / 8
    int<1> new_params_bind_flag
    if new_params_bind_flag:
      repeated:
        int<2> parameter_type       enum_field_type + unsigned flag
        if CLIENT_QUERY_ATTRIBUTES:
          string<lenenc> parameter_name
    binary<var> parameter_values
```

参数规则：

- `num_params` 来自对应 `COM_STMT_PREPARE_OK`。
- `null_bitmap` 对 `COM_STMT_EXECUTE` 使用 bit offset 0。
- `new_params_bind_flag = 1` 时必须发送每个参数类型；为 0 时 server 复用上一次绑定类型。
- NULL 参数只在 bitmap 中标记，不发送 value bytes。
- `parameter_values` 必须按 declared type 的 binary value 编码。
- `DECIMAL` / `NEWDECIMAL` 参数按 length-encoded ASCII decimal bytes 发送，和查询结果中的 decimal 字段保持同一字节语义。
- 如果使用 cursor flag，需要读取 `SERVER_STATUS_CURSOR_EXISTS`，再用 `COM_STMT_FETCH` 拉取行。

响应：

- 无结果集语句返回 `OK_Packet` 或 `ERR_Packet`。
- 有结果集语句返回 Binary Protocol Resultset。
- 若设置 `CLIENT_PS_MULTI_RESULTS`，可能有多个结果集。

### 13.3 `COM_STMT_SEND_LONG_DATA`

用于在 `COM_STMT_EXECUTE` 前分片发送大参数：

```text
int<1> command                      0x18
int<4> statement_id
int<2> param_id                     0-based
binary<var> data
```

server 不返回响应。重复发送同一 `param_id` 会追加数据。发送顺序必须在 `COM_STMT_EXECUTE` 前。

### 13.4 `COM_STMT_FETCH`

用于 cursor：

```text
int<1> command                      0x1c
int<4> statement_id
int<4> num_rows
```

响应可能是 binary resultset 行、OK/EOF terminator 或 `ERR_Packet`。

### 13.5 `COM_STMT_RESET` 与 `COM_STMT_CLOSE`

- `COM_STMT_RESET` 重置 statement 的 server 状态，通常返回 OK 或 ERR。
- `COM_STMT_CLOSE` 释放 server-side statement，不返回普通响应；发送后不能再使用该 `statement_id`。

## 14. Binary Resultset

Binary Resultset 与 Text Resultset 的 metadata 类似，但 row 编码不同：

```text
int<lenenc> column_count
column_count * ColumnDefinition
zero or more BinaryResultsetRow
terminator:
  OK_Packet if CLIENT_DEPRECATE_EOF
  EOF_Packet otherwise
```

官方文档描述 binary resultset 与 text resultset 类似，但行使用 Binary Protocol Resultset Row。

### 14.1 Binary Resultset Row

```text
int<1>      packet_header           0x00
binary<var> null_bitmap             (column_count + 7 + 2) / 8
binary<var> values                  only non-null columns
```

NULL bitmap：

- binary resultset row 使用 bit offset 2。
- 第 `field_pos` 列的 NULL bit 位于：

```text
byte_pos = (field_pos + 2) / 8
bit_pos  = (field_pos + 2) % 8
```

与之对比，`COM_STMT_EXECUTE` 参数 bitmap 的 offset 是 0。

### 14.2 Binary Protocol Value

常见 field type 的 binary value 编码：

| 类型 | 编码 |
| --- | --- |
| `MYSQL_TYPE_NULL` | 只在 NULL bitmap 中表示，无 value bytes |
| `MYSQL_TYPE_TINY` | `int<1>` |
| `MYSQL_TYPE_SHORT`, `MYSQL_TYPE_YEAR` | `int<2>` |
| `MYSQL_TYPE_LONG`, `MYSQL_TYPE_INT24` | `int<4>` |
| `MYSQL_TYPE_LONGLONG` | `int<8>` |
| `MYSQL_TYPE_FLOAT` | 4 字节 IEEE 754 single，little-endian |
| `MYSQL_TYPE_DOUBLE` | 8 字节 IEEE 754 double，little-endian |
| `MYSQL_TYPE_STRING`, `MYSQL_TYPE_VAR_STRING`, `MYSQL_TYPE_VARCHAR` | `string<lenenc>` |
| `MYSQL_TYPE_DECIMAL`, `MYSQL_TYPE_NEWDECIMAL` | `string<lenenc>` |
| `MYSQL_TYPE_TINY_BLOB`, `MYSQL_TYPE_BLOB`, `MYSQL_TYPE_MEDIUM_BLOB`, `MYSQL_TYPE_LONG_BLOB` | `string<lenenc>` |
| `MYSQL_TYPE_JSON`, `MYSQL_TYPE_GEOMETRY`, `MYSQL_TYPE_BIT` | `string<lenenc>` |
| `MYSQL_TYPE_DATE`, `MYSQL_TYPE_DATETIME`, `MYSQL_TYPE_TIMESTAMP` | length-coded date/time struct |
| `MYSQL_TYPE_TIME` | length-coded time struct |

Date/datetime/timestamp：

```text
int<1> length                       0, 4, 7, or 11
if length >= 4:
  int<2> year
  int<1> month
  int<1> day
if length >= 7:
  int<1> hour
  int<1> minute
  int<1> second
if length == 11:
  int<4> microsecond
```

压缩形式：

- length 0：所有字段为 0。
- length 4：只有 date。
- length 7：date + time，microsecond 为 0。
- length 11：date + time + microsecond。

Time：

```text
int<1> length                       0, 8, or 12
if length >= 8:
  int<1> is_negative
  int<4> days
  int<1> hour
  int<1> minute
  int<1> second
if length == 12:
  int<4> microsecond
```

驱动实现建议将 `TIME` 映射为 duration-like 结构，保留负号、天数、时分秒和微秒，避免丢失精度。

## 15. Result Drain 与 Multi-result

驱动实现中最容易出错的是没有完整消费响应。

必须 drain 的场景：

- `CLIENT_MULTI_STATEMENTS` 开启后，一条 `COM_QUERY` 可能产生多个 OK/ERR/resultset。
- stored procedure 可能产生多个结果集。
- prepared statement 设置 `CLIENT_PS_MULTI_RESULTS` 后可能产生多个结果集。
- terminator 的 `SERVER_MORE_RESULTS_EXISTS` 表示后面还有结果。
- 行读取过程中也可能收到 `ERR_Packet` 作为失败终止。

推荐状态机：

1. 读取第一个响应 packet。
2. 如果是 ERR，结束。
3. 如果是 OK，记录状态；若 `SERVER_MORE_RESULTS_EXISTS`，回到 1。
4. 如果是 resultset header，读取 metadata、rows、terminator。
5. 解析 terminator status flags；若 `SERVER_MORE_RESULTS_EXISTS`，回到 1。
6. 没有更多结果后，连接才可发送下一条命令。

## 16. `LOAD DATA LOCAL INFILE`

`COM_QUERY` 执行 `LOAD DATA LOCAL INFILE` 时，server 可能返回 `LOCAL INFILE Request`，要求 client 读取本地文件并上传内容。

安全要求：

- 只有 client 声明 `CLIENT_LOCAL_FILES` 时才应处理该请求。
- 默认不应开启 `CLIENT_LOCAL_FILES`。
- 即使开启，也应通过调用方提供的 allowlist、虚拟文件提供器或回调读取文件，不能让 server 任意读取 client 本地路径。
- 上传结束通常发送一个空 packet 表示 EOF，然后读取 server 的 OK/ERR。

## 17. 字符集、排序规则与类型转换

协议中的 `character_set` 字段通常是 collation id，而不是简单的 charset 名称。驱动需要维护 collation id 到字符集的映射，至少要正确处理：

- 连接默认字符集。
- column definition 中每列的 `character_set`。
- `character_set == 63` 时按 binary 字节处理。
- 文本协议返回值按列字符集解码，binary/blob/json/geometry/bit 等按字节或专用格式处理。
- `SERVER_STATUS_NO_BACKSLASH_ESCAPES` 会影响客户端做 SQL 字符串转义时的规则。

建议：

- 对普通查询参数优先使用 prepared statement，避免手写 SQL escaping。
- 如果必须做文本 SQL interpolation，必须基于当前连接字符集和 SQL mode 做转义。

## 18. Packet 类型判定策略

响应首字节常见含义：

| 首字节 | 常见含义 |
| --- | --- |
| `0x00` | OK packet，或 binary resultset row header |
| `0x01` | AuthMoreData，或 LOCAL INFILE Request 在部分上下文中的数据流 |
| `0xFB` | Text row 中的 NULL，或 LOCAL INFILE Request header |
| `0xFE` | EOF packet、AuthSwitchRequest、EOF-as-OK、lenenc integer 前缀 |
| `0xFF` | ERR packet |

不能只按首字节全局分派。正确做法是结合：

- 当前连接阶段：handshake、auth、command、resultset、local infile。
- 当前命令类型。
- payload length。
- negotiated capability flags。
- 是否正在读取 metadata、row、terminator。

## 19. 客户端驱动实现清单

### 19.1 最小可用能力

一个现代最小客户端通常需要：

- TCP/Unix socket 连接与超时控制。
- packet reader/writer，支持分片、sequence id、短读。
- HandshakeV10 parser。
- HandshakeResponse41 writer。
- TLS upgrade，可配置证书校验。
- `mysql_native_password` 和 `caching_sha2_password`。
- Auth Switch / Auth More Data 状态机。
- OK/ERR/EOF parser。
- `COM_QUERY`。
- Text Resultset metadata 和 row parser。
- `COM_PING`、`COM_QUIT`。
- 完整 drain multi-result 的能力，即使默认不启用 multi statements。

### 19.2 推荐扩展能力

- Prepared statement：`COM_STMT_PREPARE`、`COM_STMT_EXECUTE`、`COM_STMT_CLOSE`、`COM_STMT_RESET`。
- Binary Resultset Row parser。
- 类型化参数编码和结果解码。
- `COM_STMT_SEND_LONG_DATA`。
- cursor 与 `COM_STMT_FETCH`。
- `CLIENT_SESSION_TRACK`。
- 连接属性。
- `COM_RESET_CONNECTION` 用于连接池复用。
- 压缩层。
- `CLIENT_OPTIONAL_RESULTSET_METADATA` 和 metadata cache。
- query attributes。

### 19.3 可靠性与错误处理

- 所有 parser 必须检查剩余长度，禁止越界读。
- 协议错误、sequence id 错误、未知认证插件、TLS 失败后，连接应标记为不可复用。
- `ERR_Packet` 应保留 code、SQL state、message。
- 读写应支持 deadline/timeout 和取消。
- 连接池归还连接前必须确认响应流已 drain，事务状态符合池策略。
- `COM_QUIT` 发送失败时通常直接关闭底层连接即可。
- 对 server 断连、半关闭、超时、packet 过大、压缩解码失败都要给出明确错误。

### 19.4 测试建议

至少覆盖：

- handshake with `mysql_native_password`。
- handshake with `caching_sha2_password` fast auth。
- TLS enabled handshake。
- AuthSwitchRequest。
- `COM_QUERY` OK、ERR、空结果集、普通结果集。
- text row 中 `NULL`、空字符串、长字符串、非 ASCII 字符。
- EOF terminator 和 `CLIENT_DEPRECATE_EOF` 下的 OK terminator。
- packet payload 正好 `0xFFFFFF` 和超过 `0xFFFFFF` 的分片。
- `SERVER_MORE_RESULTS_EXISTS` 多结果集。
- prepared statement 参数编码：NULL、整数、无符号、浮点、字符串、blob、decimal、date/time。
- binary resultset NULL bitmap offset 2。
- `COM_STMT_CLOSE` 无响应。
- `LOAD DATA LOCAL INFILE` 默认拒绝。
- malformed packet、截断 packet、非法 lenenc、sequence id 错误。

## 20. 兼容性边界

- MySQL、MariaDB、Percona Server 大体兼容经典协议，但 capability flags、认证插件、扩展字段、错误码、server version 字符串可能不同。
- MySQL 8.0 默认认证方式常见为 `caching_sha2_password`；5.7 及更早环境常见 `mysql_native_password`。
- MySQL 5.7.5 起 EOF packet 被逐步弃用，新客户端应支持 `CLIENT_DEPRECATE_EOF`。
- 新协议能力如 `CLIENT_QUERY_ATTRIBUTES`、`CLIENT_OPTIONAL_RESULTSET_METADATA`、zstd compression 需要按 server 支持情况启用。
- 不要基于 server version 字符串硬编码协议布局；优先依赖 flags 和实际 packet。

## 21. 参考资料

- MySQL Source Code Documentation: Client/Server Protocol: <https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html>
- MySQL Source Code Documentation: Protocol Basics: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html>
- MySQL Source Code Documentation: MySQL Packets: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html>
- MySQL Source Code Documentation: Generic Response Packets: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_response_packets.html>
- MySQL Source Code Documentation: Connection Phase: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html>
- MySQL Source Code Documentation: HandshakeV10: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html>
- MySQL Source Code Documentation: HandshakeResponse: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html>
- MySQL Source Code Documentation: Capability Flags: <https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html>
- MySQL Source Code Documentation: Command Phase: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase.html>
- MySQL Source Code Documentation: COM_QUERY: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html>
- MySQL Source Code Documentation: Text Resultset: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html>
- MySQL Source Code Documentation: Column Definition: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html>
- MySQL Source Code Documentation: Prepared Statements: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_command_phase_ps.html>
- MySQL Source Code Documentation: COM_STMT_PREPARE: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html>
- MySQL Source Code Documentation: COM_STMT_EXECUTE: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html>
- MySQL Source Code Documentation: Binary Protocol Resultset: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_binary_resultset.html>
- MySQL Source Code Documentation: TLS: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_tls.html>
- MySQL Source Code Documentation: Compression: <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_compression.html>
