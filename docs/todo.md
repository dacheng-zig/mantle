# todo

## P0 — 阻断常见生产部署

- [ ] **TLS/SSL 完全缺失**。`client_ssl` 常量已定义但从未协商；`ZioStream`
      仅明文。`negotiateClientFlags` 不发 `SSLRequest`，无 `std.crypto.tls`
      升级路径。凭证与数据明文传输；RDS/Aurora/CloudSQL/PlanetScale 普遍要求 TLS。
      证据：capability.zig:15、handshake.zig:135、transport.zig:400 `ZioStream`。
- [ ] **无 DNS/主机名解析，仅 IPv4 字面量**。`TcpDriver.open` 用
      `IpAddress.parseIp4(host, port)`，无法连主机名、IPv6、Unix socket。
      几乎所有托管 MySQL 端点是主机名。证据：pool.zig:567。

## P1 — 生产中会被触发的鲁棒性问题

- [ ] **池无死连接探测 / 借出重试**。复用仅依赖 `canReuse()`（只看状态位），
      不校验存活。MySQL `wait_timeout`（默认 8h）或重启后，连接仍 `canReuse()`
      但下条命令必失败（EOF/broken pipe）。无 test-on-borrow ping，无透明单次重连。
      `idle_timeout_ns`/`max_lifetime_ns` 仅在调到低于 server `wait_timeout` 时缓解。
      证据：pool.zig:514 canLeaseIdle、pool.zig:256 release。
- [ ] **无 CLIENT_MULTI_RESULTS / 存储过程支持**。未协商该 capability，`CALL`
      返回结果集的存储过程会被 server 报错。状态机已处理 `server_more_results_exists`，
      但 capability 没发。证据：handshake.zig:147。

## P2 — 成熟度 / 特性完整性

- [ ] **未协商 CLIENT_DEPRECATE_EOF**。功能可用，但现代协议路径未走/未测。
- [ ] **无协议压缩**（CLIENT_COMPRESS / zstd）。
- [ ] **无 connection attributes**（program_name 等），可观测性弱。
- [ ] **无独立 `connect()` 单连接入口**，用户须经 `TcpDriver` 或手搓 ZioStream。
- [ ] **LOCAL INFILE 显式禁用**（安全默认，可接受；记录为不支持特性）。

## 已验证良好（无需改动）

封包 4 字节头 + >16MB 分包重组、sequence-id 跟踪、连接相位状态机、
语句缓存 + ER_NEED_REPREPARE 重准备、事务（隔离级别/访问模式/scoped+guard）、
连接池（generation 失效 / lifetime+idle 回收 / min_idle 预热 / 泄漏计数 /
KILL QUERY watchdog 超时）、文本+二进制双向类型覆盖（含 decimal/temporal/
null/optional/用户编码适配器）、内存所有权与 errdefer 严谨。
