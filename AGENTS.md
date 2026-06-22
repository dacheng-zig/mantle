# mantle

Mantle 是基于 `zio` 的纯 Zig MySQL driver。`zio` 提供 async I/O 与 coroutine 能力。

## 目标

构建一个 Zig-native 的 MySQL driver：追求极致高性能、友好的开发者体验，以及清晰稳定的 clean architecture。

Mantle 应直接发挥 Zig 的语言优势：`comptime` 驱动的 API、显式内存所有权、zero-copy 或 low-copy 的协议处理、可预测的 allocation，以及清晰的错误边界。

参考实现与资料：

- `../myzql`：研究其架构与实现选择，吸收优秀部分，并在 Zig-native 设计上做得更好。
- `../../MySqlConnector`：研究其成熟的 MySQL 协议行为、可靠性、连接池与开发者体验，将有价值的设计转译为 idiomatic Zig，而不是复制 .NET 模式。
- `docs`：将其中的架构设计文档和 MySQL 协议文档作为项目的一手上下文。

## 规则

- 当合适的 agent 能明显提升任务质量或效率时，从 `~/.codex/agents` 中探测并选择使用。
- 始终选择当前约束下最强可行的设计与实现路径；仓库上下文足够时，禁止用无意义提问打断工作。
- 保持 clean architecture：清晰分离 protocol、transport、connection/session state、query execution、result decoding、pooling 与 public API 等职责。
- 热点路径必须同时优化性能与正确性：减少 copy，避免不必要 allocation，保持解析逻辑显式，并用证据验证行为。
- 禁止将 TDD 作为默认工作方式。
- 仅在测试能提供高价值时编写测试：针对 protocol/parser/encoding 边界编写聚焦的 Zig unit test；针对真实 MySQL 行为、兼容性或回归风险编写 integration test。
