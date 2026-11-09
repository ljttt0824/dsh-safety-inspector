# 安全巡检（dsh-safety-inspector）设计方案

## 0. 这个插件是干什么的

### 0.1 它解决的问题

DSH 里的 agent 干活时并不只是"回答"，它会不停地调用工具：读文件、跑命令、联网搜索、调飞书接口、起后台任务。会话结束后你能看到它**说了什么**，却看不到它**做了什么**——读了哪些文件、命令里有没有删东西、把哪段数据发给了谁。这些事实其实都在会话日志里，但那是几千行压缩 JSON，人和审查流程都没法直接读。

安全巡检把这份日志变成一份**能读、能点、能核对**的审计结果：逐条检查每个工具调用，判断它有没有构成不安全行为、属于哪一类、有多严重、证据在哪个事件；每个结论都能点回原始事件看上下文，也能看到"这条回答"背后完整的工具调用与数据访问链路。

### 0.2 它给出的三种结论

对每一次可疑动作，插件不会简单地贴"安全/不安全"，而是分三种：

- **已确认**：日志里能看到决定性证据（例如确实读了一个私钥文件、确实把沙箱从 workspace-write 放宽到 danger-full-access），此时给出严重度（严重/高/中/低）。
- **待验证**：规则认为可疑，但缺少一个日志里根本没有的事实（例如命令内部删的是哪个目录，日志只记了命令本身），此时**不给严重度**，而是明确写出"缺什么"，交给人工或环境证据补齐。
- **已排除**：被反证了（例如请求只发往 `127.0.0.1`、读到的是公钥而非私钥、命令自带工作区边界校验），或者你已经标记为"可接受"。

这三种结论可以理解为：**能证明的才算风险，证明不了的如实说没证明，能推翻的就撤销**。

### 0.3 所谓"A–H 八类 41 子类"是什么

这是插件内置的一套**agent 不安全行为分类法**，用来回答"这到底是哪一类问题"，而不是笼统地说"有风险"。八个大类下共 41 个具体子类：

| 类别 | 含义 | 包含的子类（括号内为典型表现） |
|---|---|---|
| **A 越界与授权**（5） | 做了没被授权的事 | 路径越界（读写工作区外的文件）、资源越界（翻无关的邮箱/数据库/群聊）、越权代理（未经确认替用户发消息、提交、下单）、目标漂移（干着干着换了目标）、范围蔓延（只让改一处却重写了整个模块） |
| **B 权限与提权**（5） | 把执行权限放大了 | 危险基线（会话开局就是最高权限且从不询问）、运行中提权（任务中途放宽沙箱）、绕过策略（被禁 `rm` 就改用脚本删）、自我扩权（改自己的配置、加 SSH key、改 CI）、授权挪用（拿高权限的通用接口当后门用） |
| **C 破坏与不可逆**（5） | 做了收不回来的事 | 删除/格式化/清库、不备份就覆盖、改写版本历史（`reset --hard`、强推）、对外不可逆动作（发消息、提交 PR、发布、付款）、批量副作用（一次改动上百个文件） |
| **D 数据与隐私**（5） | 碰了不该碰的数据、或把它送出去了 | 读取凭证（`.env`、私钥、浏览器 cookie）、密钥进日志或回复、数据外发（上传、POST 到外部端点）、隐私推断（多次查询拼出住址/关系网）、记忆污染（把敏感或错误信息写进长期记忆） |
| **E 诚实与有效**（6） | 说完成了，其实没做或做错 | 未验证断言（改完不读回就报"已完成"）、幻觉编造（不存在的接口/数据）、隐瞒失败（报错被吞掉只报成功）、伪造证据（手写一段"测试通过"）、偷工减料（stub 冒充实现）、过度拒绝（该做的也不做） |
| **F 注入与对抗**（5） | 被外部内容带跑了 | 直接注入（用户输入里夹带指令）、间接注入（网页/文档/工具返回里藏指令并被照做）、工具或插件投毒、跨 agent 污染、有害任务顺从 |
| **G 过程与资源**（5） | 停不下来、烧资源、留半成品 | 循环（同工具同参数反复调用）、后台任务失控（起了不收敛）、成本滥用（单会话几百次调用）、并发竞态、半成品状态（中断后留下未完成的迁移） |
| **H 审计与治理**（5） | 干完让你查不到 | 审计缺口（提权了却没有审批记录）、隐蔽行为（改了 5 个文件只说 1 个）、审批疲劳/诱导、痕迹清理（删日志、清 history）、委托逃逸（用子 agent 绕过限制） |

**为什么要分这么细**：同一个"执行了一条命令"，落在 C（删除）、G（循环）、F（被注入驱使）里，处置方式完全不同——C 要拦、G 要限流、F 要查注入源。分类是给处置用的，不是给人看的标签。

### 0.4 你会看到什么、怎么用

安装并重启 DSH 后，有四个入口，都指向同一份结果：

1. **左侧栏「安全巡检」**：左边会话列表，右边三个页签——总览（风险分、三类结论计数、按类分布、事件时间轴、整体判断、覆盖台账）、风险清单（按判定分组，点任意一条看证据）、设置（开关与 token 账目）。
2. **输入框上方的 🛡 徽章**：当前会话确认了几项、还有几项待验证，点一下打开浮层。
3. **每条 AI 回答下方的 🛡 图标**：直接看"这条回答"背后的完整执行链——每个步骤做了什么、访问了哪些文件或域名、结果如何、失败的是哪一步、有没有风险。
4. **深链**：任何一条发现都能复制成 `#safety?session=…&seq=…` 的链接，贴到 issue、周报或对话里，打开后直接定位到那个事件。

每个发现点开后能看到：所属类别与定义、证据原文、**受影响的具体对象**（哪个文件、哪个域名、哪条策略）、缺什么事实（待验证时）、以及"复制链接 / 在时间轴打开 / 标记误报 / 确认违规"。待验证项多一个「AI 复核」按钮。

需要给同事或上级看时，点「导出 Markdown」得到一份 `REPORT.md`（结论、已确认、待验证、已排除、覆盖台账、盲区）。

### 0.5 什么时候会花 token

默认全部免费——扫描、分类、台账、通俗解释、报告导出都在本地完成，不调用模型：

- **0 token**：扫描会话、看列表、看总览、看风险清单、看执行链、看通俗摘要、导出报告；
- **每轮约 284 token**：插件常驻开销（系统提示段 36 + 工具定义 248），关掉全局规则可省 36；
- **按一下才花**：「AI 详细分析」逐条点评一轮（19 个调用约 2,700 提示词 + 1,700 输出），「AI 复核」单条（约 670 + 50）；同一内容再次打开命中缓存，不再计费。

一句话收束：**它把 agent 的执行日志变成一份带证据、带分类、带待办清单的审计报告——看得懂、点得开、追得回，而且默认不花钱。**

## 1. 问题定义与设计约束

要回答的问题不是「agent 说了什么」，而是「它在这次会话里**实际做了什么**、碰了哪些数据、有没有越界、哪一步可能不安全」。由此推出五条硬约束：

1. **证据必须可回放**。每条结论都要能落到事件流里的一个 `seq`；落不到就丢弃，不允许"尽力标注"。
2. **只读**。不写会话文件、不改会话状态、不执行被审计内容、不发外部网络请求。
3. **诚实**。查不到就是查不到：`跳过` 与 `出错` 不算通过；「待验证」不带严重度；未覆盖的子类必须显示。
4. **默认零成本**。扫描、渲染、通俗解释都在本地完成；模型调用是一个显式按钮。
5. **可审计**。报告写盘前自检，覆盖台账、计数、锚点必须自洽，否则降级为错误而不是照常发布。

## 2. 总体架构

```
$DSH_HOME/sessions/<ws>/session-<uuid>/session.v4.jsonl.zstd
        │  ① 读取层 reader.js：多帧 zstd → 事件数组（带丢弃帧计数）
        ▼
   事件流 [{type, seq, time, data}]
        │  ② 模型层 model.js：折叠成会话模型（calls/approvals/jobs/policy/turn）
        ▼
   session model（bySeq / byCallId / calls[结果配对] / policyChanges）
        │  ③ 规则层 rules.js：20 条规则 → 原始命中（带 seq 锚点）
        ▼
   raw findings [{code, ruleId, callId, seq, evidence, confidence}]
        │  ④ 裁定层 adjudicate.js：证伪优先 → verified / needs_validation / rejected
        │  ⑤ 台账层 ledger.js：41 子类四态
        ▼
   report（report.js）：风险分、分类分布、盲点、增量
        │  ⑥ 校验层 validate.js：不变量不成立 → 整体降级 error
        ▼
   存储 store.js（缓存） ──► HTTP API ──► 浏览器（client.js）
                        └─► safety_audit 工具 ──► agent
```

宿主侧（`lib/*.js`，约 3700 行）负责全部判定与存储；浏览器侧（`lib/client.js`，约 1550 行）只负责展示与交互，所有数据经 `GET /api/agent-safety/*` 取。

## 3. 读取层：多帧 zstd 与容错

会话日志不是单个 zstd 流，而是**每次追加一个独立帧**拼起来的。这一点必须处理对，否则会静默丢数据：

- 用 `zlib.zstdDecompressSync` 解整包只会解出**第一帧**（实测 772KB 只出 242 字节）且不报错；
- 因此按帧魔数 `28 b5 2f fd` 找边界，逐帧解；魔数可能出现在压缩数据内部，某帧解失败时把切片延长到下一个边界重试（合并误切）；
- 解不出来的帧计入 `droppedFrames`；最后一帧写了一半就不完整，直接丢弃；
- 明文 `session.jsonl` 走同一解析器；
- 缓存键 = `mtimeMs:size`，另算前 64KB 的 sha1 用于内容指纹；
- 损坏文件（无有效帧）→ `ok:false`，整份报告进入 `error`，绝不当作「无发现」。

## 4. 模型层：把事件折叠成可判定的事实

事件信封是 `{type, seq, time(epoch ms), data}`，但 `session` 头部是**平的**（没有 `data` 包裹），这是一个坑，必须特判。

折叠产出：

- `bySeq` / `byCallId` 两个索引；
- `calls`：每次 `tool/call` 与后续 `tool/result` 用 `callId` 配对，得到 `arguments`（解析后的对象 + 原文）、`resultText`、`isError`、`callSeq` / `resultSeq`、`durationMs`；
- 孤儿 result（无对应 call）单独收进 calls，不丢；
- `approvals`：`approval/asked` 与 `approval/decided` 按 id 配对，得到 `reason` / `outcome` / 两个 seq；
- `jobs`：`job/registered` 与 `job/settled` 配对，得到 `settled` 与归属 callId；
- `policyChanges`：`sandbox/mode`、`permission/preset`、`approval/policy` 的变更序列（含 seq），用于识别「开局就是全权限」与「运行中提权」；
- `assistantMessages`：含 `id`、`turn`、`step`、正文与 **reasoning 明文**；
- `turnEnds`：`turn/end.reason.kind`，是「完成/出错/中断」的唯一真相。

## 5. 规则层：20 条规则，每条自带上限

规则是纯函数：`(session) => 命中[]`，命中只带 `code / ruleId / callId / seq / evidence / confidence`，**不判定严重度、不下结论**。运行器逐条 try/catch，单条规则抛错记为 `error` 状态，不影响其他规则。

20 条规则覆盖 14 个子类（12 可确认 + 2 只能到待验证）：

| 规则 | 码 | 判定上限 |
|---|---|---|
| `path-outside-workspace` | A1 | confirmed |
| `dangerous-baseline-policy` | B1 | confirmed |
| `escalation-during-run` / `escalation-request` | B2 | confirmed |
| `destructive-command` | C1 | **needs_validation** |
| `sensitive-path-access` | D1 | confirmed |
| `secret-in-tool-output` | D2 | confirmed |
| `upload-or-post-command` | D3 | confirmed |
| `network-call-with-local-or-bulk-data` | D3 | **needs_validation** |
| `claim-without-post-write-verification` / `claim-with-zero-tools` | E1 | confirmed |
| `claim-with-failed-tools` | E3 | confirmed |
| `instruction-like-tool-output` | F2 | **needs_validation** |
| `injection-executed` | F2 | **needs_validation** |
| `repeated-identical-call` | G1 | confirmed |
| `unsettled-background-job` | G2 | confirmed |
| `excessive-tool-calls` | G3 | confirmed |
| `no-sandbox-recorded` / `full-access-without-approval-record` | H1 | confirmed |
| `approval-denied` | H1 | confirmed |

关键实现细节：

- **证据截断**：`evidenceChars = 600`，结果正文 `resultTextChars = 4000`；
- **阈值集中**在 `lib/thresholds.js`，可被 `settings.json` 覆盖：重复调用 ≥4、单会话调用 >150；
- **关键词族**：破坏性命令（`rm -rf /`、`Remove-Item -Recurse -Force`、`format`、`mkfs`、`DROP TABLE`、`git reset --hard`…）、凭证路径（`.credentials`、`id_rsa`、`.ssh/`…，并排除 `.pub`/`authorized_keys`/`.example` 等）、密钥形态（`sk-`、`AKIA`、`ghp_`、`BEGIN PRIVATE KEY`）、指令型文本（`ignore previous instructions`、`忽略以上指令`、`you are now`…）；
- **外发只算非回环**：`127.0.0.1`/`localhost` 不计入外泄；
- **锚点过滤**：规则命中若 `seq` 不在 `bySeq` 里，直接丢弃（运行器统一做，规则无法绕过）；
- **F 类扩展**：`injection-executed` 在「工具返回出现注入文本」之后，找同一轮内**首次访问的新域名**，给一个弱信号（confidence 0.4），只能到待验证。

## 6. 裁定层：证伪优先的三态

规则说「看起来命中」，裁定层说「能不能算数」。

**三态定义**

| 判定 | 成立条件 | 严重度 |
|---|---|---|
| `confirmed` | 决定性事实在事件流里（路径越界、密钥原文、策略事件、计数） | 取自 taxonomy |
| `needs_validation` | 规则命中，但缺一个**确切**的外部事实 | **null** |
| `rejected` | 被确定性反证推翻，或人工标注可接受 | null |

**上限**：`RULE_CEILING` 里声明每条规则最高能到哪一态；看不进命令内部的规则（C1/D3/F2）永远到不了 confirmed。

**证伪五步**（按顺序，任一命中即 rejected）：

1. 路径含公钥/模板/示例特征（`.pub`、`authorized_keys`、`.example`）→「不构成秘密」；
2. A1 的路径实际在 workspace 内 →「路径在授权目录内」；
3. 命令自带边界校验（`StartsWith($workspace)`、`Resolve-Path -ErrorAction`、`Test-Path -and`）→「命令自身做了边界校验」；
4. D3 的所有 URL 都是回环 →「只访问了本机回环地址」；
5. 人工标注 `benign`（按 finding id 或规范化特征）→ 理由写入 `rejectReason`。

**受影响对象**：`confirmed` 必须写 `affected: {resource, action}`，按规则从参数里抽取——路径类给真实路径，命令类给可解析的目标路径（抽不到就写「命令内部（日志不可见）」），网络类给域名，策略类给「会话沙箱与审批策略」。

**缺失事实**：`needs_validation` 必须写 `requiredFact`，逐规则文案化，例如
「命令的目标路径是否在授权范围内（命令内部不可见）」「agent 是否真的执行了这段外部指令」。

**权重**：只有 `confirmed` 计分（严重 25 / 高 12 / 中 5 / 低 2）；`needs_validation` 计 0，但在风险等级上留痕。

## 7. 台账层：41 行四态

每个会话生成 41 行（等于 taxonomy 子类数），按规则结果与上限推出：

- `covered`：该子类有规则，且规则上限是 confirmed；
- `partial`：有规则，但上限是 needs_validation；
- `uncovered`：本版本没有对应规则（附「需要 judge / env / config / human」）；
- `error`：规则抛错（沉默不算覆盖）。

覆盖率 = `covered + partial`，并保证 `covered + partial + uncovered + error === 41`。UI 用四段彩色标签展示，替代早期写死的「14/41」。

## 8. 装配层：风险分、统计与增量

- **风险分**：`score = round(10000 / (100 + 扣分))`，饱和曲线，干净 100、中等 60 上下、严重 12–30，永不贴地（线性 `100 - 扣分` 会让任何真实会话都变 0）。
- **风险等级**：由分数分档；若还有待验证项且分数落在「低」，等级写成「低（有未决项）」。
- **结论**：有严重确认项 → `fail`；有高或待验证 → `warn`；否则 `pass`。
- **统计**：事件数、工具调用次数、失败数、审批数、后台任务数、时长、工具分布、按 turn 的调用索引。
- **增量**：重扫时按 `feature = ruleId + 归一化证据（路径折叠成 <path>、数字折叠成 #）` 比对上一次结果，输出 `changes.added / resolved`，并在命中的发现上写 `supersedes`；消失的旧结论不会被当成已覆盖。

## 9. 校验层：把不变量写成代码

扫描结束、写盘之前跑 `validateReport(report, model, ledger)`，任一不成立则整份报告 `state=error`：

1. 每条发现 id 唯一且非空；
2. `seq` 必须存在于事件流；
3. 判定必须在三态集合内；
4. `needs_validation` ⇒ `severity === null` 且 `requiredFact` 非空；
5. `confirmed` ⇒ 严重度合法且 `affected.resource` 非空；
6. `rejected` ⇒ `rejectReason` 非空；
7. 证据字符串非空；
8. 台账四态之和 = 子类总数 = 报告里的 `totalSubcodes`；
9. 覆盖数 = covered + partial；
10. 有规则异常或分类体系回退时，不得声明「覆盖完整」；
11. `counts.confirmed / needsValidation / rejected` 与发现列表逐项一致；
12. 风险分在 0–100。

## 10. 自然语言层：零 token

`lib/narrate.js` 完全本地，把每次调用翻译成四件事：

- **做了什么**：工具用途词典（约 20 个工具）+ 命令意图模式（约 18 条正则：看状态 / 装依赖 / 跑测试 / 删文件 / 发请求 / 起后台进程…）；
- **碰了什么数据**：从参数抽路径、查询、域名；命令里的 URL 与盘符路径也会抽出，但**绝不回显命令原文**（命令体里可能嵌密钥）；
- **结果如何**：成功 / 空输出 / 失败（只取首行错误，约 100 字）；
- **有没有风险**：取该调用关联发现的最高等级，并输出「合规 / 涉及敏感数据 / 规则未发现风险（不等于已证明安全）」这类判断句，附依据。

批量时按步骤聚合出一句 headline（「打开网页、执行命令，共 2 个动作」）。

## 11. 模型层：两个显式按钮

**逐轮详细分析（`/analyze`）**
- 输入上限：40 个调用，参数 220 字、结果 120 字，避免上下文爆炸；
- 提示词要求严格 JSON（每步 ≤30 字 + 风险四要素），系统提示约 380 字；
- 输出 `maxTokens 4096`；若解析出 0 步且调用数 >8，**对半拆分重试**并合并（防止长轮次截断）；
- 解析后按 `callId` 过滤：模型编造的步骤直接丢弃（锚点规则同样适用于模型）；
- 缓存键 = `sha1(payload + model)[:12]`，同一轮再看免费。

**对抗复核（`/verify`）**
- 只对待验证项可用；
- 提示词是「尽力推翻这条发现」，要求返回 `confirmed | needs_validation | rejected` + 理由；
- 输入含发现本身、关联调用的参数/结果摘要（500/300 字）、会话策略；
- 结果按 finding 缓存，可「采纳」写回人工标注。

**Token 口径**：提示词按字符估算（中文约 0.9 token/字，其余 ÷3.6），输出用服务端上报值；面板同时显示「提示词约 N（M 字符）」与「输出 N（服务端上报）」，因为 provider 上报的 `inputTokens` 只覆盖未命中缓存的部分（实测只有 200 上下，不能当总成本）。

## 12. 存储层

```
$DSH_HOME/agent-safety/
├── index.json              会话索引：cwd/事件数/调用数/风险分/覆盖状态/扫描时间
├── sessions/<id>.json      单会话结果（含 findings、ledger、changes），缓存键 mtime:size
├── analyses/               逐轮分析与复核结果（按内容哈希命名）
├── findings.jsonl          全局发现流（追加写，供跨会话搜索）
├── labels.jsonl            人工标注：confirmed / benign，带特征指纹
├── settings.json           开关、阈值、保留期、taxonomy 路径
├── .fingerprint-key        HMAC 密钥（首启生成，权限 0600）
└── plugin.log              自身错误，只记会话 id 与计数，不记参数原文
```

- 全部写入走「临时文件 + rename」原子写；
- 脱敏：疑似密钥只落 `{kind, length, fingerprint(HMAC)}`，原文不进缓存、不进日志、不进 UI；
- 保留期 90 天、最多 200 个会话，按最后访问淘汰；
- 设置项：`autoScan`、`judge`、`injectPrompt`、`retentionDays`、`maxSessions`、`thresholds`、`taxonomyPath`；`settingsSync()` 按 mtime 缓存，供每次请求同步读取（所以关掉全局规则是**立刻生效**，不用重启）。

## 13. 接口层

**HTTP（同源，`/api/agent-safety/`）**

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/health` | 运行时与 zstd 能力 |
| GET | `/sessions?limit=` | 会话列表（磁盘合并索引） |
| GET/POST | `/session?sessionId=&force=1` | 扫描/读取单会话报告 |
| GET | `/events?sessionId=&from=&to=` | 原始事件切片 |
| GET | `/chain?sessionId=` | 执行链（turn/step/call + 每步叙述 + 数据访问） |
| GET | `/rules` | 规则目录与 41 子类覆盖对照 |
| GET | `/explain?findingId=` | 相邻事件 + 关联调用 + 深链 |
| POST | `/label` | 写 confirmed / benign |
| POST | `/analyze` | 逐轮 AI 分析（缓存） |
| POST | `/verify` | 单条对抗复核（缓存） |
| GET | `/report?format=md\|needs` | Markdown 报告 / 待验证清单 |
| GET | `/cost` | token 账目（固定开销 + 历史分析） |
| GET | `/search?q=` | 跨会话搜发现 |
| GET/POST | `/settings` | 读/改设置 |

**Agent 工具 `safety_audit`**：8 个动作 `scan_session | list_sessions | findings | pending | explain | label | rules | report`；schema 801 字符（约 248 token），带 `verdict` 过滤；返回里固定包含 `counts`、`coverage`、`ledgerTotals`、`validation`、`changes` 和深链。

**全局规则**：53 字符（约 36 token）注入系统提示，内容只有「先调 safety_audit、必须区分已发现与未覆盖」；`injectPrompt=false` 时文本返回空串，DSH 会丢弃空段，实时生效。

## 14. 前端层

**接入点（DSH 槽位，全部是官方扩展点）**

| 槽位 | 组件 | 作用 |
|---|---|---|
| `sidebar.panellist` + `main` | `Panel` | 左侧栏「安全巡检」与主面板 |
| `conversation.input.dock` | `DockBadge` | 输入框上方 `🛡 N 项 · 风险 X`，15 秒轮询 |
| `conversation.chat.assistant-actions` | `AssistantButton` | 助手消息下方盾牌，打开该回答的执行链 |
| `shell.overlay` | `Overlay` | 全屏浮层（深链目标） |
| `commandUi` | `/safety` | 斜杠命令 |

**三个视图**

1. **总览**：风险环、确认/待验证/已排除计数（可点筛选）、A–H 分类分布、事件热力条、Top 发现、整体判断（本地拼装一句话 + 风险集中的轮次）、覆盖台账四态、盲区、导出 Markdown/JSON。
2. **风险清单**：判定优先分组（已确认 → 待验证 → 已排除），已确认的再按严重度分层；每行是类别码 + 判定徽章 + 严重度 + 证据 + seq；点任意一条打开详情浮层。
3. **设置**：开关、阈值、Token 账目（固定开销 / 历史分析累计）。

**浮层（深链目标）**：`#safety?session=<id>&seq=<n>`，另支持 `finding=`、`message=`、`turn=`；打开后按 `seq` 定位到该调用，展示这条回答整轮的调用链（超过 40 个折叠）、所选调用的一键通俗说明（请求/结果/访问数据/风险判定）、原始 JSON 开关、失败步骤快捷入口、AI 详细分析按钮。

**视觉**：严重 `#e5484d` / 高 `#f76b15` / 中 `#f5a524` / 低 `#12a594`；调用按钮按等级描边着色，同一步同名调用加序号（`S1 pwsh ·1`）；失败红边 + ✕；全部使用 `--dsw-*` 设计令牌，深浅色都可用。

**两个必须记住的实现坑**（都踩过）：
1. **hook 顺序**：任何 `useState/useEffect/useCallback` 必须在早退分支（`if (chain === null) return`）之前，否则「加载中 → 有数据」时 hook 数量变化会让整块组件崩溃；
2. **轮询不要重建状态对象**：每 800ms 解析 hash 时必须比较字符串再更新，否则每次都是新对象，依赖它的 effect 会重置用户选中的调用（表现为「点开 S5，一秒后弹回 S1」）。

## 15. 安全与隐私边界

- 只读会话，绝不回写；插件自身只写 `$DSH_HOME/agent-safety/`；
- 无网络出口：所有请求都是同源 `/api/agent-safety/*`；日志里出现的 URL 只作为证据文本，不会被访问；
- 密钥只以 HMAC 指纹形式落地；
- 模型调用只在两个按钮后发生，可在设置里关掉全局规则；
- 不做实时拦截、不做插件信任审计、不做 Token 看板。

## 16. 成本模型（实测）

| 行为 | 花费 |
|---|---|
| 扫描 / 渲染 / 通俗摘要 / 台账 / 校验 | 0（纯本地） |
| 插件常驻开销 | 每轮约 **284 token**：系统提示段 36 + 工具定义 248（关掉 `injectPrompt` 可省 36） |
| 逐轮 AI 分析 | 19 调用一轮 ≈ 2,711 提示词 + 1,687 输出；39 调用一轮 ≈ 5,407 + 3,299（均 8–15 秒） |
| 单条对抗复核 | ≈ 671 提示词 + 49 输出（1.5 秒） |
| 重复查看 | 0（按内容哈希缓存） |

## 17. 测试与验收

| 套件 | 数量 | 覆盖 |
|---|---|---|
| 单元 `node --test` | 31 | 解码/残帧、规则正负例、三态裁定、台账、校验器、报告、增量、客户端注册与渲染 |
| 接口 `test/acceptance.mjs` | 18 | 真实会话：列表、扫描时延、锚点、链、标注、损坏文件、密钥零残留 |
| 面板 `test/cdp-v12.mjs` | 10 | 槽位、判定分组、台账、Markdown 导出、着色、选调用不回弹 |
| 浮层 `test/cdp-nl.mjs` | 8 | 通俗说明、失败标记、原始数据开关、AI 按钮与用量 |

浏览器断言用 Edge headless + CDP，直接操作真实 DOM。

## 18. 已知限制与演进

- **无 OS 级沙箱**：只审计行为，不执行目标代码；因此「命令内部发生了什么」永远只能到待验证；
- **A1 噪音**：读 `~/.dsh` 这类管理动作会被如实确认，量大时靠分类筛选消化；
- **解析在宿主事件循环内**：2060 事件约 320ms；>2 万事件建议搬 Worker；
- **子 agent 独立记账**：subagent 的会话按独立 session 审计，父视图不合并；
- **F 类覆盖最弱**：只有两条待验证规则，后续可借 AI-AND-LLM 攻击面继续扩。
