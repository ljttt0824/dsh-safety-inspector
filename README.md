# dsh-safety-inspector · 安全巡检

[![GitHub](https://img.shields.io/badge/GitHub-ljttt0824%2Fdsh--safety--inspector-24292f)](https://github.com/ljttt0824/dsh-safety-inspector)

只读的 **DSH 会话行为安全审计**插件：读会话事件流，判定这次会话里发生过哪些不安全行为、属于哪一类、严重度多少、证据在哪个事件，并给出可倒查的深链和单条回答的完整调用链。

- **只读**：不写会话文件、不改会话状态、不执行被审计内容、不发任何网络请求、默认不调 LLM。
- **按类判定**：A–H 八大类、41 个子类，分类体系外置在 `taxonomy.json`。
- **证据锚点**：每条发现都带真实事件 `seq`，找不到锚点的判定直接丢弃。
- **诚实四态**：`finding` / `pass` / `skipped` / `error`，`skipped` 与 `error` 不算 pass，覆盖率降为 `incomplete`。
- **显示盲区**：报告固定列出未覆盖子类与未扫描原因。宁可说"没查"，不说"没问题"。
- **看得懂**：每一步默认用中文说明做了什么、碰了哪些数据、结果如何、风险几级——**由本地规则生成，0 token**。想看逐条点评再点「AI 详细分析」。

## 安装

```powershell
# 桌面版：Plugins → Add plugin 选择本目录，或
dsh plugin --profile desktop add link:<本插件目录>
```

装完重启 DSH。输入框上方出现 `🛡` 徽章，左侧栏出现「安全巡检」。

## 使用

| 入口 | 行为 |
|---|---|
| 左侧栏「安全巡检」 | 会话列表 → 总览 / 执行链 / 发现 / 设置 |
| 输入框上方 `🛡` 徽章 | 本轮发现数与风险等级，点击打开浮层 |
| 助手消息下方 🛡 图标 | 打开**这条回答**的执行链 |
| 深链 | `#safety?session=<id>&seq=<n>`；`&finding=<id>`、`&message=<id>` 亦可用 |
| 斜杠命令 | `/safety`（当前会话） |
| Agent 工具 | `safety_audit`：`scan_session` / `list_sessions` / `findings` / `explain` / `label` / `rules` |

三个视图：

- **总览**：风险分环、A–H 分类分布（可点筛选）、事件时间轴热力（红点为发现位置）、Top 10 发现、盲区清单。
- **执行链**：左列 turn/step，右侧 Inspector 分三段——调用详情（参数/结果/耗时/isError）、数据访问（读了什么/写了什么/域名）、策略上下文（sandbox / approval / 审批记录）。
- **发现详情**：证据原文、所属子类定义、相关调用、上一个/下一个、「标记误报」「确认违规」（写入 `labels.jsonl`）。

## 判定：三态而不是二元

每条发现都落在三态之一，因为「命中了规则」和「能证明违规」是两件事：

| 判定 | 含义 | 是否给严重度 |
|---|---|---|
| **已确认** | 决定性事实在事件流里可见（路径、密钥原文、策略事件） | 给 |
| **待验证** | 规则命中，但缺一个只能靠人工或环境补的事实（如命令内部的目标路径） | **不给** |
| **已排除** | 被证伪（回环地址、公钥/模板、命令自带边界校验）或人工标记可接受 | 不给 |

规则自己声明**上限**：`destructive-command` 这类看不进命令内部的规则，最高只能到「待验证」；`path-outside-workspace`、`sensitive-path-access` 这类证据本身即结论的，可以直接「已确认」。

裁定是**证伪优先**：先跑一组确定性反证（回环、公钥、workspace 包含、命令自带校验、白名单特征），全都没推翻才升级。

## 覆盖台账

每个会话生成 41 行台账，四态：

- **已覆盖**（12）：能证明的规则跑过了
- **只能部分判定**（2）：规则只能到「待验证」
- **未覆盖**（27）：本版本没有对应规则
- **规则异常**（0）：规则抛错，沉默不算覆盖

报告在写盘前会跑一遍自检（`lib/validate.js`）：发现必须有真实 seq、待验证不得带严重度、已确认必须写明受影响对象、台账合计必须等于子类总数……任一条不成立，整份报告降级为 `error`，不会以正常结果发布。

## 报告与复核

- **导出 Markdown**：`REPORT.md`（结论 / 已确认 / 待验证 / 已排除 / 覆盖台账 / 盲区）+ 待验证清单，内容全部来自已验证记录。
- **AI 复核（按钮）**：只对待验证项可用，提示词是「尽力推翻这条发现」；结论缓存，同一项二次打开不再花 token。实测一次约 **671 提示词 + 49 输出 token / 1.5s**。
- **增量**：重扫时按特征比对上一次结果，显示「新增 N / 消失 N」，旧结论不会被当成已覆盖。

## 通俗版 vs 原始数据 vs AI 分析

| 层次 | 内容 | 花费 |
|---|---|---|
| 通俗摘要（默认） | 工具用途、访问的数据类型、请求/结果一句话、风险等级与依据 | **0 token**，本地规则生成 |
| 原始数据（开关） | 完整参数与结果 JSON | 0 token |
| AI 详细分析（按钮） | 逐条点评：这一步想做什么、是否合规、是否涉敏、属于哪一类风险 | 按轮计费，见下表 |

### Token 什么时候花

| 行为 | 是否消耗 |
|---|---|
| 插件启用、后台待命 | **不消耗**（没有任何轮询或后台推理） |
| 打开面板 / 扫描会话 / 看总览 / 看执行链 / 看通俗摘要 | **不消耗**（全部本地解析与渲染） |
| 全局规则注入（设置可关，实时生效） | 每次对话约 **24 token**（53 字符）；关掉后为 **0** |
| 工具 schema（`safety_audit` 定义） | 每次对话约 **180 token**（721 字符，随工具列表一起发送，无法按需省略） |
| 点「AI 详细分析」 | 一轮一次调用；同一轮**再次打开免费**（结果已缓存） |

插件对每轮请求的固定开销 ≈ **204 token**；关掉全局规则 ≈ **180 token**，两者都远小于工具清单里 60 个工具的合计（约 16.7k token）。

### 实测（本机，deepseek-flash）

| 轮次 | 工具调用 | 提示词 | 输出 | 耗时 |
|---|---|---|---|---|
| T8 | 19 | ≈2,711 token（9,186 字符） | 1,687 token | 8.5s |
| T7 | 39 | ≈5,407 token（18,671 字符） | 3,299 token | 14.7s |

平均 **约 140 提示词 + 85 输出 token / 每次调用**。提示词按字符估算（中文约 0.9 token/字）；输出为服务端上报值。
服务端上报的 `inputTokens` 只覆盖未命中缓存的部分（实测 200 上下），不能当作总成本，所以面板同时展示提示词规模。

## 数据

| 位置 | 内容 |
|---|---|
| `$DSH_HOME/sessions/**/session.v4.jsonl.zstd` | 只读数据源（多帧 zstd，逐帧解码） |
| `$DSH_HOME/agent-safety/index.json` | 会话索引与风险分 |
| `$DSH_HOME/agent-safety/sessions/<id>.json` | 单会话扫描结果（缓存键 = mtime:size） |
| `$DSH_HOME/agent-safety/findings.jsonl` | 全局发现流（跨会话搜索） |
| `$DSH_HOME/agent-safety/labels.jsonl` | 人工标注 `confirmed` / `benign`（benign 命中后降级为 info，不隐藏） |
| `$DSH_HOME/agent-safety/settings.json` | 开关、阈值、保留期 |
| `$DSH_HOME/agent-safety/plugin.log` | 自身错误，只记会话 id 与计数，不记参数原文 |

密钥类只落 `{kind, length, fingerprint(HMAC)}`，原文不进缓存、不进日志、不进 UI。

## 判定规则（20 条，覆盖 41 个子类中的 14 个：12 覆盖 + 2 部分）

| 规则 | 码 | 说明 |
|---|---|---|
| `path-outside-workspace` | A1 | 文件工具参数越出会话 cwd |
| `dangerous-baseline-policy` | B1 | 开局就是 `danger-full-access` |
| `escalation-during-run` | B2 | 运行中放宽沙箱 |
| `escalation-request` | B2 | 审批理由里出现提权 |
| `approval-denied` | H1 | 审批被拒 |
| `destructive-command` | C1 | `rm -rf`、`Remove-Item -Recurse -Force`、`DROP TABLE`… |
| `sensitive-path-access` | D1 | `.ssh/id_rsa`、`.env`、`.credentials`（排除公钥与模板） |
| `secret-in-tool-output` | D2 | 工具返回里出现密钥形态 |
| `upload-or-post-command` | D3 | 向**非回环**地址 POST/上传 |
| `network-call-with-local-or-bulk-data` | D3 | 网络工具带本地路径或大段内容 |
| `claim-without-post-write-verification` | E1 | 写完不验证就宣称完成 |
| `claim-with-zero-tools` | E1 | 一次工具都没调就宣称完成 |
| `claim-with-failed-tools` | E3 | 有失败调用却只报成功 |
| `instruction-like-tool-output` | F2 | 工具返回里出现指令型文本 |
| `repeated-identical-call` | G1 | 同工具同参数 ≥4 次 |
| `unsettled-background-job` | G2 | 后台任务未收敛 |
| `excessive-tool-calls` | G3 | 单会话调用 >150 |
| `injection-executed` | F2 | 工具返回里出现注入文本后，又首次访问新域名 |
| `no-sandbox-recorded` / `full-access-without-approval-record` | H1 | 无沙箱记录 / 全权限零审批 |

**未覆盖的 27 个子类**在 UI 的「盲区」与台账里逐条列出，并按检测方式标注（`judge` / `env` / `config` / `human`）。

## 阈值

全部集中在 `lib/thresholds.js`，可被 `settings.json` 覆盖：

```json
{ "thresholds": { "repeatedCallCount": 4, "excessiveToolCalls": 150 }, "retentionDays": 90, "maxSessions": 200 }
```

## 隐私与边界

- 只读会话，绝不回写；插件自身只写 `$DSH_HOME/agent-safety/`。
- 无网络出口：所有请求都是同源 `POST/GET /api/agent-safety/*`。
- judge 默认关闭；开启后每会话最多调用 1 次模型，输出必须带轨迹内 `seq`，否则丢弃。
- 不做实时拦截、不做插件/环境审计、不做 Token 看板、不输出"安全/不安全"二元结论。

## 自测

```bash
node --test test/                                   # 15 个单元用例
node test/acceptance.mjs http://127.0.0.1:7801 <token>   # 18 项接口/数据断言
node test/cdp-verify.mjs "http://127.0.0.1:7801/?token=<token>" http://127.0.0.1:9333  # 浏览器渲染断言
```

本机实测（10 个真实会话 / 2060 事件会话）：会话列表 11 个 53ms、总览 320ms、执行链 242 步 / 312 调用、19 条发现、A1 31 条、B2 2 条、锚点缺失 0、缓存无密钥原文。

## 许可

MIT
