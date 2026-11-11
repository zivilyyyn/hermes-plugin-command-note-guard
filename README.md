# command-note-guard

> **Alpha — 实验阶段。** 行为、配置键与退回提示可能随时变化，尚未稳定，暂不建议在生产或个人关键流程上依赖。欢迎测试与反馈。

Hermes `pre_tool_call` 插件。执行 `terminal` 前检查命令是否带有审计摘要：

- 不会进入 Hermes 审批/密码流程的命令：直接放行。
- 会进入审批/密码流程且摘要完整：放行，**不改写命令**。
- 会进入审批/密码流程但摘要缺失或不完整：退回该次调用（`action: block`，命令未执行），提示模型补齐摘要后，在同一轮里**原样重发同一条命令**。

默认模式是 `strict`。插件不会代写摘要，摘要必须由当时的模型自己写。

## 三行摘要格式

摘要必须是命令开头连续的 `#` 注释行（遇到第一个非注释行即停止），固定三行：

```text
# 【新改动|回滚|只读】用途=一句话说明这条命令要做什么
# 写入=写到哪里：文件/目录/服务/远端主机；只读则写 无
# 失败影响=失败时会怎样，一句话
```

规则：

- 第一行必须以 `#` 开头，并带 `【新改动】`、`【回滚】`、`【只读】` 三选一标签。
- 第二、三行也必须以 `#` 开头。
- 三个键名容错：`用途=` / `用途:` / `用途：`；`写入=` / `写入:` / `写入：`；`失败影响=` / `失败影响:` / `失败影响：`，也接受 `失败=`。
- 摘要行之后必须紧跟原命令本身，插件不会修改、移动或重新拼接命令。
- 摘要只用于审批卡片展示，不参与执行。

完整示例：

```text
# 【回滚】用途=清理临时目录
# 写入=/tmp/cng
# 失败影响=不可恢复
rm -rf /tmp/x
```

## 退回后的流程

1. 第一次调用会进入审批但缺少摘要，插件返回 `block`，命令不会执行。
2. 审批卡片显示命中项、缺少项（`label` / `用途` / `写入` / `失败影响`）和三行格式示例。
3. 模型按格式补写摘要，在**同一轮**里原样重发同一条命令（命令本身不要改）。
4. 摘要完整后插件放行；后续命令照常执行。

退回提示固定为：

```text
这条命令缺少审计摘要，已退回（未执行）。命中形态：recursive delete
缺：label、用途、写入、失败影响

请补成三行注释后，原样重发同一条命令（命令本身不要改）：
# 【新改动|回滚|只读】用途=做什么
# 写入=写到哪（只读写 无）
# 失败影响=失败会怎样

示例：
# 【新改动】用途=重启示例服务加载新版插件
# 写入=launchctl gui/<uid> 域
# 失败影响=服务短暂中断，随后自动重连
```

## execute_code 覆盖

`execute_code` 在沙箱里可以通过 `hermes_tools.terminal(command, ...)`（含别名导入）回调真正的 `terminal` 工具，同样会触发审批与 `sudo` 密码框。插件会对 `execute_code` 的 `code` 做静态分析，取出其中每个 `terminal(...)` 调用的 command，套用同一套审批判据与三行摘要规则。

覆盖范围：

- 直接字符串字面量：`terminal("rm -rf /tmp/x")`。
- `command=` 关键字：`terminal(command="kill 123")`。
- 同一函数体或模块级、调用之前最近一次 `ast.Constant(str)` 赋值：`cmd = "rm -rf /tmp/x"; terminal(cmd)`。只回溯一层，不做控制流分析。
- f-string 的静态部分：`terminal(f"rm -rf {p}")` 按 `rm -rf {}` 近似文本判断审批命中项与摘要。
- 函数别名与属性调用：`from hermes_tools import terminal as t` 之后的 `t(...)`，以及 `hermes_tools.terminal(...)`。

不覆盖（静态取不到 command 时直接放行，不会代写摘要）：

- 动态拼接、函数返回值、下标、`join` 等非字面量或非单层 `Name` 的 command。
- 通过 `subprocess`、`os.system` 等自行调起的命令。
- 多层变量传递：`a = "rm ..."; b = a; terminal(b)`。

摘要必须写在 **command 字符串**开头，而不是 `execute_code` 的 Python 源码里。例如：

```python
from hermes_tools import terminal
terminal(
    "# 【只读】用途=查看目录\n"
    "# 写入=无\n"
    "# 失败影响=无\n"
    "ls -la"
)
```

Python 源码里的注释不算摘要。多个 `terminal()` 调用都不合格时，退回提示只报第一个，并给出不合格总数。

## 模式开关

环境变量在插件导入时读取一次，修改后需重载 Hermes。

```bash
# 默认（都不设）：strict，会进入审批就要求三行摘要，缺失即退回
unset COMMAND_NOTE_GUARD COMMAND_NOTE_GUARD_DRY

# 完全关闭：不注册、不生效；0 / false 等价
export COMMAND_NOTE_GUARD=off

# 宽松：会进入审批时只要求首行是 #，不检查三键
export COMMAND_NOTE_GUARD=lenient

# 旧行为回退：不拦截，自动补一行摘要后放行
export COMMAND_NOTE_GUARD=annotate

# 灰测：只 logger.info 记录缺少项，不改命令、不拦截
export COMMAND_NOTE_GUARD_DRY=1
```

`COMMAND_NOTE_GUARD_DRY=1` 优先级最高：只记录、不改、不拦。

### annotate 旧行为

```text
# 【自动补注】recursive delete | 对象：/tmp/x | 后果：recursive delete
rm -rf /tmp/x
```

- 摘要固定为单行，≤140 字符。
- 原命令逐字保留在第二行，缩进、换行都不变。
- 首行（第一个非空行）已经是 `#` 注释时不补注。
- 摘要只用于审批卡片展示，不参与执行；命令照常运行。
- 日志只记录命中项，不记录命令正文或对象内容。

## 判据来源：Hermes 审批模块

插件不再维护自己的风险形态清单。判据只有一个问题：**这条命令会不会进入 Hermes 的审批/密码流程**。

命中检测直接调用 Hermes 源码里的两个纯函数（延迟 import，避免插件加载期失败）：

```python
from tools.approval_detection import (
    detect_dangerous_command,
    detect_hardline_command,
)
```

- `detect_hardline_command(command)` 返回 `(True, description)`：追加 `hardline:<description>`。这是 Hermes 的硬拦截底线，`--yolo` 也不能绕过。
- `detect_dangerous_command(command)` 返回 `(True, key, description)`：追加 `description or key`。这与 `terminal_tool` 的审批守卫使用同一张 `DANGEROUS_PATTERNS` 表。
- 非注释行里出现 `\bsudo\b`：追加 `sudo`。`sudo` 会单独触发密码框，不包含在上面两个函数里。

也就是说，这里的命中集合与 Hermes 审批守卫同源；Hermes 不要求审批的命令，本插件也不要求摘要。

### 相比旧清单的行为变化

旧版按自建形态表判断，会对一些实际不进入审批的命令要求摘要。以下命令现在**不再要求摘要**：

- `scp` / `rsync`：分类器不 flag（除非同时命中真正的危险模式）；旧清单的 `remote-copy` 命中已不再要求摘要。
- `chmod` / `chown` 的普通权限修改（例如 `chmod 700 ~/x.sh`）：只有 `777` / `666` / other-writable、递归 chown root 等危险写法才命中；旧清单的 `permissions` 命中已不再要求摘要。
- `launchctl print` 等只读子命令：分类器不 flag，因此不要求摘要（旧清单本来也只匹配操作类子命令）。普通服务的 `launchctl bootout gui/501/local.foo` 则从旧清单的 `launchd` 命中变为不要求摘要；分类器只对 `ai.hermes` / `hermes` 网关标签的 `stop` / `kickstart` / `bootout` / `unload` / `kill` / `disable` / `remove` 报审批。
- 普通重定向到非敏感目标（例如 `echo hi > /dev/null 2>&1`）：不命中（旧清单也排除了 `/dev/null` 与 `2>&1`）；`> /etc/...` 等敏感路径仍会命中。
- 普通 `kill -9 <pid>`：分类器只 flag `kill -9 -1`、`pkill -9` 等宽范围终止；旧清单的 `kill-process` 命中已不再要求摘要。

反过来，旧清单未覆盖但 Hermes 会审批的命令（例如 SQL `DELETE` 无 `WHERE`、`git reset --hard`、敏感路径写入等）现在也会要求摘要。`python3 -c 'print(1)'` 也仍会命中 `script execution via -e/-c flag`，因为分类器本身就会 flag 内联脚本。

同一命令可能命中多个项，日志与退回提示会列出全部命中项。

## 日志

- 退回：`command-note-guard: blocked <hits> missing=<missing>`，只记录命中项和缺失项，不记录命令正文。
- annotate：`command-note-guard: annotated <hits>`。
- 灰测：`command-note-guard: dry-run missing=<missing> hits=<hits>`。
- 关闭：`command-note-guard: disabled by COMMAND_NOTE_GUARD`。

## 已知局限

1. `execute_code` 只做静态分析：动态拼接、函数返回值、下标、`join`、多层变量传递等取不到字面量的 command 会直接放行。例如 `cmd = "rm " + "-rf /tmp/x"`。
2. 通过 `subprocess`、`os.system` 等自行调起的命令不在 `terminal` 的审批路径上，插件也看不到。
3. 插件跑在 host 隔离模式、无法 import `tools.approval_detection` 时，启用一份五条兜底规则（`fallback:recursive-delete`、`fallback:sql-drop`、`fallback:inline-script`、`fallback:heredoc`、`fallback:sudo`），仍要求摘要，只记一次 warning。此时覆盖率明显低于正常路径，其余命令会放行。
4. 判据与 Hermes 审批守卫同源：Hermes 分类器不 flag 的命令，本插件也不会要求摘要；这不是「命令一定安全」的保证。
5. 摘要只认命令开头连续的 `#` 行；摘要与命令之间插入空行，或把摘要写到命令之后，都会被判为缺失。
6. 插件内部异常一律放行；任何解析失败都不会阻止命令执行。
