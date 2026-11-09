# command-note-guard

> **Alpha — 实验阶段。** 行为、配置键与退回提示可能随时变化，尚未稳定，暂不建议在生产或个人关键流程上依赖。欢迎测试与反馈。

Hermes `pre_tool_call` 插件。执行 `terminal` 前检查命令是否带有审计摘要：

- 只读命令、未命中风险形态的命令：直接放行。
- 命中风险形态且摘要完整：放行，**不改写命令**。
- 命中风险形态但摘要缺失或不完整：退回该次调用（`action: block`，命令未执行），提示模型补齐摘要后，在同一轮里**原样重发同一条命令**。

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

1. 第一次调用命中风险形态但缺少摘要，插件返回 `block`，命令不会执行。
2. 审批卡片显示命中形态、缺少项（`label` / `用途` / `写入` / `失败影响`）和三行格式示例。
3. 模型按格式补写摘要，在**同一轮**里原样重发同一条命令（命令本身不要改）。
4. 摘要完整后插件放行；后续命令照常执行。

退回提示固定为：

```text
这条命令缺少审计摘要，已退回（未执行）。命中形态：recursive-delete
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

## 模式开关

环境变量在插件导入时读取一次，修改后需重载 Hermes。

```bash
# 默认（都不设）：strict，命中风险形态就要求三行摘要，缺失即退回
unset COMMAND_NOTE_GUARD COMMAND_NOTE_GUARD_DRY

# 完全关闭：不注册、不生效；0 / false 等价
export COMMAND_NOTE_GUARD=off

# 宽松：命中风险形态时只要求首行是 #，不检查三键
export COMMAND_NOTE_GUARD=lenient

# 旧行为回退：不拦截，自动补一行摘要后放行
export COMMAND_NOTE_GUARD=annotate

# 灰测：只 logger.info 记录缺少项，不改命令、不拦截
export COMMAND_NOTE_GUARD_DRY=1
```

`COMMAND_NOTE_GUARD_DRY=1` 优先级最高：只记录、不改、不拦。

### annotate 旧行为

```text
# 【自动补注】recursive-delete | 对象：/tmp/x | 后果：删除目录及其内容，不可恢复
rm -rf /tmp/x
```

- 摘要固定为单行，≤140 字符。
- 原命令逐字保留在第二行，缩进、换行都不变。
- 首行（第一个非空行）已经是 `#` 注释时不补注。
- 摘要只用于审批卡片展示，不参与执行；命令照常运行。
- 日志只记录命中的形态名，不记录命令正文或对象内容。

## 命中形态

| 短名 | 判定 |
|---|---|
| `recursive-delete` | `rm -r` / `rm -rf` / `rm --recursive` |
| `sql-drop` | `DROP TABLE` / `DATABASE` / `SCHEMA` / `INDEX`（忽略大小写） |
| `redirect-write` | `>` / `>>` 写入真实文件；`/dev/null` 与 `2>&1` 等丢弃输出写法除外 |
| `inline-script` | `python -c`、`bash -c`、`node -e` 等直接执行代码 |
| `heredoc` | `<<EOF`、`<<'EOF'`、`<<-EOF` |
| `kill-process` | `kill` / `pkill` / `killall` / `Stop-Process` |
| `permissions` | `chmod` / `chown` |
| `launchd` | `launchctl` 的 bootout / bootstrap / kickstart / load / unload / enable / disable |
| `remote-copy` | `scp` / `rsync` |
| `remote-exec` | `ssh` + 远端写动词：`rm` / `cp` / `mv` / `dd` / `tee` / `chmod` / `chown` / `kill` / `pkill` / `launchctl` / `scp` / `rsync`（引号内也算）；`ssh host ls`、`ssh host cat x` 等只读不命中 |
| `privilege` | 非注释行中的 `sudo` |
| `system-path-write` | 路径命中 `/etc/`、`/Library/LaunchDaemons/`、`/System/`、`/private/etc/`、`~/.hermes/config.yaml`、`$HOME/.hermes/config.yaml`，**且**命令同时含写语义（重定向、`tee`、`cp`、`mv`、`install`、`sed -i`、`rm`、`chmod`、`chown`、`ln`、`truncate`、`dd`、`defaults write`、`plutil -replace`、`crontab`）；对只读动词主导的命令（`cat`、`ls`、`grep` 等）豁免 |

同一命令可能命中多个形态，日志与退回提示会列出全部命中项。

## 日志

- 退回：`command-note-guard: blocked <hits> missing=<missing>`，只记录形态名和缺失项，不记录命令正文。
- annotate：`command-note-guard: annotated <hits>`。
- 灰测：`command-note-guard: dry-run missing=<missing> hits=<hits>`。
- 关闭：`command-note-guard: disabled by COMMAND_NOTE_GUARD`。

## 已知局限

1. 纯计算的 `python3 -c 'print(1)'` 也会命中 `inline-script`，需要写摘要，但实际可能没有任何副作用。
2. 普通调试输出 `echo test > /tmp/x.log` 会命中 `redirect-write`（写入系统路径时还会命中 `system-path-write`），即使只是日志也要写摘要。
3. `chmod` / `chown` 即使作用于临时文件也会命中 `permissions`；`ssh` 的远端复合命令只要出现写动词就整体命中 `remote-exec`，无法区分远端只读部分。
4. 摘要只认命令开头连续的 `#` 行；摘要与命令之间插入空行，或把摘要写到命令之后，都会被判为缺失。
5. 风险形态匹配仍会扫过注释文本本身；注释里出现 `rm`、`launchctl bootout` 等词时，可能被当作风险形态命中。
6. 插件内部异常一律放行；任何解析失败都不会阻止命令执行。
