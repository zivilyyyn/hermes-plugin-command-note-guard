"""Require a three-line audit summary on risky ``terminal`` commands.

By default the plugin is strict: when a command shape can delete, overwrite,
execute inline code, change permissions, touch system paths, or otherwise have
side effects, the command must start with three ``#`` comment lines:

    # 【新改动|回滚|只读】用途=一句话说明
    # 写入=写到哪里（只读写 无）
    # 失败影响=失败时会怎样

If any part is missing, the call is blocked without changing the command. The
model rewrites the note and resends the same command in the same turn.

``COMMAND_NOTE_GUARD=annotate`` restores the old auto-annotation behaviour;
``lenient`` only requires a leading ``#`` line; ``off``/``0``/``false``
disables the plugin; ``COMMAND_NOTE_GUARD_DRY=1`` only logs.

Fail-open: any unexpected error returns ``None`` so the tool still runs.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from typing import Any, Optional

logger = logging.getLogger(__name__)

_ENV_MODE = os.environ.get("COMMAND_NOTE_GUARD", "").strip().lower()
_DISABLED = _ENV_MODE in {"off", "0", "false"}
_ANNOTATE_MODE = _ENV_MODE == "annotate"
_LENIENT_MODE = _ENV_MODE == "lenient"
_DRY_RUN = os.environ.get("COMMAND_NOTE_GUARD_DRY", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def _has_file_redirect(command: str) -> bool:
    """Return True when output is redirected to a real file rather than /dev/null."""
    i = 0
    quote = ""
    length = len(command)
    while i < length:
        char = command[i]
        if quote:
            if char == "\\" and quote == '"':
                i += 2
                continue
            if char == quote:
                quote = ""
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
            i += 1
            continue
        if char == "\\":
            i += 2
            continue
        if char != ">":
            i += 1
            continue

        j = i + 1
        if j < length and command[j] == ">":
            j += 1
        while j < length and command[j] in " \t":
            j += 1
        if j < length and command[j] == "&":
            # File-descriptor duplication such as 2>&1 or >&2, not a file write.
            i = j + 1
            continue
        if j < length and command[j] == "|":
            # Clobber redirect >| file.
            j += 1
            while j < length and command[j] in " \t":
                j += 1

        start = j
        while j < length and command[j] not in " \t\r\n;&|<>()":
            j += 1
        target = command[start:j].strip("'\"")
        if target and target != "/dev/null":
            return True
        i = j if j > i else i + 1
    return False


def _has_uncommented_sudo(command: str) -> bool:
    """Return True when sudo appears on a line that is not a comment line."""
    for line in command.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\bsudo\b", line):
            return True
    return False


def _strip_quoted(text: str) -> str:
    """Blank the inside of quoted strings, keeping the quotes and outside text."""
    out: list[str] = []
    quote = ""
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if quote:
            if char == "\\" and quote == '"' and i + 1 < length:
                # Escaped character inside double quotes, including \" itself.
                out.append(" ")
                out.append(" ")
                i += 2
                continue
            if char == quote:
                quote = ""
                out.append(char)
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
            out.append(char)
        else:
            out.append(char)
        i += 1
    return "".join(out)


_SYSTEM_PATH_RE = re.compile(
    r"/etc/|/Library/LaunchDaemons/|/System/|/private/etc/"
    r"|~/\.hermes/config\.yaml|\$HOME/\.hermes/config\.yaml"
)
_WRITE_INTENT_RE = re.compile(
    r"(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|sed\s+-i|\brm\b|\bchmod\b"
    r"|\bchown\b|\bln\b|\btruncate\b|\bdd\b|\bdefaults\s+write\b"
    r"|\bplutil\s+-replace\b|\bcrontab\b)"
)


_READ_ONLY_VERBS = frozenset({
    "cat", "ls", "grep", "egrep", "fgrep", "rg", "head", "tail", "less",
    "more", "stat", "file", "wc", "mdls", "strings", "diff", "find", "du",
    "df", "ps", "id", "uname", "sw_vers", "launchctl", "plutil", "echo",
    "printf", "test",
})
_SEGMENT_SPLIT_RE = re.compile(r"\|\||&&|[|;]")
_FORCE_WRITE_RE = re.compile(
    r"\bplutil\s+-replace\b|\bdefaults\s+write\b|sed\s+-i|\btee\b|\bcrontab\b"
)


def _is_assignment(token: str) -> bool:
    """Return True for a leading ``KEY=value`` environment assignment."""
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token))


def _segment_first_token(segment: str) -> str:
    """Return the first non-assignment token of one command segment."""
    for token in segment.split():
        if not _is_assignment(token):
            return token
    return ""


def _read_only_dominant(command: str) -> bool:
    """Return True when every command segment starts with a read-only verb."""
    tokens = [
        _segment_first_token(segment)
        for segment in _SEGMENT_SPLIT_RE.split(command)
        if segment.strip()
    ]
    tokens = [token for token in tokens if token]
    return bool(tokens) and all(token in _READ_ONLY_VERBS for token in tokens)


def _has_force_write(command: str) -> bool:
    """Return True when the command contains an unambiguous write shape."""
    return bool(
        _FORCE_WRITE_RE.search(command)
        or ">>" in command
        or _has_file_redirect(command)
    )


def _has_system_path_write(command: str) -> bool:
    """Return True only when a sensitive path is paired with write intent."""
    if not (_SYSTEM_PATH_RE.search(command) and _WRITE_INTENT_RE.search(command)):
        return False
    # Commands dominated by read-only verbs are inspection, not writes, unless
    # an explicit write construct overrides the exemption.
    if _read_only_dominant(command) and not _has_force_write(command):
        return False
    return True


# Central table: short name -> compiled regex or callable matcher.
# Add or remove shapes here; the hook logic does not need to change.
_RISK_PATTERNS: tuple[tuple[str, Any], ...] = (
    ("recursive-delete", lambda command: re.search(
        r"\brm\s+(?:--recursive\b|-[a-zA-Z]*[rR][a-zA-Z]*\b)", _strip_quoted(command)
    )),
    ("sql-drop", lambda command: re.search(
        r"\bdrop\s+(?:table|database|schema|index)\b", _strip_quoted(command), re.IGNORECASE
    )),
    ("redirect-write", _has_file_redirect),
    ("inline-script", re.compile(r"\b(?:python3?|ruby|perl|node|sh|bash|zsh)\s+-[a-zA-Z]*[ce]\b")),
    ("heredoc", re.compile(r"<<-?\s*['\"]?[A-Za-z_][A-Za-z0-9_]*")),
    ("kill-process", re.compile(r"\b(?:kill|pkill|killall)\b|Stop-Process")),
    ("permissions", re.compile(r"\b(?:chmod|chown)\b")),
    ("launchd", re.compile(r"\blaunchctl\s+(?:bootout|bootstrap|kickstart|load|unload|enable|disable)\b")),
    ("remote-copy", re.compile(r"\b(?:scp|rsync)\b")),
    ("privilege", _has_uncommented_sudo),
    ("system-path-write", _has_system_path_write),
    ("remote-exec", lambda command: bool(
        re.search(r"(?<![\w./-])ssh\s+\S", command)
        and re.search(
            r"\b(?:rm|cp|mv|dd|tee|chmod|chown|kill|pkill|launchctl|scp|rsync)\b",
            command,
        )
    )),
)


def _first_nonempty_line(command: str) -> str:
    """Return the stripped first non-empty line, or an empty string."""
    for line in command.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


_NOTE_LABELS = ("【新改动】", "【回滚】", "【只读】")
_NOTE_KEY_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("用途", ("用途",)),
    ("写入", ("写入",)),
    ("失败影响", ("失败影响", "失败")),
)
_NOTE_KEY_SEP = r"\s*[=:：]"


def _comment_header(command: str) -> list[str]:
    """Return the leading consecutive ``#`` comment lines, stripped.

    The first non-comment line, including a blank line, ends the header.
    """
    header: list[str] = []
    for line in command.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            break
        header.append(stripped)
    return header


def _note_status(command: str) -> tuple[bool, list[str]]:
    """Check the three-line audit note and return ``(ok, missing)``.

    ``missing`` contains any of ``label``, ``用途``, ``写入``, ``失败影响``.
    """
    header = _comment_header(command)
    text = "\n".join(header)
    first_line = header[0] if header else ""

    missing: list[str] = []
    if not first_line.startswith("#") or not any(
        label in first_line for label in _NOTE_LABELS
    ):
        missing.append("label")
    for name, aliases in _NOTE_KEY_ALIASES:
        if not any(
            re.search(re.escape(alias) + _NOTE_KEY_SEP, text) for alias in aliases
        ):
            missing.append(name)
    return (not missing, missing)


def _match_risk(command: str) -> list[str]:
    """Return the short names of every risky shape found in the command."""
    hits: list[str] = []
    for name, matcher in _RISK_PATTERNS:
        if hasattr(matcher, "search"):
            matched = matcher.search(command) is not None
        else:
            matched = bool(matcher(command))
        if matched:
            hits.append(name)
    return hits


_CONSEQUENCES: dict[str, str] = {
    "recursive-delete": "删除目录及其内容，不可恢复",
    "sql-drop": "删除数据库对象，不可恢复",
    "redirect-write": "覆盖写入文件",
    "inline-script": "执行内联脚本，可读写文件与访问网络",
    "heredoc": "通过 heredoc 执行多行脚本",
    "kill-process": "终止进程，被终止的任务会中断",
    "permissions": "修改文件权限或属主",
    "launchd": "变更 launchd 任务，可能中断正在运行的服务",
    "remote-copy": "向远端或本地复制文件",
    "privilege": "以 root 权限执行",
    "system-path-write": "写入系统路径",
    "remote-exec": "在远端主机执行命令",
}
_FALLBACK_CONSEQUENCE = "执行带副作用的命令"

_NOISE_TOKENS = frozenset({
    "do", "done", "then", "fi", "else", "elif", "for", "in", "while",
    "case", "esac", "!", "{", "}", "if",
})
_SYSTEM_PATH_PREFIXES = (
    "/etc/",
    "/Library/LaunchDaemons/",
    "/System/",
    "/private/etc/",
)
_HOME_CONFIG_PATHS = frozenset({
    "~/.hermes/config.yaml",
    "$HOME/.hermes/config.yaml",
})


def _consequence(hits: list[str]) -> str:
    """Return the consequence sentence for the first matched shape."""
    if not hits:
        return _FALLBACK_CONSEQUENCE
    return _CONSEQUENCES.get(hits[0], _FALLBACK_CONSEQUENCE)


def _clean_token(token: str) -> str:
    """Trim shell punctuation that shlex leaves attached to a token."""
    return token.strip(" \t\r\n;&|(){}[]<>")


def _tokenize(segment: str) -> list[str]:
    """Best-effort shell tokenisation that never raises."""
    try:
        return [_clean_token(token) for token in shlex.split(segment)]
    except Exception:
        return [_clean_token(token) for token in segment.split()]


def _iter_segment_tokens(command: str):
    """Yield token lists for each shell segment, skipping empty segments."""
    for segment in _SEGMENT_SPLIT_RE.split(command):
        if not segment.strip():
            continue
        tokens = [token for token in _tokenize(segment) if token]
        if tokens:
            yield tokens


def _redirect_targets(command: str) -> list[str]:
    """Return file targets of ``>`` / ``>>`` redirects, in order."""
    targets: list[str] = []
    i = 0
    quote = ""
    length = len(command)
    while i < length:
        char = command[i]
        if quote:
            if char == "\\" and quote == '"':
                i += 2
                continue
            if char == quote:
                quote = ""
            i += 1
            continue
        if char in ("'", '"'):
            quote = char
            i += 1
            continue
        if char == "\\":
            i += 2
            continue
        if char != ">":
            i += 1
            continue

        j = i + 1
        if j < length and command[j] == ">":
            j += 1
        while j < length and command[j] in " \t":
            j += 1
        if j < length and command[j] == "&":
            # File-descriptor duplication such as 2>&1 or >&2.
            i = j + 1
            continue
        if j < length and command[j] == "|":
            # Clobber redirect >| file.
            j += 1
            while j < length and command[j] in " \t":
                j += 1

        start = j
        while j < length and command[j] not in " \t\r\n;&|<>()":
            j += 1
        target = command[start:j].strip("'\"")
        if target and target != "/dev/null" and not re.fullmatch(r"&\d", target):
            targets.append(target)
        i = j if j > i else i + 1
    return targets


def _flag_targets(command: str, flags: tuple[str, ...]) -> list[str]:
    """Return values passed to short/long output-style flags."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        for index, token in enumerate(tokens):
            if token in flags and index + 1 < len(tokens):
                value = tokens[index + 1]
                if value and not value.startswith("-"):
                    targets.append(value)
    return targets


def _rm_targets(command: str) -> list[str]:
    """Return non-option arguments following an ``rm`` token."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        for index, token in enumerate(tokens):
            if token != "rm":
                continue
            for candidate in tokens[index + 1:]:
                if candidate.startswith("-") or candidate in _NOISE_TOKENS:
                    continue
                targets.append(candidate)
    return targets


def _cp_mv_targets(command: str) -> list[str]:
    """Return the last non-option argument of ``cp`` / ``mv``."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        index = next(
            (i for i, token in enumerate(tokens) if token in {"cp", "mv"}),
            None,
        )
        if index is None:
            continue
        args = [
            token for token in tokens[index + 1:]
            if not token.startswith("-") and token not in _NOISE_TOKENS
        ]
        if args:
            targets.append(args[-1])
    return targets


def _chmod_chown_targets(command: str) -> list[str]:
    """Return the last non-option (file) argument of ``chmod`` / ``chown``."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        index = next(
            (i for i, token in enumerate(tokens) if token in {"chmod", "chown"}),
            None,
        )
        if index is None:
            continue
        args = [
            token for token in tokens[index + 1:]
            if not token.startswith("-") and token not in _NOISE_TOKENS
        ]
        if args:
            targets.append(args[-1])
    return targets


def _launchctl_targets(command: str) -> list[str]:
    """Return the domain/label argument following a ``launchctl`` subcommand."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        index = next(
            (i for i, token in enumerate(tokens) if token == "launchctl"),
            None,
        )
        if index is None or index + 1 >= len(tokens):
            continue
        rest = [
            token for token in tokens[index + 2:]
            if not token.startswith("-") and token not in _NOISE_TOKENS
        ]
        labels = [token for token in rest if "/" in token]
        if labels:
            targets.append(labels[0])
        elif rest:
            targets.append(rest[-1])
    return targets


def _scp_rsync_targets(command: str) -> list[str]:
    """Return the last argument (destination) of ``scp`` / ``rsync``."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        index = next(
            (i for i, token in enumerate(tokens) if token in {"scp", "rsync"}),
            None,
        )
        if index is None:
            continue
        args = [
            token for token in tokens[index + 1:]
            if not token.startswith("-") and token not in _NOISE_TOKENS
        ]
        if args:
            targets.append(args[-1])
    return targets


def _ssh_targets(command: str) -> list[str]:
    """Return the host name immediately following ``ssh``."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        index = next(
            (i for i, token in enumerate(tokens) if token == "ssh"),
            None,
        )
        if index is None:
            continue
        for candidate in tokens[index + 1:]:
            if candidate.startswith("-") or candidate in _NOISE_TOKENS:
                continue
            targets.append(candidate)
            break
    return targets


def _system_path_targets(command: str) -> list[str]:
    """Return sensitive system paths that appear as command tokens."""
    targets: list[str] = []
    for tokens in _iter_segment_tokens(command):
        for token in tokens:
            if token in _HOME_CONFIG_PATHS or token.startswith(_SYSTEM_PATH_PREFIXES):
                targets.append(token)
    return targets


def _extract_targets(command: str) -> list[str]:
    """Extract up to two affected objects, most specific category first."""
    try:
        ordered: list[str] = []
        ordered.extend(_redirect_targets(command))
        ordered.extend(_flag_targets(command, ("-o", "--output")))
        ordered.extend(_rm_targets(command))
        ordered.extend(_cp_mv_targets(command))
        ordered.extend(_chmod_chown_targets(command))
        ordered.extend(_launchctl_targets(command))
        ordered.extend(_scp_rsync_targets(command))
        ordered.extend(_ssh_targets(command))
        ordered.extend(_system_path_targets(command))

        targets: list[str] = []
        for target in ordered:
            cleaned = target.strip().strip("'\"")
            if cleaned and cleaned not in targets:
                targets.append(cleaned)
            if len(targets) == 2:
                break
        return targets
    except Exception:
        return []


def _build_note(hits: list[str], targets: list[str]) -> str:
    """Build the one-line audit summary prepended to the command."""
    shape = hits[0] if hits else "unknown"
    objects = " / ".join(targets) if targets else "未解析到具体对象"
    note = f"# 【自动补注】{shape} | 对象：{objects} | 后果：{_consequence(hits)}"
    if len(note) > 140:
        note = note[:139] + "…"
    return note


def _block_message(hits: list[str], missing: list[str]) -> str:
    """Build the short Chinese retry instruction shown on the approval card."""
    names = "、".join(hits)
    lacking = "、".join(missing)
    return (
        f"这条命令缺少审计摘要，已退回（未执行）。命中形态：{names}\n"
        f"缺：{lacking}\n"
        "\n"
        "请补成三行注释后，原样重发同一条命令（命令本身不要改）：\n"
        "# 【新改动|回滚|只读】用途=做什么\n"
        "# 写入=写到哪（只读写 无）\n"
        "# 失败影响=失败会怎样\n"
        "\n"
        "示例：\n"
        "# 【新改动】用途=重启 Mac-Hub dashboard 加载新版插件\n"
        "# 写入=launchctl gui/501 域\n"
        "# 失败影响=面板短暂中断，自动重连"
    )


def _on_pre_tool_call(
    tool_name: str = "", args: Any = None, **_: Any
) -> Optional[dict[str, Any]]:
    """Block risky terminal commands whose audit note is incomplete."""
    try:
        if _DISABLED or tool_name != "terminal":
            return None
        if not isinstance(args, dict):
            return None

        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return None

        hits = _match_risk(command)
        if not hits:
            return None

        if _DRY_RUN:
            if _ANNOTATE_MODE:
                logger.info("command-note-guard: dry-run annotate %s", ",".join(hits))
            else:
                if _LENIENT_MODE:
                    missing = (
                        []
                        if _first_nonempty_line(command).startswith("#")
                        else ["label"]
                    )
                else:
                    missing = _note_status(command)[1]
                if missing:
                    logger.info(
                        "command-note-guard: dry-run missing=%s hits=%s",
                        ",".join(missing),
                        ",".join(hits),
                    )
            return None

        if _ANNOTATE_MODE:
            # Optional fallback: old behaviour, auto-annotate instead of blocking.
            if _first_nonempty_line(command).startswith("#"):
                return None
            note = _build_note(hits, _extract_targets(command))
            logger.info("command-note-guard: annotated %s", ",".join(hits))
            return {"action": "modify", "args": {**args, "command": note + "\n" + command}}

        if _LENIENT_MODE:
            ok = _first_nonempty_line(command).startswith("#")
            missing = [] if ok else ["label"]
        else:
            ok, missing = _note_status(command)

        if ok:
            return None

        logger.info(
            "command-note-guard: blocked %s missing=%s",
            ",".join(hits),
            ",".join(missing),
        )
        return {"action": "block", "message": _block_message(hits, missing)}
    except Exception:
        # Fail open: a broken guard must never stop normal work.
        return None


def register(ctx) -> None:
    """Register the pre_tool_call guard unless disabled by the environment."""
    if _DISABLED:
        logger.info("command-note-guard: disabled by COMMAND_NOTE_GUARD")
        return
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
