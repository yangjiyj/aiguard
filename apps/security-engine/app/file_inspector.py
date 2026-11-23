"""P2-2 文件格式管控检视器。

职责：对随请求上送的文件/图片附件做"内容真实性 + 外发风险"检视，产出统一的
SecurityFinding（type="file"）。设计红线：

- 只用魔术字节判断真实类型，绝不信任 content_type 与扩展名；
- 证据全程脱敏，只落 sha256 + 安全元数据，绝不回显原始字节；
- 压缩包只读中央目录（infolist），绝不解压，天然防解压炸弹；
- 文件名做路径穿越清洗，只保留 basename；
- 大小 / 数量 / 压缩比 / 解压总量 / 嵌套层级全部有上限，防 DoS；
- 可执行 / 伪装可执行 / 脚本 / 未知类型 / 压缩炸弹的处置读文件策略（2.9.22）：
  allow 不出命中、alert_allow 出 alert、block 出 block，缺省 alert_allow；
  压缩包条目数、解压总量、嵌套数、压缩比读文件策略，环境变量只作缺省；
  普通压缩包 / 类型不符 → audit。

本模块是纯同步叶子模块：输入 context["attachments"]，输出 List[SecurityFinding]。
不做引擎装配（由 engine.check_input 在 Task #7 懒加载接入）。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import io
import logging
import os
import zipfile
from typing import Dict, List, Optional, Tuple

# 叶子模块在顶层导入统一模型；engine 反向懒加载本模块以避免环（与 custom_rules 一致）
from app.detectors.engine import SecurityFinding

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# —— DoS 上限（环境变量只作缺省；压缩包四项可由文件策略覆盖）——
MAX_FILE_ATTACHMENTS = _int_env("SECURITY_FILE_MAX_ATTACHMENTS", 10)
MAX_FILE_BYTES = _int_env("SECURITY_FILE_MAX_BYTES", 20 * 1024 * 1024)        # 单文件 20MB
MAX_ZIP_ENTRIES = _int_env("SECURITY_FILE_ZIP_MAX_ENTRIES", 1000)
MAX_ZIP_TOTAL_UNCOMPRESSED = _int_env("SECURITY_FILE_ZIP_MAX_UNCOMPRESSED", 100 * 1024 * 1024)  # 100MB
MAX_ZIP_RATIO = _int_env("SECURITY_FILE_ZIP_MAX_RATIO", 100)                  # 压缩比上限
MAX_ZIP_NESTED = _int_env("SECURITY_FILE_ZIP_MAX_NESTED", 3)                  # 嵌套压缩包数量上限

# 文件风险类别的处置档位（2.9.22 契约 2.2 节）：允许 / 告警放行 / 禁止。
FILE_RISK_ACTIONS = ("allow", "alert_allow", "block")
DEFAULT_FILE_RISK_ACTION = "alert_allow"
FILE_RISK_ACTION_FIELDS = (
    "executable_action",
    "disguised_executable_action",
    "script_action",
    "unknown_action",
    "zip_bomb_action",
    # 下面两项由网关、独立代理执行；引擎只校验并原样保留。
    "unverified_file_reference_action",
    "file_reference_lookup_failure_action",
)
_FINDING_ACTION = {"alert_allow": "alert", "block": "block"}

# 规则包是否已加载的显式标记：normalize_file_policy（规则包加载）打 True，进程启动时的
# 占位策略为 False。为 False 时文件风险只记录（RULE_PACK_MISSING_ACTION）；手写的策略字典
# 没有这个键，按已加载处理。
RULE_PACK_LOADED_KEY = "rule_pack_loaded"

_EMPTY_RUNTIME_POLICY = {
    RULE_PACK_LOADED_KEY: False,
    "allowed_types": [],
    "blocked_types": [],
    "review_types": [],
    "max_file_mb": 0,
    "max_zip_ratio": 0,
    "max_attachments": 0,
}
_RUNTIME_POLICY = dict(_EMPTY_RUNTIME_POLICY)


def normalize_file_policy(policy: Optional[dict]) -> Dict[str, object]:
    """Purely validate and normalize a rule-pack file policy.

    The control-plane contract emits string arrays and non-negative integers.
    Coercing malformed values here would silently activate a partial policy, so
    callers get ``ValueError`` and can keep their complete last-good rule pack.
    """
    if policy is None:
        policy = {}
    if not isinstance(policy, dict):
        raise ValueError("file_policy must be an object")

    def _list(name: str) -> List[str]:
        value = policy.get(name)
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"file_policy.{name} must be an array")
        normalized: List[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"file_policy.{name} items must be strings")
            item = item.strip().lower()
            if item:
                normalized.append(item)
        return normalized

    def _non_negative_int(name: str) -> int:
        value = policy.get(name)
        if value is None:
            return 0
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"file_policy.{name} must be a non-negative integer")
        return value

    def _strict_bool(name: str) -> bool:
        value = policy.get(name)
        if value is None:
            return False
        if not isinstance(value, bool):
            raise ValueError(f"file_policy.{name} must be a boolean")
        return value

    def _risk_action(name: str) -> str:
        # 旧策略 JSON 没有这些字段：按缺省“告警放行”解释，不报错（客户现场）。
        value = policy.get(name)
        if value is None:
            return DEFAULT_FILE_RISK_ACTION
        if not isinstance(value, str) or value not in FILE_RISK_ACTIONS:
            raise ValueError(f"file_policy.{name} must be one of {', '.join(FILE_RISK_ACTIONS)}")
        return value

    normalized = {
        "allowed_types": _list("allowed_types"),
        "blocked_types": _list("blocked_types"),
        "review_types": _list("review_types"),
        "max_file_mb": _non_negative_int("max_file_mb"),
        "max_zip_ratio": _non_negative_int("max_zip_ratio"),
        "max_attachments": _non_negative_int("max_attachments"),
        "max_zip_entries": _non_negative_int("max_zip_entries"),
        "max_zip_uncompressed_mb": _non_negative_int("max_zip_uncompressed_mb"),
        "max_zip_nested": _non_negative_int("max_zip_nested"),
        "content_dlp_enabled": _strict_bool("content_dlp_enabled"),
        RULE_PACK_LOADED_KEY: True,
    }
    for field in FILE_RISK_ACTION_FIELDS:
        normalized[field] = _risk_action(field)
    return normalized


def snapshot_file_policy() -> Dict[str, object]:
    """Return an isolated snapshot suitable for last-good rollback."""
    return {
        name: list(value) if isinstance(value, list) else value
        for name, value in _RUNTIME_POLICY.items()
    }


def replace_file_policy(policy: dict) -> None:
    """Replace the already validated runtime policy by reference."""
    global _RUNTIME_POLICY
    _RUNTIME_POLICY = {
        name: list(value) if isinstance(value, list) else value
        for name, value in policy.items()
    }


def load_file_policy(policy: Optional[dict]) -> None:
    """Validate and load runtime file policy from a control-plane rule pack."""
    replace_file_policy(normalize_file_policy(policy))


def _policy_view(policy: Optional[Dict[str, object]]) -> Dict[str, object]:
    return _RUNTIME_POLICY if policy is None else policy


def _policy_max_file_bytes(policy: Optional[Dict[str, object]] = None) -> int:
    mb = int(_policy_view(policy).get("max_file_mb") or 0)
    return mb * 1024 * 1024 if mb > 0 else MAX_FILE_BYTES


def _policy_max_zip_ratio(policy: Optional[Dict[str, object]] = None) -> int:
    return int(_policy_view(policy).get("max_zip_ratio") or 0) or MAX_ZIP_RATIO


def _policy_max_attachments(policy: Optional[Dict[str, object]] = None) -> int:
    return int(_policy_view(policy).get("max_attachments") or 0) or MAX_FILE_ATTACHMENTS


def _policy_max_zip_entries(policy: Optional[Dict[str, object]] = None) -> int:
    return int(_policy_view(policy).get("max_zip_entries") or 0) or MAX_ZIP_ENTRIES


def _policy_max_zip_uncompressed(policy: Optional[Dict[str, object]] = None) -> int:
    mb = int(_policy_view(policy).get("max_zip_uncompressed_mb") or 0)
    return mb * 1024 * 1024 if mb > 0 else MAX_ZIP_TOTAL_UNCOMPRESSED


def _policy_max_zip_nested(policy: Optional[Dict[str, object]] = None) -> int:
    return int(_policy_view(policy).get("max_zip_nested") or 0) or MAX_ZIP_NESTED


# 规则包缺失时文件风险只记录（rule_pack_missing_action 只有 record 一个取值，不下发）。
RULE_PACK_MISSING_ACTION = "record"


def _policy_risk_action(policy: Optional[Dict[str, object]], field: str) -> str:
    """文件风险类别的处置。

    规则包加载的策略都经 normalize_file_policy 补齐了处置字段（旧策略缺字段补告警放行）并
    打上 RULE_PACK_LOADED_KEY；占位策略标记为未加载：只记录，不拦、不告警。
    """
    view = _policy_view(policy)
    if view.get(RULE_PACK_LOADED_KEY) is False:
        return RULE_PACK_MISSING_ACTION
    value = view.get(field)
    return value if value in FILE_RISK_ACTIONS else DEFAULT_FILE_RISK_ACTION

_EXECUTABLE = {"pe", "elf", "macho", "macho_fat", "script"}
_ARCHIVE = {"zip", "gzip", "tar", "rar", "7z"}
_SAFE = {"png", "jpeg", "gif", "bmp", "webp", "tiff", "heic", "pdf", "ole"}
# 没有固定魔术字节的文本、源码类型：声明类型在允许名单里时不当未知类型（2.9.22 审查）。
# sh 等脚本不在内：有 #! 时归 file-script，没有时仍按未知类型处置。
_DECLARED_TEXT = {
    "txt", "csv", "json", "md", "yaml", "toml", "ini", "xml", "html", "css", "log", "sql",
    "py", "js", "ts", "go", "java", "c", "cs", "rb", "php", "rs", "kt", "swift", "scala", "vue",
}
# 允许名单里写扩展名或别名时，折算成声明类型的规范 token。
_TOKEN_ALIASES = {
    "yml": "yaml", "markdown": "md", "htm": "html", "jsx": "js", "tsx": "ts",
    "h": "c", "hpp": "c", "cc": "c", "cpp": "c", "kts": "kt",
}
# 脚本（#! 开头）声明成这些文本/源码类型不算伪装：脚本本来就是文本。
_SCRIPT_TEXT_DECLARED = {
    "", "script", "txt", "csv", "md", "json", "xml", "yaml", "toml", "ini", "env", "log", "sql",
    "js", "ts", "py", "java", "go", "rs", "c", "cs", "php", "rb", "svg", "rtf",
}
_NATIVE_EXECUTABLE_DECLARED = {"", "pe", "elf", "script", "macho", "macho_fat"}
_DECLARED_OFFICE = {"docx", "pptx", "xlsx"}

_CT_MAP = {
    "image/png": "png", "image/jpeg": "jpeg", "image/jpg": "jpeg", "image/gif": "gif",
    "image/bmp": "bmp", "image/x-ms-bmp": "bmp", "image/webp": "webp", "image/svg+xml": "svg",
    "image/tiff": "tiff", "image/heic": "heic", "application/pdf": "pdf", "text/plain": "txt",
    "text/csv": "csv", "text/markdown": "md", "application/rtf": "rtf",
    "application/msword": "doc", "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-powerpoint": "ppt", "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.oasis.opendocument.text": "odt", "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp", "application/dicom": "dcm",
    "application/zip": "zip", "application/x-zip-compressed": "zip", "application/gzip": "gzip",
    "application/x-gzip": "gzip", "application/x-7z-compressed": "7z",
    "application/x-rar-compressed": "rar", "application/vnd.rar": "rar",
    "application/x-tar": "tar", "application/x-bzip2": "bz2", "application/x-xz": "xz",
    "application/json": "json", "application/xml": "xml", "text/xml": "xml", "application/x-yaml": "yaml",
    "application/yaml": "yaml", "text/yaml": "yaml", "text/x-yaml": "yaml", "text/html": "html", "text/css": "css",
    "text/x-python": "py", "text/javascript": "js", "application/javascript": "js", "application/x-javascript": "js",
    "text/x-markdown": "md",
    "application/sql": "sql", "application/x-sqlite3": "sqlite",
}
_EXT_MAP = {
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif", "bmp": "bmp", "webp": "webp",
    "svg": "svg", "tif": "tiff", "tiff": "tiff", "heic": "heic", "pdf": "pdf",
    "doc": "doc", "docx": "docx", "xls": "xls", "xlsx": "xlsx", "ppt": "ppt", "pptx": "pptx",
    "rtf": "rtf", "txt": "txt", "csv": "csv", "md": "md", "odt": "odt", "ods": "ods", "odp": "odp",
    "zip": "zip", "gz": "gzip", "tgz": "gzip", "7z": "7z", "rar": "rar", "tar": "tar", "bz2": "bz2", "xz": "xz", "iso": "iso",
    "json": "json", "xml": "xml", "yaml": "yaml", "yml": "yaml", "toml": "toml", "ini": "ini", "env": "env", "log": "log", "sql": "sql",
    "js": "js", "jsx": "js", "ts": "ts", "tsx": "ts", "py": "py", "java": "java", "go": "go", "rs": "rs", "c": "c", "cc": "c", "cpp": "c", "h": "c", "hpp": "c", "cs": "cs", "php": "php", "rb": "rb",
    "markdown": "md", "html": "html", "htm": "html", "css": "css", "kt": "kt", "kts": "kt", "swift": "swift", "scala": "scala", "vue": "vue",
    "dcm": "dcm", "dicom": "dcm", "nii": "nii", "nii.gz": "nii", "dwg": "dwg", "dxf": "dxf", "step": "step", "stp": "step", "stl": "stl", "obj": "obj",
    "sqlite": "sqlite", "db": "db", "mdb": "mdb", "parquet": "parquet", "avro": "avro", "orc": "orc",
    "mp3": "mp3", "wav": "wav", "flac": "flac", "aac": "aac", "ogg": "ogg", "mp4": "mp4", "mov": "mov", "avi": "avi", "mkv": "mkv", "webm": "webm",
    "exe": "pe", "dll": "pe", "msi": "pe", "scr": "pe", "com": "pe", "so": "elf", "dylib": "macho", "app": "macho",
    "sh": "script", "bash": "script", "zsh": "script", "bat": "script", "cmd": "script", "ps1": "script",
    "apk": "apk", "ipa": "ipa", "jar": "jar", "war": "war", "ear": "ear", "class": "class",
}
_ARCHIVE_EXTS = (".zip", ".gz", ".tgz", ".rar", ".7z", ".tar", ".bz2", ".xz")


def _detect_real_type(data: bytes) -> str:
    """仅凭魔术字节判定真实类型，不信任任何外部声明。"""
    if len(data) < 2:
        return "unknown"
    # —— 可执行 / 脚本（高危）——
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if data[:4] == b"\xca\xfe\xba\xbe":
        return "macho_fat"   # Mach-O fat / Java class，统一按可执行风险对待
    if data[:2] == b"#!":
        return "script"
    # —— 压缩包 ——
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    # POSIX/GNU TAR 的 ustar 标识位于 257..261，属于真实格式字节而非声明信息。
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:6] == b"Rar!\x1a\x07":
        return "rar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    # 老 Office（.doc/.xls/.ppt）使用 OLE Compound File，当前无安全正文解析器。
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    # —— 安全类 ——
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:4] in (b"GIF87a"[:4], b"GIF89a"[:4]):
        return "gif"
    if data[:2] == b"BM":
        return "bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if len(data) >= 12 and data[4:8] == b"ftyp" and data[8:12] in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"):
        return "heic"
    if data[:5] == b"%PDF-" or data[:4] == b"%PDF":
        return "pdf"
    return "unknown"


def _classify(real_type: str) -> str:
    if real_type in _EXECUTABLE:
        return "executable"
    if real_type in _ARCHIVE:
        return "archive"
    if real_type in _SAFE:
        return "safe"
    return "unknown"


def _extension_type(file_name: str) -> str:
    """只看扩展名的声明类型 token（content_type 为 text/plain 等泛类型时补充判断）。"""
    lower_name = (file_name or "").lower()
    if lower_name.endswith(".nii.gz"):
        return "nii"
    ext = lower_name.rsplit(".", 1)[-1] if lower_name and "." in lower_name else ""
    return _EXT_MAP.get(ext, "")


def _expand_allowed(allowed: set[str]) -> set[str]:
    return allowed | {_TOKEN_ALIASES[token] for token in allowed if token in _TOKEN_ALIASES}


def _declared_type(content_type: Optional[str], file_name: str) -> str:
    """从 content_type（优先）/ 扩展名推断"声明的"类型 token，用于客户文件策略。"""
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in _CT_MAP:
        return _CT_MAP[ct]
    lower_name = (file_name or "").lower()
    if lower_name.endswith(".nii.gz"):
        return "nii"
    ext = lower_name.rsplit(".", 1)[-1] if lower_name and "." in lower_name else ""
    return _EXT_MAP.get(ext, "")


# 文件类型“禁止”命中的规则编号：前缀加命中的类型（如 file-policy-blocked-type:exe），
# 内容例外按类型放开。只写前缀的旧例外按别名对全部禁止类型生效（见 custom_rules.ExceptionSet）。
BLOCKED_TYPE_RULE_ID = "file-policy-blocked-type"


def blocked_type_rule_id(token: str) -> str:
    return f"{BLOCKED_TYPE_RULE_ID}:{token}"


def _policy_tokens(real_type: str, declared_type: str) -> set[str]:
    tokens = {real_type, _classify(real_type)}
    if declared_type:
        tokens.add(declared_type)
    if real_type in _ARCHIVE:
        tokens.add("archive")
    if real_type in _EXECUTABLE:
        tokens.add("executable")
    return {token for token in tokens if token and token != "binary"}


def _same_family(a: str, b: str) -> bool:
    return a == b


_TEXT_SNIFF_BYTES = 8192


def _decodes_as_text(chunk: bytes, *, final: bool, skip_partial_start: bool) -> bool:
    """chunk 能否按 UTF-8 或 GB18030 解码。

    final=False 时末尾截断在多字节字符中间不算失败；skip_partial_start 时开头最多跳过 3 个字节
    再试（尾部窗口可能从多字节字符中间开始）。
    """
    offsets = range(4) if skip_partial_start else (0,)
    for encoding in ("utf-8", "gb18030"):
        for offset in offsets:
            try:
                codecs.getincrementaldecoder(encoding)().decode(chunk[offset:], final=final)
                return True
            except UnicodeDecodeError:
                continue
    return False


_UTF16_BOMS = ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))


def _looks_like_utf16_text(body: bytes, encoding: str) -> bool:
    """带 BOM 的 UTF-16 文本（Windows 记事本存的“Unicode”）：全文能严格解码且没有 U+0000。"""
    try:
        text = body.decode(encoding)
    except UnicodeDecodeError:
        return False
    return "\x00" not in text


def _looks_like_text(data: bytes) -> bool:
    """声明为文本时的廉价内容核对：全文没有 NUL，且头部、尾部各 8KiB 能按 UTF-8 或 GB18030 解码。

    只看头部会被“前 8KiB 文本、后面二进制”绕过，所以 NUL 扫全文、解码再看尾部。
    以 UTF-16 BOM（FF FE / FE FF）开头的按 UTF-16 解码核对，不套 NUL 检查。
    """
    for bom, encoding in _UTF16_BOMS:
        if data.startswith(bom):
            return _looks_like_utf16_text(data[len(bom):], encoding)
    if b"\x00" in data:
        return False
    head = data[:_TEXT_SNIFF_BYTES]
    if not _decodes_as_text(head, final=len(data) <= len(head), skip_partial_start=False):
        return False
    if len(data) <= _TEXT_SNIFF_BYTES:
        return True
    tail = data[-_TEXT_SNIFF_BYTES:]
    return _decodes_as_text(tail, final=True, skip_partial_start=True)


def _policy_allows_declared_content(real_type: str, declared_types, allowed: set[str], data: bytes) -> bool:
    """Return whether an otherwise unknown/archive payload is explicitly allowed.

    Plain text has no stable magic bytes, while OOXML documents are ZIP containers.
    Their authenticated MIME/filename token therefore remains part of the configured
    policy decision after the raw bytes have been checked for executable signatures.
    ``declared_types`` carries both the MIME token and the extension token, so a
    ``.md`` sent as ``text/plain`` still matches an allowed ``md``. A declared text
    type only counts when the bytes look like text (``_looks_like_text``).
    """
    if isinstance(declared_types, str):
        declared_types = {declared_types}
    allowed = _expand_allowed(allowed)
    for declared_type in declared_types:
        if (declared_type in _DECLARED_TEXT and declared_type in allowed and real_type == "unknown"
                and _looks_like_text(data)):
            return True
        if declared_type in _DECLARED_OFFICE and declared_type in allowed and real_type == "zip":
            return True
    return False


def _sanitize_filename(name: Optional[str]) -> Tuple[str, bool]:
    """返回（清洗后的安全 basename, 是否检出路径穿越特征）。"""
    if not name:
        return ("<noname>", False)
    raw = str(name)
    traversal = False
    if "\x00" in raw:
        traversal = True
    if ".." in raw or raw.startswith("/") or raw.startswith("~") or raw.startswith("\\"):
        traversal = True
    if len(raw) >= 2 and raw[1] == ":":   # Windows 盘符 C:\
        traversal = True
    base = raw.replace("\\", "/").split("/")[-1]
    safe = "".join(ch for ch in base if ch.isprintable() and ch not in "/\\")
    safe = safe.replace("..", "")[:120] or "<noname>"
    return (safe, traversal)


def _sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _evidence(safe_name: str, declared_ct: Optional[str], real_type: str, size: int,
              digest: Optional[str] = None, extra: str = "") -> str:
    """统一脱敏证据：只含哈希 + 安全元数据，绝不含原始字节。"""
    parts = []
    if digest:
        parts.append(f"sha256:{digest}")
    parts.append(f"name={safe_name}")
    parts.append(f"declared={(declared_ct or '-').split(';')[0].strip() or '-'}")
    parts.append(f"real={real_type}")
    parts.append(f"size={size}")
    if extra:
        parts.append(extra)
    return " ".join(parts)


def _inspect_zip(
    data: bytes, policy: Optional[Dict[str, object]] = None
) -> Optional[str]:
    """只读中央目录（绝不解压）判断压缩炸弹特征；命中返回简短原因，否则 None。"""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            max_entries = _policy_max_zip_entries(policy)
            if len(infos) > max_entries:
                return f"entries={len(infos)}>{max_entries}"
            total_unc = 0
            total_cmp = 0
            nested = 0
            for zi in infos:
                total_unc += max(0, zi.file_size)
                total_cmp += max(0, zi.compress_size)
                if zi.filename.lower().endswith(_ARCHIVE_EXTS):
                    nested += 1
            max_uncompressed = _policy_max_zip_uncompressed(policy)
            if total_unc > max_uncompressed:
                return f"uncompressed={total_unc}>{max_uncompressed}"
            if total_cmp > 0:
                ratio = total_unc / total_cmp
                max_ratio = _policy_max_zip_ratio(policy)
                if ratio > max_ratio:
                    return f"ratio={int(ratio)}>{max_ratio}"
            max_nested = _policy_max_zip_nested(policy)
            if nested > max_nested:
                return f"nested={nested}>{max_nested}"
        return None
    except zipfile.BadZipFile:
        return None
    except Exception as exc:  # pragma: no cover - 防御性兜底
        logger.warning("zip inspect failed: %s", exc)
        return None


def _risk_finding(policy: Optional[Dict[str, object]], field: str, findings: List[SecurityFinding],
                  category: str, severity: str, rule_id: str, rule_name: str,
                  preview: str, location: str, evidence: str, confidence: float) -> None:
    """按文件策略的处置档位追加一条风险命中；allow 不出命中。"""
    configured = _policy_risk_action(policy, field)
    if configured == "allow":
        return
    if configured == RULE_PACK_MISSING_ACTION:
        finding = _finding(category, severity, "allow", rule_id, rule_name,
                           preview, location, evidence, confidence)
        finding.counts_as_security_finding = False
        finding.evidence_reason = "留证原因：规则包未加载，文件风险只记录"
        finding.triage = {**finding.triage, "disposition": "observation",
                          "disposition_reason": "rule_pack_missing"}
        findings.append(finding)
        return
    action = _FINDING_ACTION[configured]
    if category == "file_unknown_type" and action == "block":
        # 未知类型平时 0.4 置信度只留证；管理员显式选“禁止”是确定的策略结论，
        # 不能被置信度门控悄悄压成 audit。
        confidence = max(confidence, 0.9)
    findings.append(_finding(category, severity, action, rule_id, rule_name,
                             preview, location, evidence, confidence))


def _finding(category: str, severity: str, action: str, rule_id: str, rule_name: str,
             preview: str, location: str, evidence: str, confidence: float) -> SecurityFinding:
    return SecurityFinding(
        type="file",
        category=category,
        counts_as_security_finding=category != "file_unknown_type",
        evidence_kind="runtime" if category == "file_unknown_type" else "literal",
        evidence_reason="文件类型无法检视，按文件策略保护；不是已确认恶意文件" if category == "file_unknown_type" else "",
        severity=severity,
        matched_text_preview=preview,
        rule_id=rule_id,
        confidence=confidence,
        rule_name=rule_name,
        rule_type="file_fingerprint",
        action=action,
        matched_location=location,
        redacted_evidence=evidence,
    )


def _inspect_one(
    idx: int,
    att: dict,
    policy: Optional[Dict[str, object]] = None,
) -> List[SecurityFinding]:
    if not isinstance(att, dict):
        return []
    declared_ct = att.get("content_type")
    raw_name = att.get("file_name") or att.get("field_name") or ""
    safe_name, traversal = _sanitize_filename(raw_name)
    location = f"attachment[{idx}]:{safe_name}"
    b64 = att.get("data_base64") or ""

    findings: List[SecurityFinding] = []
    effective_policy = _policy_view(policy)
    blocked = set(effective_policy.get("blocked_types") or [])
    review = set(effective_policy.get("review_types") or [])
    allowed = set(effective_policy.get("allowed_types") or [])
    declared_tok = _declared_type(declared_ct, safe_name)

    # 路径穿越：独立判定，即便文件本身安全也要审计（始终落清洗后的名字）
    if traversal:
        findings.append(_finding(
            "file_path_traversal", "medium", "alert",
            "file-path-traversal", "文件名路径穿越清洗",
            f"文件名疑似路径穿越，已清洗为 {safe_name}",
            location,
            _evidence(safe_name, declared_ct, "n/a", 0, extra="traversal=stripped"),
            0.9,
        ))

    if not b64:
        # 客户端可能已在本地解析正文，只把可信附件块中的 filename/MIME
        # 留给网关。没有原始字节时不能做魔术字节校验，但显式配置的
        # blocked_types 仍应按声明扩展名执行；普通文本里的 .pdf 不会走到这里。
        if declared_tok and declared_tok in blocked:
            findings.append(_finding(
                "file_policy_blocked_type", "high", "block",
                blocked_type_rule_id(declared_tok), "文件类型策略阻断",
                f"文件类型 {declared_tok} 命中文件管控阻断策略",
                location,
                _evidence(safe_name, declared_ct, "unavailable", 0, extra=f"declared_token={declared_tok} policy=blocked evidence=metadata_only"),
                0.75,
            ))
        return findings

    # 估算大小，超限则不解码、不深度解析（防 DoS）
    est = (len(b64) * 3) // 4
    max_file_bytes = _policy_max_file_bytes(policy)
    if est > max_file_bytes:
        findings.append(_finding(
            "file_oversized", "medium", "audit",
            "file-oversized", "超大文件外发审计",
            f"文件超过大小上限，跳过深度解析（约 {est} 字节）",
            location,
            _evidence(safe_name, declared_ct, "n/a", est, extra=f"limit={max_file_bytes}"),
            0.5,
        ))
        return findings

    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        logger.info("attachment[%s] base64 decode failed, skipped", idx)
        return findings

    if len(data) > max_file_bytes:
        findings.append(_finding(
            "file_oversized", "medium", "audit",
            "file-oversized", "超大文件外发审计",
            "文件超过大小上限，跳过深度解析",
            location,
            _evidence(safe_name, declared_ct, "n/a", len(data), extra=f"limit={max_file_bytes}"),
            0.5,
        ))
        return findings

    real = _detect_real_type(data)
    rclass = _classify(real)
    declared_tok = _declared_type(declared_ct, safe_name)
    digest = _sha16(data)


    policy_tokens = _policy_tokens(real, declared_tok)
    display_type = declared_tok or real
    blocked_hits = sorted(policy_tokens & blocked)
    if blocked_hits:
        # 每个命中的禁止类型各出一条命中，规则编号带类型，例外按类型放开。
        for token in blocked_hits:
            findings.append(_finding(
                "file_policy_blocked_type", "high", "block",
                blocked_type_rule_id(token), "文件类型策略阻断",
                f"文件类型 {display_type} 命中文件管控阻断策略",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest, extra=f"declared_token={declared_tok or '-'} policy=blocked"),
                0.9,
            ))
        return findings
    extension_tok = _extension_type(safe_name)
    if declared_tok and declared_tok not in _DECLARED_TEXT:
        # MIME 声明了具体的非文本类型、扩展名却是文本类：两者冲突，扩展名不参与放开判断，
        # 按未知类型走（复审补充）。MIME 未识别时 declared_tok 本来就取自扩展名。
        extension_tok = ""
    if allowed and not ((policy_tokens | {extension_tok}) & _expand_allowed(allowed)):
        findings.append(_finding(
            "file_policy_not_allowed", "medium", "audit",
            "file-policy-not-allowed", "文件类型不在允许范围",
            f"文件类型 {display_type} 不在允许上传范围",
            location,
            _evidence(safe_name, declared_ct, real, len(data), digest=digest, extra=f"declared_token={declared_tok or '-'} policy=not_allowed"),
            0.75,
        ))
    if policy_tokens & review:
        findings.append(_finding(
            "file_policy_review_type", "medium", "audit",
            "file-policy-review-type", "文件类型需复核",
            f"文件类型 {display_type} 命中文件管控复核策略",
            location,
            _evidence(safe_name, declared_ct, real, len(data), digest=digest, extra=f"declared_token={declared_tok or '-'} policy=review"),
            0.7,
        ))

    explicitly_allowed_declared_content = _policy_allows_declared_content(
        real, {declared_tok, extension_tok}, allowed, data
    )

    if rclass == "executable":
        if real == "script":
            disguised = declared_tok not in _SCRIPT_TEXT_DECLARED
        else:
            disguised = declared_tok not in _NATIVE_EXECUTABLE_DECLARED
        if disguised:
            _risk_finding(
                policy, "disguised_executable_action", findings,
                "file_disguised_executable", "critical",
                "file-disguised-exec", "伪装可执行文件外发",
                f"声明 {declared_ct} 实为可执行文件({real})，疑似伪装外发",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest, extra="disguised=1"),
                0.99,
            )
        elif real == "script":
            _risk_finding(
                policy, "script_action", findings,
                "file_script", "high",
                "file-script", "脚本文件外发",
                "检出脚本文件外发",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest),
                0.99,
            )
        else:
            _risk_finding(
                policy, "executable_action", findings,
                "file_executable", "high",
                "file-executable", "可执行文件外发",
                f"检出可执行文件({real})外发",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest),
                0.99,
            )
    elif rclass == "archive":
        bomb = _inspect_zip(data, policy) if real == "zip" else None
        if bomb:
            _risk_finding(
                policy, "zip_bomb_action", findings,
                "file_zip_bomb", "high",
                "file-zip-bomb", "压缩炸弹外发",
                "压缩包疑似解压炸弹",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest, extra=bomb),
                0.95,
            )
        elif not explicitly_allowed_declared_content:
            findings.append(_finding(
                "file_archive", "medium", "audit",
                "file-archive", "压缩包外发审计",
                f"压缩包({real})外发，建议审计",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest),
                0.6,
            ))
    elif rclass == "safe":
        if declared_tok and declared_tok != real and not _same_family(declared_tok, real):
            findings.append(_finding(
                "file_type_mismatch", "medium", "audit",
                "file-type-mismatch", "文件类型不符外发审计",
                f"声明 {declared_ct} 实为 {real}，类型不符",
                location,
                _evidence(safe_name, declared_ct, real, len(data), digest=digest),
                0.7,
            ))
        # 否则安全类且类型相符 → 允许，不产噪
    elif not explicitly_allowed_declared_content:  # unknown
        _risk_finding(
            policy, "unknown_action", findings,
            "file_unknown_type", "medium",
            "file-unknown", "未知类型文件外发",
            "未能识别的文件类型，无法完成安全检视",
            location,
            _evidence(safe_name, declared_ct, real, len(data), digest=digest),
            0.4,
        )

    return findings


def inspect_attachments(
    context: Optional[dict],
    policy: Optional[Dict[str, object]] = None,
) -> List[SecurityFinding]:
    """对 context["attachments"] 做文件格式管控检视，返回统一 SecurityFinding 列表。"""
    if not context or not isinstance(context, dict):
        return []
    attachments = context.get("attachments")
    if not isinstance(attachments, list) or not attachments:
        return []

    findings: List[SecurityFinding] = []
    for idx, att in enumerate(attachments[:_policy_max_attachments(policy)]):
        try:
            attachment_findings = _inspect_one(idx, att, policy)
            for finding in attachment_findings:
                finding.attachment_index = idx
            findings.extend(attachment_findings)
        except Exception as exc:  # pragma: no cover - 单附件异常不应拖垮整体
            logger.warning("attachment[%s] inspect error: %s", idx, exc)
    return findings
