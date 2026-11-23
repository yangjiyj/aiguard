"""文件内容 DLP 正文提取器（第一期）。

职责：对已通过 file_inspector 格式安全检视的"文本类"附件（txt/csv/json/
docx/pptx/xlsx/文本型 pdf）提取可送检的纯文本正文，交给 engine 现有检测器
（PII/密钥/自定义规则）做内容级 DLP。

设计红线（与 file_inspector 一致）：
- Office 使用 ZIP/XML；PDF 使用锁定 pypdf 字体映射解析；图像使用离线 Tesseract。
  所有遗漏、损坏、预算耗尽均显式报告，不把部分正文当成完整检测。
- 只读取正文相关条目，绝不无界解压：复用 file_inspector 的 ZIP DoS 上限
  （条目数/单条目大小/解压总量/压缩比/嵌套层级）。
- 文件解析有超时保护（Office 10s / PDF 20s，env 可调），超时即返回 timeout，
  由上层按故障策略阻断——绝不拖垮代理主进程或事件循环。
- 提取失败（损坏/加密/超时/越界）返回结构化错误，绝不抛出、绝不静默放行。
- 本模块只产正文文本，不做规则匹配（规则匹配由 engine.check_input 完成）。
"""
from __future__ import annotations

import io
import gzip
import os
import re
import tarfile
import threading
import time
import signal
import xml.etree.ElementTree as ET
import zipfile
import multiprocessing as _mp

# security-engine 本身是多线程服务，fork 可能继承锁的半状态并死锁。所有解析入口与
# 参数均可 pickle，因此固定使用 spawn，让子进程从干净解释器启动。
try:
    _mp_ctx = _mp.get_context("spawn")
except ValueError:  # pragma: no cover - 极少数受限运行时退回默认
    _mp_ctx = _mp.get_context()
from dataclasses import dataclass, field
from typing import Optional
from app.bounded_work import WorkUnavailable, check_work_budget, effective_deadline


# 复用 file_inspector 的 ZIP DoS 上限，保持单一真源（避免漂移）。
from app.file_inspector import (  # noqa: E402 (与 file_inspector 互不环依赖)
    MAX_ZIP_ENTRIES,
    MAX_ZIP_RATIO,
    MAX_ZIP_TOTAL_UNCOMPRESSED,
)

logger_min = __import__("logging").getLogger(__name__)

# —— 单条目 / 正文总量上限（env 可调）——
MAX_ARCHIVE_DEPTH = max(0, int(os.getenv("SECURITY_FILE_ARCHIVE_MAX_DEPTH", "3")))
MAX_PDF_PAGES = max(1, int(os.getenv("SECURITY_FILE_PDF_MAX_PAGES", "100")))
MAX_PARSE_MEMORY_MB = max(128, int(os.getenv("SECURITY_FILE_PARSE_MEMORY_MB", "768")))
MAX_PDF_IMAGES = max(1, int(os.getenv("SECURITY_FILE_PDF_MAX_IMAGES", "100")))
MAX_TEXT_CHARS = _mx = int(os.getenv("SECURITY_FILE_CONTENT_MAX_CHARS", str(2 * 1024 * 1024)))  # 单附件提取正文上限 2MB 文本
MAX_XML_PER_ENTRY = int(os.getenv("SECURITY_FILE_XML_MAX_PER_ENTRY", str(8 * 1024 * 1024)))     # 单 XML 条目 8MB
# 全局并发解析上限（部署硬上限）：每个解析任务起一个子进程，用信号量限制同时在跑的解析进程数，
# 防止突发大量文件拖垮 security-engine。普通文字请求不进解析路径，不受此限。
MAX_CONCURRENT_PARSE = max(1, int(os.getenv("SECURITY_FILE_MAX_CONCURRENT_PARSE", "4")))
MAX_CONCURRENT_OCR = max(1, int(os.getenv("SECURITY_OCR_MAX_CONCURRENT_PARSE", "2")))
_ocr_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_OCR)
_parse_semaphore = threading.Semaphore(MAX_CONCURRENT_PARSE) if MAX_CONCURRENT_PARSE > 0 else None
OFFICE_TIMEOUT_SEC = float(os.getenv("SECURITY_FILE_OFFICE_TIMEOUT_SEC", "10"))
PDF_TIMEOUT_SEC = float(os.getenv("SECURITY_FILE_PDF_TIMEOUT_SEC", "20"))
ARCHIVE_TIMEOUT_SEC = float(os.getenv("SECURITY_FILE_ARCHIVE_TIMEOUT_SEC", "10"))

# XML 命名空间（只取正文相关标签的文本）
_NSMAP = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}

# 文本类附件：可提取正文的类型集合
TEXTUAL_TYPES = {
    "txt", "csv", "json", "md", "yaml", "xml", "docx", "pptx", "xlsx", "pdf",
    "zip", "tar", "gzip",
}


@dataclass
class ExtractionResult:
    """正文提取结果。text 为空且 error/encrypted/timeout 任一为真时表示未成功提取。"""

    text: str = ""
    truncated: bool = False
    error: Optional[str] = None      # corrupt / zip_unsafe / unsupported
    encrypted: bool = False
    timeout: bool = False
    real_type: str = ""
    extracted_chars: int = 0
    # 脱敏证据：只保留条目计数与是否截断，绝不保留正文
    evidence: dict = field(default_factory=dict)
    incomplete_reasons: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not (self.truncated or self.error or self.encrypted or self.timeout or self.incomplete_reasons)


@dataclass
class _ParsedText:
    text: str = ""
    incomplete_reasons: list[str] = field(default_factory=list)


@dataclass
class _ArchiveBudget:
    entries: int = 0
    expanded_bytes: int = 0

    def consume(self, size):
        self.entries += 1
        self.expanded_bytes += size
        if self.entries > MAX_ZIP_ENTRIES or self.expanded_bytes > MAX_ZIP_TOTAL_UNCOMPRESSED:
            raise _ExtractionError("zip_unsafe")


def is_textual(real_type: str) -> bool:
    return real_type in TEXTUAL_TYPES


def _truncate(text: str) -> tuple[str, bool]:
    if len(text) > MAX_TEXT_CHARS:
        return text[:MAX_TEXT_CHARS], True
    return text, False


def _decode_text(data: bytes) -> str:
    """尽力解码纯文本：优先 utf-8，回退 latin-1（绝不抛）。"""
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="ignore")


def _extract_plain(data: bytes) -> str:
    return _decode_text(data)


def _safe_zip(data: bytes) -> Optional[zipfile.ZipFile]:
    """受 DoS 上限约束地打开 ZIP：条目数/解压总量/压缩比越界返回 None。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return None
    try:
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError):
        zf.close()
        return None
    if len(infos) > MAX_ZIP_ENTRIES:
        zf.close()
        return None
    total_uncompressed = 0
    total_compressed = 0
    for info in infos:
        total_uncompressed += info.file_size
        total_compressed += info.compress_size
        if info.file_size > MAX_XML_PER_ENTRY:
            zf.close()
            return None
    if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
        zf.close()
        return None
    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        if ratio > MAX_ZIP_RATIO:
            zf.close()
            return None
    return zf


def _join_texts(parts: list[str]) -> str:
    return "\n".join(p for p in parts if p)


_ARCHIVE_TEXT_EXTENSIONS = {
    ".txt", ".text", ".csv", ".tsv", ".json", ".md", ".markdown", ".yaml",
    ".yml", ".xml", ".html", ".htm", ".log", ".ini", ".conf", ".cfg", ".sql",
}
_ARCHIVE_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar",
    ".gz", ".tgz", ".rar", ".7z", ".mp3", ".wav", ".mp4", ".mov", ".avi",
}


def _looks_like_text(data: bytes) -> bool:
    """在读取上限内判断无扩展名成员是否值得送正文检测。"""
    if not data or b"\x00" in data[:4096]:
        return False
    sample = data[:4096]
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte < 127)
        return printable / max(1, len(sample)) >= 0.85


def _archive_member_kind(name: str) -> str:
    lower = (name or "").lower().split("?", 1)[0]
    for extension in _ARCHIVE_TEXT_EXTENSIONS:
        if lower.endswith(extension):
            return "text"
    for extension in _ARCHIVE_BINARY_EXTENSIONS:
        if lower.endswith(extension):
            return "binary"
    return "unknown"


def _read_bounded(stream, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise _ExtractionError("zip_unsafe")
    return data


def _merge_parts(parts: list[_ParsedText]) -> _ParsedText:
    text, truncated = _truncate(_join_texts([part.text for part in parts]))
    reasons = list(dict.fromkeys(reason for part in parts for reason in part.incomplete_reasons))
    if truncated:
        reasons.append("truncated")
    return _ParsedText(text, list(dict.fromkeys(reasons)))


def _archive_part(name: str, raw: bytes, depth: int, budget: _ArchiveBudget) -> _ParsedText:
    from app.file_inspector import _detect_real_type
    real = _detect_real_type(raw)
    kind = real
    if real == "zip":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = set(zf.namelist())
        if "word/document.xml" in names:
            kind = "docx"
        elif "xl/workbook.xml" in names or "xl/worksheets/sheet1.xml" in names:
            kind = "xlsx"
        elif any(n.startswith("ppt/slides/") for n in names):
            kind = "pptx"
    if real == "unknown" and (_archive_member_kind(name) == "text" or _looks_like_text(raw)):
        kind = "txt"
    if kind in ("zip", "tar", "gzip") and depth > MAX_ARCHIVE_DEPTH:
        return _ParsedText("", ["archive_depth"])
    try:
        if kind in ("zip", "tar", "gzip"):
            parsed = {"zip": _extract_zip_archive, "tar": _extract_tar_archive, "gzip": _extract_gzip_archive}[kind](raw, depth, budget)
        elif kind in ("docx", "xlsx", "pptx"):
            parsed = {"docx": _extract_docx, "xlsx": _extract_xlsx, "pptx": _extract_pptx}[kind](raw)
        elif kind == "pdf":
            parsed = _extract_text_pdf(raw)
        elif kind == "txt":
            parsed = _extract_plain(raw)
        elif kind in ("png", "jpeg", "jpg", "gif", "bmp", "webp", "tiff"):
            from app.ocr import _ocr_with_tesseract
            parsed = _ocr_with_tesseract(raw)
        else:
            return _ParsedText("", ["unsupported_member"])
    except _ExtractionError as exc:
        return _ParsedText("", [str(exc)])
    if isinstance(parsed, str):
        parsed = _ParsedText(parsed)
    # Member names are attacker-controlled metadata, not document text.
    return parsed


def _extract_zip_archive(data: bytes, depth=0, budget=None) -> _ParsedText:
    budget = budget or _ArchiveBudget()
    zf = _safe_zip(data)
    if zf is None:
        raise _ExtractionError("zip_unsafe")
    parts = []
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            budget.consume(info.file_size)
            if info.flag_bits & 1:
                parts.append(_ParsedText("", ["encrypted"]))
                continue
            try:
                raw = zf.read(info)
                parts.append(_archive_part(info.filename, raw, depth + 1, budget))
            except (RuntimeError, OSError, zipfile.BadZipFile, _ExtractionError):
                parts.append(_ParsedText("", ["corrupt_member"]))
    return _merge_parts(parts)


def _extract_tar_archive(data: bytes, depth=0, budget=None) -> _ParsedText:
    budget = budget or _ArchiveBudget()
    parts = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for member in tf:
                budget.consume(member.size)
                if member.size < 0 or member.size > MAX_XML_PER_ENTRY:
                    raise _ExtractionError("zip_unsafe")
                if member.isdir():
                    continue
                if not member.isfile():
                    parts.append(_ParsedText("", ["unsupported_member"]))
                    continue
                stream = tf.extractfile(member)
                if stream is None:
                    raise _ExtractionError("corrupt")
                with stream:
                    raw = _read_bounded(stream, MAX_XML_PER_ENTRY)
                parts.append(_archive_part(member.name, raw, depth + 1, budget))
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise _ExtractionError("corrupt") from exc
    return _merge_parts(parts)


def _extract_gzip_archive(data: bytes, depth=0, budget=None) -> _ParsedText:
    budget = budget or _ArchiveBudget()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            raw = _read_bounded(stream, MAX_ZIP_TOTAL_UNCOMPRESSED)
    except (OSError, EOFError) as exc:
        raise _ExtractionError("corrupt") from exc
    if len(raw) / max(1, len(data)) > MAX_ZIP_RATIO:
        raise _ExtractionError("zip_unsafe")
    budget.consume(len(raw))
    return _archive_part("", raw, depth + 1, budget)


def _extract_docx(data: bytes) -> str:
    zf = _safe_zip(data)
    if zf is None:
        raise _ExtractionError("zip_unsafe")
    texts: list[str] = []
    missing = []
    try:
        # 正文 + 页眉 + 页脚 + 表格都在 word/*.xml，统一取 w:t
        targets = [n for n in zf.namelist() if n.startswith("word/") and n.endswith(".xml")]
        if any("/media/" in name or "/embeddings/" in name for name in zf.namelist()):
            missing.append("office_embedded_content")
        for name in targets:
            try:
                raw = zf.read(name)
            except (RuntimeError, OSError, zipfile.BadZipFile):
                raise _ExtractionError("corrupt_member")
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise _ExtractionError("corrupt_member")
            for t in root.iter("{%s}t" % _NSMAP["w"]):
                if t.text:
                    texts.append(t.text)
    finally:
        zf.close()
    return _ParsedText(_join_texts(texts), missing)


def _extract_pptx(data: bytes) -> str:
    zf = _safe_zip(data)
    if zf is None:
        raise _ExtractionError("zip_unsafe")
    texts: list[str] = []
    missing = []
    try:
        # 正文 slide + 备注 notesSlide，统一取 a:t
        targets = [
            n for n in zf.namelist()
            if (n.startswith("ppt/slides/") or n.startswith("ppt/notesSlides/"))
            and n.endswith(".xml")
        ]
        if any("/media/" in name or "/embeddings/" in name for name in zf.namelist()):
            missing.append("office_embedded_content")
        for name in targets:
            try:
                raw = zf.read(name)
            except (RuntimeError, OSError, zipfile.BadZipFile):
                raise _ExtractionError("corrupt_member")
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise _ExtractionError("corrupt_member")
            for t in root.iter("{%s}t" % _NSMAP["a"]):
                if t.text:
                    texts.append(t.text)
    finally:
        zf.close()
    return _ParsedText(_join_texts(texts), missing)


def _extract_xlsx(data: bytes) -> str:
    zf = _safe_zip(data)
    if zf is None:
        raise _ExtractionError("zip_unsafe")
    try:
        # 共享字符串表 + 所有工作表，统一取 t 标签
        names = zf.namelist()
        # 优先 xl/sharedStrings.xml（含单元格文本字面量）
        try:
            ss_raw = zf.read("xl/sharedStrings.xml")
            ss_root = ET.fromstring(ss_raw)
            shared: list[str] = []
            for si in ss_root.iter("{%s}si" % _NSMAP["s"]):
                buf = "".join(t.text or "" for t in si.iter("{%s}t" % _NSMAP["s"]))
                shared.append(buf)
        except KeyError:
            shared = []
        except (ET.ParseError, RuntimeError, OSError, zipfile.BadZipFile):
            raise _ExtractionError("corrupt_member")
        # 工作表里的 <c t="s"><v>idx</v></c> 引用 shared[idx]；内联字符串 t="str"/t="inlineStr" 直取
        sheet_names = [n for n in names if n.startswith("xl/worksheets/") and n.endswith(".xml")]
        cells: list[str] = []
        for name in sheet_names:
            try:
                raw = zf.read(name)
            except (RuntimeError, OSError, zipfile.BadZipFile):
                raise _ExtractionError("corrupt_member")
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise _ExtractionError("corrupt_member")
            for c in root.iter("{%s}c" % _NSMAP["s"]):
                t_attr = c.get("t", "")
                v = c.find("{%s}v" % _NSMAP["s"])
                if t_attr == "s" and v is not None and v.text and v.text.isdigit():
                    idx = int(v.text)
                    if 0 <= idx < len(shared):
                        cells.append(shared[idx])
                    else:
                        raise _ExtractionError("corrupt_member")
                elif t_attr in ("str", "inlineStr"):
                    if t_attr == "str" and v is not None and v.text:
                        cells.append(v.text)
                    for tn in c.iter("{%s}t" % _NSMAP["s"]):
                        if tn.text:
                            cells.append(tn.text)
                elif v is not None and v.text:
                    cells.append(v.text)
        missing = ["office_embedded_content"] if any("/media/" in name or "/embeddings/" in name for name in names) else []
        return _ParsedText(_join_texts(cells), missing)
    finally:
        zf.close()


class _ExtractionError(Exception):
    """提取过程中的受控失败（zip_unsafe / corrupt / encrypted / unsupported）。"""


# Legacy malformed encrypted PDFs must still be explicitly rejected.
_PDF_ENCRYPT_RE = re.compile(rb"/Encrypt\s+\d+\s+\d+\s+R")


def _extract_text_pdf(data: bytes) -> _ParsedText:
    if _PDF_ENCRYPT_RE.search(data):
        raise _ExtractionError("encrypted")
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise _ExtractionError("pdf_dependency_missing") from exc
    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted:
        raise _ExtractionError("encrypted")
    parts = []
    image_count = 0
    for index, page in enumerate(reader.pages):
        if index >= MAX_PDF_PAGES:
            parts.append(_ParsedText("", ["page_limit"]))
            break
        page_text = page.extract_text() or ""
        parts.append(_ParsedText(page_text))
        image_seen = False
        for img in page.images:
            image_seen = True
            image_count += 1
            if image_count > MAX_PDF_IMAGES:
                parts.append(_ParsedText("", ["image_limit"]))
                break
            from app.ocr import _ocr_with_tesseract
            try:
                recognized = _ocr_with_tesseract(img.data)
                parts.append(_ParsedText(recognized, [] if recognized else ["ocr_no_text"]))
            except _ExtractionError as exc:
                parts.append(_ParsedText("", [str(exc)]))
        if not page_text.strip() and not image_seen:
            parts.append(_ParsedText("", ["pdf_no_text"]))
    return _merge_parts(parts)


def _parse_in_child(func, data: bytes, conn) -> None:
    """子进程入口（top-level，可 pickle，适配 forkserver/spawn start method）。

    跑解析并把结果通过 Pipe 回传：('ok', text) / ('err', reason)。
    任何异常都转成受控结果，绝不外抛（子进程崩溃由父进程 EOFError 兜成 corrupt）。
    """
    try:
        if hasattr(os, "setsid"):
            os.setsid()
        # PDFs/XML/images are untrusted; a subprocess timeout alone does not bound RAM.
        import resource
        cap = MAX_PARSE_MEMORY_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        text = func(data)
        # Bound IPC as well as parsing: never send an unbounded Office body
        # into the parent before its final truncation step.
        if isinstance(text, _ParsedText):
            text.text, truncated = _truncate(text.text)
            if truncated and "truncated" not in text.incomplete_reasons:
                text.incomplete_reasons.append("truncated")
        else:
            text, truncated = _truncate(text)
            if truncated:
                text = _ParsedText(text, ["truncated"])
        conn.send(("ok", text))
    except _ExtractionError as exc:
        conn.send(("err", str(exc)))
    except Exception:
        conn.send(("err", "corrupt"))
    finally:
        conn.close()


def _run_with_timeout(func, data: bytes, timeout: float) -> str:
    """在独立子进程里跑解析，超时即 terminate 子进程（真墙钟上限，不假装）。

    设计§6.2：ThreadPoolExecutor 的 timeout 无法终止线程（实测 0.1s 超时+2s 任务会等满 2s），
    故改用 multiprocessing.Process：超时后 terminate()/kill() 真杀子进程并释放资源。
    每任务一进程：CPU 密集解析天然隔离，单文件崩溃/超时不影响其它；适配 forkserver/spawn。
    """
    if timeout <= 0:
        raise _ExtractionError("timeout")
    deadline = effective_deadline(time.monotonic() + timeout)
    acquired = False
    ocr_acquired = False
    parent_conn = None
    child_conn = None
    proc = None
    try:
        def acquire_capacity(semaphore):
            while True:
                check_work_budget(deadline)
                if semaphore.acquire(timeout=max(0, min(.05, deadline - time.monotonic()))):
                    return True

        # Admission and parsing share the HTTP request's deadline/cancellation.
        check_work_budget(deadline)
        if _parse_semaphore is not None:
            acquired = acquire_capacity(_parse_semaphore)
            if not acquired:
                raise _ExtractionError("timeout")
        if getattr(func, "__name__", "") in {"_extract_text_pdf", "_extract_zip_archive", "_extract_tar_archive", "_extract_gzip_archive", "_ocr_with_tesseract", "_legacy_ocr"}:
            ocr_acquired = acquire_capacity(_ocr_semaphore)
            if not ocr_acquired:
                raise _ExtractionError("timeout")
        check_work_budget(deadline)
        parent_conn, child_conn = _mp_ctx.Pipe(duplex=False)
        proc = _mp_ctx.Process(target=_parse_in_child, args=(func, bytes(data), child_conn), daemon=True)
        proc.start()
        child_conn.close()
        while True:
            check_work_budget(deadline)
            if parent_conn.poll(max(0, min(.05, deadline - time.monotonic()))):
                kind, payload = parent_conn.recv()
                check_work_budget(deadline)
                if kind == "ok":
                    return payload
                raise _ExtractionError(payload)
    except WorkUnavailable as exc:
        raise _ExtractionError(exc.reason) from exc
    except _ExtractionError:
        raise
    except (EOFError, OSError):
        raise _ExtractionError("corrupt")
    finally:
        if proc is not None:
            if proc.is_alive():
                # Kill OCR descendants too, so timeout never leaves an orphaned CLI.
                try:
                    if os.getpgid(proc.pid) == proc.pid:
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.terminate()
                except ProcessLookupError:
                    pass
            proc.join(timeout=1)
            if proc.is_alive():
                proc.kill()
        if parent_conn is not None:
            parent_conn.close()
        if child_conn is not None:
            child_conn.close()
        if ocr_acquired:
            _ocr_semaphore.release()
        if _parse_semaphore is not None and acquired:
            _parse_semaphore.release()


def extract_attachment_text(real_type: str, data: bytes) -> ExtractionResult:
    """提取单个文本类附件的正文。绝不抛异常——失败以 result.error/encrypted/timeout 表达。"""
    res = ExtractionResult(real_type=real_type)
    if not isinstance(data, (bytes, bytearray)) or not data:
        res.error = "empty"
        return res
    if real_type not in TEXTUAL_TYPES:
        res.error = "unsupported"
        return res

    try:
        try:
            check_work_budget()
        except WorkUnavailable as exc:
            raise _ExtractionError(exc.reason) from exc
        if real_type in ("txt", "csv", "json", "md", "yaml", "xml"):
            text = _extract_plain(bytes(data))
        elif real_type == "docx":
            text = _run_with_timeout(_extract_docx, bytes(data), OFFICE_TIMEOUT_SEC)
        elif real_type == "pptx":
            text = _run_with_timeout(_extract_pptx, bytes(data), OFFICE_TIMEOUT_SEC)
        elif real_type == "xlsx":
            text = _run_with_timeout(_extract_xlsx, bytes(data), OFFICE_TIMEOUT_SEC)
        elif real_type == "pdf":
            text = _run_with_timeout(_extract_text_pdf, bytes(data), PDF_TIMEOUT_SEC)
        elif real_type == "zip":
            text = _run_with_timeout(_extract_zip_archive, bytes(data), ARCHIVE_TIMEOUT_SEC)
        elif real_type == "tar":
            text = _run_with_timeout(_extract_tar_archive, bytes(data), ARCHIVE_TIMEOUT_SEC)
        elif real_type == "gzip":
            text = _run_with_timeout(_extract_gzip_archive, bytes(data), ARCHIVE_TIMEOUT_SEC)
        else:
            res.error = "unsupported"
            return res
    except _ExtractionError as exc:
        msg = str(exc)
        if msg == "encrypted":
            res.encrypted = True
        elif msg == "timeout":
            res.timeout = True
        else:
            res.error = msg
        res.evidence = {"failure": msg}
        return res

    if isinstance(text, _ParsedText):
        res.incomplete_reasons = text.incomplete_reasons
        text = text.text
    text, truncated = _truncate(text)
    if truncated and "truncated" not in res.incomplete_reasons:
        res.incomplete_reasons.append("truncated")
    if not text and real_type in {"pdf", "docx", "pptx", "xlsx", "zip", "tar", "gzip"} and not res.incomplete_reasons:
        res.incomplete_reasons.append("no_text")
    res.text = text
    res.truncated = truncated or "truncated" in res.incomplete_reasons
    res.extracted_chars = len(text)
    res.evidence = {"chars": len(text), "truncated": res.truncated, "complete": res.complete, "incomplete_reasons": res.incomplete_reasons}
    return res
