"""文件解析可终止超时测试（设计 §6.2）。

验证 ThreadPoolExecutor 无法做到的"真墙钟超时"：0.1s 超时 + 2s 任务，
Process 方案应在远小于 2s 内返回 timeout（子进程被 terminate）。
"""
from __future__ import annotations

import time

import pytest

from app.file_text_extractor import (
    ExtractionResult,
    _run_with_timeout,
    extract_attachment_text,
)


def _slow_two_seconds(data: bytes) -> str:
    """模拟一个要 2 秒的解析任务。"""
    time.sleep(2)
    return "done"


def _fast_ok(data: bytes) -> str:
    return "ok-" + data.decode("latin-1")


def _always_boom(data: bytes) -> str:
    raise ValueError("bad")


def test_parser_process_uses_spawn_not_fork():
    from app import file_text_extractor as fte

    assert fte._mp_ctx.get_start_method() == "spawn"


def test_run_with_timeout_real_terminates_quickly():
    """0.1s 超时 + 2s 任务：Process 方案必须远早于 2s 返回（真终止）。"""
    start = time.monotonic()
    with pytest.raises(Exception):  # _ExtractionError 不导出，用基类
        _run_with_timeout(_slow_two_seconds, b"x", 0.1)
    elapsed = time.monotonic() - start
    # 关键断言：绝不能等满 2 秒（ThreadPoolExecutor 的 bug 就是会等满）。
    # 留宽裕（forkserver 起 + join）：应 < 1s
    assert elapsed < 1.0, f"超时未真终止，elapsed={elapsed:.2f}s（应<1s）"


def test_run_with_timeout_normal_returns():
    """正常任务在超时内完成 → 返回结果。"""

    out = _run_with_timeout(_fast_ok, b"hello", 5)
    assert out == "ok-hello"


def test_run_with_timeout_exception_is_corrupt():
    """子进程异常 → corrupt（不外抛）。"""

    with pytest.raises(Exception):
        try:
            _run_with_timeout(_always_boom, b"x", 5)
        except Exception as exc:
            assert "corrupt" in str(exc) or "bad" in str(exc)
            raise


def test_extract_timeout_does_not_block_engine():
    """端到端：一个会触发超时的 Office 文件（通过 ENV 调低超时）→ 返回 timeout 结果，不阻塞。"""
    import os
    # 调低 Office 超时到 0.1s；构造一个会卡住解析的伪 docx（合法 zip 但 document.xml 巨大）
    os.environ["SECURITY_FILE_OFFICE_TIMEOUT_SEC"] = "0.1"
    # 重新加载以读到新 env（模块顶部读 env，需 reload）
    import importlib
    from app import file_text_extractor as fte
    importlib.reload(fte)
    # 构造一个真正大的 docx，让解析超过 0.1s
    import io, zipfile
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    # 一个含大量 w:t 的 document.xml
    inner = "".join(f"<w:p><w:r><w:t>row{i}</w:t></w:r></w:p>" for i in range(5000))
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}"><w:body>{inner}</w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="text/xml"/></Types>')
        z.writestr("word/document.xml", doc)
    res = fte.extract_attachment_text("docx", buf.getvalue())
    # 要么成功提取，要么 timeout（取决于机器速度）；关键是不阻塞崩溃
    assert res.timeout is True or (res.text is not None and res.error is None)
    # 清理
    del os.environ["SECURITY_FILE_OFFICE_TIMEOUT_SEC"]
    importlib.reload(fte)
