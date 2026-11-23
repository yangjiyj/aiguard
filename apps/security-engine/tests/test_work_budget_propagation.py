import asyncio
import base64
import threading
import time
import pytest
from app import bounded_work as work
from app import file_text_extractor as extractor
from app import file_content_dlp_bridge as bridge
from app.detectors import semantic as sem


def _slow_parser(data):
    time.sleep(2)
    return "late"


def test_pool_installs_and_restores_worker_budget():
    pool = work.BoundedWorkPool("budget-context", 1, 1)
    deadline = time.monotonic() + 5
    try:
        observed = pool.submit(lambda: work.effective_deadline(time.monotonic() + 100), deadline=deadline).result(1)
        assert observed == deadline
        assert pool._executor.submit(lambda: work.effective_deadline(12345)).result(1) == 12345
    finally:
        pool._executor.shutdown()


def test_parser_uses_remaining_request_budget_and_releases_capacity():
    started = time.monotonic()
    with work.execution_budget(started + 0.15):
        with pytest.raises(extractor._ExtractionError, match="timeout"):
            extractor._run_with_timeout(_slow_parser, b"", 10)
    assert time.monotonic() - started < 0.6
    assert extractor._parse_semaphore.acquire(blocking=False)
    extractor._parse_semaphore.release()


def test_cancelled_request_stops_active_child_and_keeps_slot_until_exit():
    pool = work.BoundedWorkPool("cancel-parser", 1, 1)
    entered = threading.Event()
    def parse():
        entered.set()
        return extractor._run_with_timeout(_slow_parser, b"", 10)
    async def run():
        task = asyncio.create_task(pool.run(parse, deadline=time.monotonic() + 10))
        while not entered.is_set():
            await asyncio.sleep(.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        until = time.monotonic() + .6
        while pool.snapshot()["in_flight"] and time.monotonic() < until:
            await asyncio.sleep(.01)
        assert pool.snapshot()["in_flight"] == 0
    try:
        asyncio.run(run())
    finally:
        pool._executor.shutdown()


def test_expired_request_never_decodes_or_starts_next_attachment(monkeypatch):
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    calls = []
    def parse(kind, data):
        calls.append(data)
        time.sleep(.06)
        return extractor.ExtractionResult(text="safe prefix")
    monkeypatch.setattr(bridge, "extract_attachment_text", parse)
    attachments = [{"file_name": "report.txt", "data_base64": base64.b64encode(str(i).encode()).decode()} for i in range(5)]
    with work.execution_budget(time.monotonic() + .03):
        text, findings = bridge.extract_textual_attachment_content({"attachments": attachments})
    assert len(calls) == 1
    assert "safe prefix" in text
    assert any(f.attachment_index == 1 and "unscanned_attachment_range=1:5" in f.redacted_evidence for f in findings)


def test_semantic_budget_cannot_restart_after_file_stage(monkeypatch):
    detector = sem.SemanticDetector(url="http://example.invalid", model="m", api_key="synthetic", op_timeout=20, total_timeout=20)
    observed = []
    def detect(content, stage, deadline, *args, **kwargs):
        observed.append(deadline)
        return []
    monkeypatch.setattr(detector, "_detect_window", detect)
    deadline = time.monotonic() + 1
    with work.execution_budget(deadline):
        detector.detect("normal", "input")
    assert observed == [deadline]


def test_queued_semantic_call_does_not_start_after_request_cancellation(monkeypatch):
    import concurrent.futures
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    first = executor.submit(release.wait, 2)
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    monkeypatch.setattr(sem, "_CAPACITY", threading.BoundedSemaphore(1))
    cancelled = threading.Event()
    called = []
    try:
        with work.execution_budget(time.monotonic() + 5, cancelled):
            future = sem._submit_bounded(lambda: called.append(True), private_deadline=time.monotonic() + 5)
        cancelled.set()
        release.set()
        first.result(1)
        assert future.result(1) is sem._TIMEOUT
        assert called == []
    finally:
        release.set()
        executor.shutdown()


def test_cancelled_semantic_wait_stops_next_stage_but_keeps_http_slot(monkeypatch):
    import concurrent.futures
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    cancelled = threading.Event()
    monkeypatch.setattr(sem, "_EXECUTOR", executor)
    capacity = threading.BoundedSemaphore(1)
    monkeypatch.setattr(sem, "_CAPACITY", capacity)
    started = threading.Event()
    def slow_http():
        started.set()
        release.wait(2)
        return "result"
    try:
        with work.execution_budget(time.monotonic() + 5, cancelled):
            future = sem._submit_bounded(slow_http, private_deadline=time.monotonic() + 5)
            assert started.wait(1)
            cancelled.set()
            with pytest.raises(work.WorkUnavailable, match="canceled"):
                work.wait_for_work_future(future, time.monotonic() + 5)
        assert not capacity.acquire(blocking=False), "running HTTP prematurely released its own slot"
        release.set()
        assert future.result(1) == "result"
    finally:
        release.set()
        executor.shutdown()


def test_http_timeout_terminates_file_process_and_never_starts_next_file(monkeypatch):
    import httpx
    from app.main import app
    from app.api import check_input
    from tests.test_file_content_dlp import _make_docx
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    monkeypatch.setenv("SECURITY_INPUT_BUDGET_SECONDS", "0.15")
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    pool = work.BoundedWorkPool("http-file-budget", 1, 1)
    monkeypatch.setattr(check_input, "_INPUT_POOL", pool)
    monkeypatch.setattr(extractor, "_extract_docx", _slow_parser)
    processes = []
    original = extractor._mp_ctx.Process
    def record_process(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(extractor._mp_ctx, "Process", record_process)
    encoded = base64.b64encode(_make_docx(["normal"])).decode()
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/check-input/", json={"request_id": "budget-real-process", "content": "normal", "context": {"attachments": [{"file_name": "one.docx", "data_base64": encoded}, {"file_name": "two.docx", "data_base64": encoded}]}})
            assert response.status_code == 503
            assert response.json()["detail"]["inspection_status"] == "incomplete"
            until = time.monotonic() + .8
            while pool.snapshot()["in_flight"] and time.monotonic() < until:
                await asyncio.sleep(.01)
            assert pool.snapshot()["in_flight"] == 0
            assert len(processes) == 1
            assert not processes[0].is_alive()
            response = await client.post("/check-input/", json={"request_id": "next-request", "content": "normal"})
            assert response.status_code == 200
    try:
        asyncio.run(run())
    finally:
        pool._executor.shutdown()
