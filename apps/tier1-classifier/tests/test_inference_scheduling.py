import asyncio
import time
from fastapi.responses import JSONResponse
import app.main as main

class Slow:
    def score(self, text):
        time.sleep(.25)
        return (.1, "benign")

def test_inference_does_not_block_health(monkeypatch):
    monkeypatch.setattr(main.classifier, "get_scorer", lambda: Slow())
    async def run():
        task=asyncio.create_task(main.classify(main.ClassifyRequest(text="normal")))
        await asyncio.sleep(.02)
        assert not task.done()
        assert (await main.health_check())["status"] == "healthy"
        await task
    asyncio.run(run())

def test_inference_deadline_returns_unavailable(monkeypatch):
    monkeypatch.setattr(main.classifier, "get_scorer", lambda: Slow())
    monkeypatch.setenv("TIER1_INFERENCE_TIMEOUT_SECONDS", ".02")
    value=asyncio.run(main.classify(main.ClassifyRequest(text="normal")))
    assert isinstance(value, JSONResponse) and value.status_code == 503
