import sys
import os
import pytest

# Ensure lib/ is importable when running pytest from tests/e2e/
sys.path.insert(0, os.path.dirname(__file__))

from lib.api_client import AdminAPIClient
from lib.browser import BrowserSession
from lib.fixtures import ensure_test_tenant
from lib.cleanup import cleanup_test_tenant


@pytest.fixture(scope="session", autouse=True)
def test_tenant():
    ensure_test_tenant()
    yield
    cleanup_test_tenant()


@pytest.fixture
async def admin_api():
    c = AdminAPIClient()
    await c.login()
    yield c
    await c.aclose()


@pytest.fixture
async def browser():
    b = BrowserSession()
    await b.start()
    yield b
    await b.stop()
