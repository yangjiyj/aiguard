import httpx
import os

BASE = os.getenv("E2E_API_BASE", "http://127.0.0.1:8081")
ADMIN_USER = os.getenv("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("E2E_ADMIN_PASS", "NapiE2E#2026!")


class AdminAPIClient:
    def __init__(self, base=BASE):
        self.base = base
        self.client = httpx.AsyncClient(base_url=base, timeout=10)
        self.token = None

    async def login(self):
        r = await self.client.post(
            "/admin/v1/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
        r.raise_for_status()
        self.token = r.json()["token"]
        self.client.headers["Authorization"] = f"Bearer {self.token}"

    async def get(self, path, **kw):
        return await self.client.get(path, **kw)

    async def post(self, path, **kw):
        return await self.client.post(path, **kw)

    async def put(self, path, **kw):
        return await self.client.put(path, **kw)

    async def patch(self, path, **kw):
        return await self.client.patch(path, **kw)

    async def delete(self, path, **kw):
        return await self.client.delete(path, **kw)

    async def aclose(self):
        await self.client.aclose()
