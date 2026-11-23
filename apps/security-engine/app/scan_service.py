"""文件扫描服务装配（设计 §4/§6/§10 的组件串接）。

把 ScanStore(临时区) + ScanAdmission(准入) + ScanResultCache(结果缓存) +
FileIDVerdictRegistry(file_id 协议) 装配为进程级单例，供 engine 与 API 共用。

默认所有组件惰性启用：
- ScanStore 需配置 SECURITY_SCAN_STORE_DIR（绝对路径）才启用；未配置时引擎仍可处理
  请求体内的 data_base64（≤2MB 兼容路径），只是不走 object_id 大文件路径。
- 准入/缓存/注册表始终启用（内存结构，零外部依赖）。
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional

from app.file_id_registry import FileIDVerdictRegistry
from app.scan_admission import ScanAdmission
from app.scan_result_cache import ScanResultCache
from app.scan_store import ScanStore

logger = logging.getLogger(__name__)


def _scan_store_dir() -> Optional[str]:
    d = os.getenv("SECURITY_SCAN_STORE_DIR", "").strip()
    if not d or not os.path.isabs(d):
        return None
    return d


class ScanService:
    def __init__(self) -> None:
        self.admission = ScanAdmission()
        self.cache = ScanResultCache()
        self.registry = FileIDVerdictRegistry()
        self._store: Optional[ScanStore] = None
        self._store_lock = threading.Lock()
        self._reaper_started = False

    @property
    def store(self) -> Optional[ScanStore]:
        # 若已注入或已建（测试或正常装配），优先复用，避免重复建。
        with self._store_lock:
            if self._store is not None:
                return self._store
        if _scan_store_dir() is None:
            return None
        with self._store_lock:
            if self._store is None:
                self._store = ScanStore(_scan_store_dir())  # type: ignore[arg-type]
                self._store.ensure_root()
            return self._store

    def has_store(self) -> bool:
        return _scan_store_dir() is not None

    def reap_all(self) -> int:
        """启动与定时清理：惰性装配临时区后删除超时对象。"""
        store = self.store
        if store is None:
            return 0
        try:
            return store.reap_expired()
        except Exception:  # pragma: no cover - 清理失败不影响检测
            logger.warning("scan store reap failed", exc_info=True)
            return 0


# 进程级单例
scan_service = ScanService()
