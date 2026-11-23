"""受限文件扫描临时区（独立扫描服务核心，设计 §4/§8）。

职责：
- 提供受限临时隔离区，文件以随机不可预测的 object_id 寻址，原文件名绝不参与路径拼接；
- 流式写入：边写边累计 size 与 sha256，不把整个文件 load 进内存；
- TTL 管理：单对象默认 30 分钟；启动清理（孤儿）+ 定时清理共同兜底；
- 路径穿越防护：object_id 只允许 [A-Za-z0-9_-]{32}，且解析后必须仍在根目录内；
- 租户绑定：object_id 关联 tenant_id + request_id，跨租户不可访问。

红线：
- 不接受任意绝对路径或 URL；
- 写入句柄关闭后立即删除（检测完即焚）；
- 磁盘高水位时拒绝新写入（不拖垮普通文字请求）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional, Tuple

OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
DEFAULT_TTL_SECONDS = int(os.getenv("SECURITY_SCAN_STORE_TTL_SECONDS", str(30 * 60)))
# 磁盘高水位（临时区总占用字节上限），默认 2GB；超限拒绝新写入
DEFAULT_HIGH_WATERMARK_BYTES = int(
    os.getenv("SECURITY_SCAN_STORE_HIGH_WATERMARK_MB", str(2 * 1024))
) * 1024 * 1024
# 单文件部署硬上限（不得被租户配置突破）
DEPLOY_MAX_FILE_BYTES = int(os.getenv("SECURITY_SCAN_STORE_DEPLOY_MAX_MB", str(100))) * 1024 * 1024


@dataclass
class ScanObject:
    object_id: str
    tenant_id: str
    request_id: str
    path: str
    size: int
    sha256: str
    created_at: float
    ttl_seconds: int
    content_type: str = ""
    file_name: str = ""  # 仅元数据保留，不参与路径


@dataclass
class _StoreStats:
    total_bytes: int = 0
    object_count: int = 0


class ScanStoreError(Exception):
    """受控错误（quota / watermark / not_found / traversal）。"""


class ScanStore:
    def __init__(
        self,
        root_dir: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        high_watermark_bytes: int = DEFAULT_HIGH_WATERMARK_BYTES,
        deploy_max_file_bytes: int = DEPLOY_MAX_FILE_BYTES,
        now_fn=time.time,
    ) -> None:
        if not root_dir or not os.path.isabs(root_dir):
            raise ScanStoreError("scan store root must be an absolute path")
        self._root = os.path.realpath(root_dir)
        self._ttl = max(1, int(ttl_seconds))
        self._high_water = max(1, int(high_watermark_bytes))
        self._deploy_max = max(1, int(deploy_max_file_bytes))
        self._now = now_fn
        self._lock = threading.Lock()
        self._index: dict[str, ScanObject] = {}
        self._stats = _StoreStats()

    # —— 生命周期 ——
    def ensure_root(self) -> None:
        os.makedirs(self._root, exist_ok=True)
        # 受限目录权限（0o700：仅属主可读写执行）
        try:
            os.chmod(self._root, 0o700)
        except OSError:
            pass

    def reap_expired(self, now: Optional[float] = None) -> int:
        """删除超时对象，返回删除数。进程启动与定时任务共同调用。"""
        now = self._now() if now is None else now
        removed = 0
        with self._lock:
            expired = [oid for oid, obj in self._index.items() if (now - obj.created_at) > obj.ttl_seconds]
        for oid in expired:
            self._delete(oid)
            removed += 1
        # 同时清理磁盘孤儿（重启后内存 index 丢失的残留文件）
        removed += self.reap_disk_orphans(now)
        return removed

    def reap_disk_orphans(self, now: Optional[float] = None) -> int:
        """按共享元数据清理过期对象，不误删其它 worker 的活动对象。

        每个完整对象由 ``.blob`` + ``.meta.json`` 组成。元数据使用墙钟时间，
        因而可被其它进程和重启后的进程理解。缺少元数据的残片只在超过 TTL
        后删除，避免正处于“写完 blob、提交元数据”窗口时被其它 worker 误删。
        """
        if not os.path.isdir(self._root):
            return 0
        now = self._now() if now is None else now
        removed = 0
        try:
            entries = os.listdir(self._root)
        except OSError:
            return 0
        for name in entries:
            if not name.endswith(".meta.json"):
                continue
            oid = name[:-len(".meta.json")]
            if not OBJECT_ID_RE.match(oid):
                continue
            obj = self._load_disk_object(oid)
            if obj is None:
                continue
            if (now - obj.created_at) > obj.ttl_seconds:
                self._delete(oid)
                removed += 1
        # 处理崩溃留下的无元数据 blob；必须经过一个完整 TTL 宽限期。
        for name in entries:
            if not name.endswith(".blob"):
                continue
            oid = name[:-len(".blob")]
            if not OBJECT_ID_RE.match(oid) or os.path.exists(self._meta_path(oid)):
                continue
            path = self._blob_path(oid)
            try:
                stale = (now - os.path.getmtime(path)) > self._ttl
            except OSError:
                stale = False
            if stale and self._safe_remove(path):
                removed += 1
        return removed

    def purge_all(self) -> int:
        """清空全部对象（测试 / 关机清理用）。"""
        oids = set()
        with self._lock:
            oids.update(self._index.keys())
        if os.path.isdir(self._root):
            for name in os.listdir(self._root):
                if name.endswith(".meta.json"):
                    oid = name[:-len(".meta.json")]
                    if OBJECT_ID_RE.match(oid):
                        oids.add(oid)
        for oid in oids:
            self._delete(oid)
        return len(oids)

    # —— 写入（流式）——
    def receive_stream(
        self,
        tenant_id: str,
        request_id: str,
        stream,
        content_type: str = "",
        file_name: str = "",
        max_file_bytes: Optional[int] = None,
    ) -> ScanObject:
        """从可迭代/文件类流式接收：边写边累计 size+sha256，不整体 load 入内存。

        stream: 可迭代的 bytes 块（如 FastAPI Request.stream() 或分块生成器）。
        超过 max_file_bytes（取 min(传入, 部署硬上限)）→ 删除已写部分并 raise。
        """
        if not tenant_id or not request_id:
            raise ScanStoreError("tenant_id and request_id are required")
        self.ensure_root()
        # 高水位前置检查（拒绝新写入，不拖垮普通请求）
        with self._lock:
            if self._disk_usage_bytes() >= self._high_water:
                raise ScanStoreError("disk_high_watermark_reached")
        effective_max = min(max_file_bytes or self._deploy_max, self._deploy_max)
        object_id = secrets.token_urlsafe(24)  # ~32 chars，不可预测
        # object_id 已是 token_urlsafe 安全字符集；双重校验
        if not OBJECT_ID_RE.match(object_id):
            raise ScanStoreError("object_id generation failed")
        target = self._blob_path(object_id)
        digest = hashlib.sha256()
        size = 0
        fh = None
        try:
            # 文件权限 0600（仅属主读写）；用 os.open 控制创建模式，避免 umask 导致过宽
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            fh = os.fdopen(fd, "wb")
            for chunk in stream:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise ScanStoreError("stream chunk must be bytes")
                size += len(chunk)
                if size > effective_max:
                    fh.close()
                    self._safe_remove(target)
                    raise ScanStoreError("file_exceeds_max_bytes")
                digest.update(chunk)
                fh.write(chunk)
            fh.close()
            obj = ScanObject(
                object_id=object_id,
                tenant_id=tenant_id,
                request_id=request_id,
                path=target,
                size=size,
                sha256=digest.hexdigest(),
                created_at=self._now(),
                ttl_seconds=self._ttl,
                content_type=content_type,
                file_name=os.path.basename(file_name or ""),
            )
            self._write_metadata(obj)
            with self._lock:
                self._index[object_id] = obj
                self._stats.total_bytes += size
                self._stats.object_count += 1
            return obj
        except Exception:
            if fh is not None:
                try:
                    fh.close()
                except Exception:
                    pass
            self._safe_remove(target)
            self._safe_remove(self._meta_path(object_id))
            raise

    # —— 读取 ——
    def get(self, object_id: str, tenant_id: str) -> ScanObject:
        obj = self._get_checked(object_id, tenant_id)
        return obj

    def read_bytes(self, object_id: str, tenant_id: str) -> bytes:
        """读取对象字节（检测用）。仅检测路径调用，读完由 consume 删除。"""
        obj = self._get_checked(object_id, tenant_id)
        try:
            with open(obj.path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise ScanStoreError("object_already_removed")

    def consume(self, object_id: str, tenant_id: str) -> None:
        """检测完成后立即删除对象（即焚）。"""
        self._get_checked(object_id, tenant_id)
        self._delete(object_id)

    def stats(self) -> Tuple[int, int]:
        with self._lock:
            return self._stats.object_count, self._stats.total_bytes

    # —— 内部 ——
    def _get_checked(self, object_id: str, tenant_id: str) -> ScanObject:
        if not object_id or not OBJECT_ID_RE.match(object_id):
            raise ScanStoreError("invalid_object_id")
        with self._lock:
            obj = self._index.get(object_id)
        if obj is None:
            obj = self._load_disk_object(object_id)
        if obj is None or not os.path.exists(obj.path):
            raise ScanStoreError("object_not_found")
        if tenant_id != obj.tenant_id:
            # 跨租户不可访问（租户隔离）
            raise ScanStoreError("object_not_found")
        if (self._now() - obj.created_at) > obj.ttl_seconds:
            self._delete(object_id)
            raise ScanStoreError("object_not_found")
        return obj

    def _delete(self, object_id: str) -> None:
        with self._lock:
            obj = self._index.pop(object_id, None)
            if obj is not None:
                self._stats.object_count = max(0, self._stats.object_count - 1)
                self._stats.total_bytes = max(0, self._stats.total_bytes - obj.size)
        self._safe_remove(self._blob_path(object_id))
        self._safe_remove(self._meta_path(object_id))

    def _blob_path(self, object_id: str) -> str:
        path = os.path.realpath(os.path.join(self._root, object_id + ".blob"))
        if not self._is_within(path):
            raise ScanStoreError("path_traversal_blocked")
        return path

    def _meta_path(self, object_id: str) -> str:
        path = os.path.realpath(os.path.join(self._root, object_id + ".meta.json"))
        if not self._is_within(path):
            raise ScanStoreError("path_traversal_blocked")
        return path

    def _write_metadata(self, obj: ScanObject) -> None:
        meta_path = self._meta_path(obj.object_id)
        tmp_path = meta_path + "." + secrets.token_hex(8) + ".tmp"
        payload = asdict(obj)
        # 路径永远由可信 root + object_id 推导，不持久化可被篡改的绝对路径。
        payload.pop("path", None)
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, meta_path)
        finally:
            self._safe_remove(tmp_path)

    def _load_disk_object(self, object_id: str) -> Optional[ScanObject]:
        try:
            with open(self._meta_path(object_id), "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if payload.get("object_id") != object_id:
                return None
            return ScanObject(
                object_id=object_id,
                tenant_id=str(payload["tenant_id"]),
                request_id=str(payload["request_id"]),
                path=self._blob_path(object_id),
                size=int(payload["size"]),
                sha256=str(payload["sha256"]),
                created_at=float(payload["created_at"]),
                ttl_seconds=max(1, int(payload["ttl_seconds"])),
                content_type=str(payload.get("content_type", "")),
                file_name=os.path.basename(str(payload.get("file_name", ""))),
            )
        except (FileNotFoundError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None

    def _disk_usage_bytes(self) -> int:
        if not os.path.isdir(self._root):
            return 0
        total = 0
        try:
            entries = os.listdir(self._root)
        except OSError:
            return 0
        for name in entries:
            if not name.endswith(".blob"):
                continue
            path = os.path.realpath(os.path.join(self._root, name))
            if not self._is_within(path):
                continue
            try:
                total += os.path.getsize(path)
            except OSError:
                pass
        return total

    def _safe_remove(self, path: str) -> bool:
        try:
            os.remove(path)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return False

    def _is_within(self, target: str) -> bool:
        # target 已 realpath；必须在 root 下
        try:
            common = os.path.commonpath([self._root, target])
        except ValueError:
            return False
        return common == self._root
