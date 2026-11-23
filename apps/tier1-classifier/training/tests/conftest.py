"""training 测试夹具：每测一个独立临时 SQLite 路径，互不污染。"""
import os
import tempfile

import pytest


@pytest.fixture()
def tmp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db", prefix="tier1_labels_")
    os.close(fd)
    os.unlink(path)  # 让 LabelStore 自己建库，验证建表逻辑
    yield path
    if os.path.exists(path):
        os.unlink(path)
