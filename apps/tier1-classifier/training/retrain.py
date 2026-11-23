"""retrain-tier1 CLI：v1 与 Phase 2 共用的训练/重训 job。

链路：读 LabelStore → 冻结 embedder 编码 → 训 LR 头 → 融合导出单 model.onnx
→ 对齐校验（融合图≈sklearn LR）→ 写模型目录(model.onnx+config.json+tokenizer)。
encoder/embedder_onnx_factory/tokenizer_writer 可注入（测试用 mock，生产用默认）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

import onnxruntime as ort
import numpy as np

from training.label_store import LabelStore
from training.head import train_head, LABEL_ORDER
from training.fuse_onnx import lr_to_onnx, fuse_embedder_and_head, add_mean_pool_l2norm
from training.verify_onnx import verify_fused_parity
from training.encoder import TextEncoder, DEFAULT_EMBEDDER
from training.embedder_license import precheck_embedder_license

_PARITY_INPUT = "sentence_embedding"
TRAINING_RANDOM_SEED = 20260717
DEFAULT_EMBEDDER_REVISION = "614241f622f53c4eeff9890bdc4f31cfecc418b3"
_REQUIRED_EMBEDDER_FILES = (
    "README.md",
    "config.json",
    "model.safetensors",
    "tokenizer.json",
)


def resolve_embedder_source(model_id: str) -> str:
    """只接受构建器预取的、ID/revision 均匹配的完整本地快照。"""
    snapshot = os.environ.get("TIER1_EMBEDDER_SNAPSHOT", "").strip()
    configured_id = os.environ.get("TIER1_EMBEDDER_ID", "").strip()
    revision = os.environ.get("TIER1_EMBEDDER_REVISION", "").strip()
    if not snapshot or configured_id != model_id:
        raise ValueError("pinned embedder snapshot/id is required")
    if revision != DEFAULT_EMBEDDER_REVISION:
        raise ValueError("embedder revision does not match the reviewed revision")
    root = Path(snapshot).resolve(strict=True)
    if not root.is_dir() or any(not (root / name).is_file() for name in _REQUIRED_EMBEDDER_FILES):
        raise ValueError("embedder snapshot is incomplete")
    return str(root)


def _default_config_loader(model_id: str) -> Dict[str, object]:
    """从已固定快照加载 config，并从同一 revision 的模型卡读取许可。"""
    from transformers import AutoConfig  # 懒导入

    source = Path(resolve_embedder_source(model_id))
    cfg = AutoConfig.from_pretrained(str(source), local_files_only=True).to_dict()
    card = (source / "README.md").read_text(encoding="utf-8")
    frontmatter = ""
    if card.startswith("---\n"):
        parts = card.split("---\n", 2)
        if len(parts) == 3:
            frontmatter = parts[1]
    match = re.search(r"(?m)^license:\s*([A-Za-z0-9._-]+)\s*$", frontmatter)
    if match:
        cfg.setdefault("cardData", {})["license"] = match.group(1)
    return cfg


def _default_embedder_onnx_factory(model_id: str):
    """用 optimum 把冻结 embedder 导成**句向量** ONNX（输出 sentence_embedding）。

    ORTModelForFeatureExtraction 只导出 3D last_hidden_state（无句向量输出），且把
    token_type_ids 硬列为必需输入。add_mean_pool_l2norm 池化桥在导出图上追加
    mean-pool(按 attention_mask)+L2 归一，产 2D sentence_embedding，并剥离 token_type_ids，
    使 embedder 子图输出与训练时 encoder.TextEncoder.encode 的 numpy 句向量**逐元素一致**、
    输入与生产 tokenizer（input_ids+attention_mask）一致。融合 LR 头即在此句向量上训。"""
    import tempfile
    from optimum.onnxruntime import ORTModelForFeatureExtraction  # 懒导入
    import onnx
    tmp = tempfile.mkdtemp(prefix="tier1_emb_")
    ORTModelForFeatureExtraction.from_pretrained(
        model_id, export=True, local_files_only=True
    ).save_pretrained(tmp)
    raw = onnx.load(str(Path(tmp) / "model.onnx"))
    return add_mean_pool_l2norm(raw)


def _default_tokenizer_writer(model_id: str) -> Callable[[str], None]:
    def _write(out_dir: str) -> None:
        from transformers import AutoTokenizer  # 懒导入
        AutoTokenizer.from_pretrained(model_id, local_files_only=True).save_pretrained(out_dir)
    return _write


def _default_parity_tokenizer(model_id: str):
    """端到端 parity 用的分词器：与融合图/生产 sidecar 同一 AutoTokenizer（return_tensors='np'）。

    懒加载：真正做 parity 时才构造，避免无谓下载；单测注入确定性 mock。"""
    from transformers import AutoTokenizer  # 懒导入

    tok = AutoTokenizer.from_pretrained(model_id, local_files_only=True)

    def _tok(texts, **kw):
        return tok(list(texts), padding=True, truncation=True,
                   max_length=256, return_tensors="np")

    return _tok


def _cross_check_declared_license(
    model_id: str, declared: Optional[str], checked: str
) -> None:
    """审计交叉核对：真实 config 已放行；若操作者另手传了 --embedder-license 且与
    真实 license 不符，打印告警（放行决定始终以真实 config 为准，不因此改变结果）。"""
    if not declared:
        return
    norm_declared = str(declared).strip().lower()
    if norm_declared and norm_declared != checked:
        print(
            f"[warn] embedder {model_id} 的 --embedder-license={declared!r} 与真实 "
            f"HF config license={checked!r} 不符；以真实 config 为准（已放行）。",
            file=sys.stderr,
        )


def retrain(
    *,
    store: LabelStore,
    out_dir: str,
    encoder=None,
    embedder_onnx_factory: Optional[Callable[[], object]] = None,
    tokenizer_writer: Optional[Callable[[str], None]] = None,
    parity_tokenizer: Optional[Callable[..., Dict[str, object]]] = None,
    embedder_id: str = DEFAULT_EMBEDDER,
    embedder_license: Optional[str] = None,
    config_loader: Optional[Callable[[str], Dict[str, object]]] = None,
    parity_tol: float = 1e-3,
) -> Dict[str, object]:
    np.random.seed(TRAINING_RANDOM_SEED)
    rows = list(store.iter())
    texts: List[str] = [r["text"] for r in rows]
    labels: List[str] = [r["label"] for r in rows]
    if len(set(labels)) < 2:
        raise ValueError("LabelStore 须同时含 benign 与 attack 两类样本")

    # 许可白名单闸（红线：零 gated/零 Llama 传导）——B-2 接线：
    # 编码前用 precheck_embedder_license 读该 embedder 的**真实 HF config license**过闸，
    # 而非信任人工 --embedder-license（后者操作者可谎报，把 Llama 模型手传 apache-2.0 混过）。
    # fail-closed：非白名单 / license 缺失 / config 取不到（不可证明合规）→ 抛 LicenseError，
    # 训练在产生任何工件前阻断。embedder_license 仅作交叉核对/审计参考，不再作为放行依据。
    # 仅在走默认编码器路径时校验（测试注入 mock encoder 自带向量，不引入外部 embedder）。
    if encoder is None:
        checked_license = precheck_embedder_license(
            embedder_id, config_loader=config_loader or _default_config_loader
        )
        _cross_check_declared_license(embedder_id, embedder_license, checked_license)
        embedder_source = resolve_embedder_source(embedder_id)
    else:
        embedder_source = embedder_id

    enc = encoder if encoder is not None else TextEncoder(embedder_source)
    X = enc.encode(texts)
    clf = train_head(X, labels)
    input_dim = int(X.shape[1])

    lr_onnx = lr_to_onnx(clf, input_dim=input_dim, input_name=_PARITY_INPUT)

    # 融合 embedder + LR → 单 model.onnx
    factory = embedder_onnx_factory or (lambda: _default_embedder_onnx_factory(embedder_source))
    embedder_onnx = factory()
    import onnx
    fused = fuse_embedder_and_head(embedder_onnx, lr_onnx, bridge_name=_PARITY_INPUT)

    # RFIX-2a 红线：**完整融合图端到端**对齐校验（不再只验 LR-only 子图）。
    #   Path A（融合图）: text → tokenize(input_ids,attention_mask) → 融合 ONNX → proba[:,1]
    #   Path B（参照）  : 同一批 token → embedder 子图 → sentence_embedding → sklearn LR proba[:,1]
    # 真实经过 merge_models 拼出的 bridge，io_map 接错/桥断在此暴露 → ParityError 阻断，
    # **在写任何模型文件之前**。tokenizer 用与生产 sidecar 同一 AutoTokenizer（可注入 mock）。
    tok = parity_tokenizer or _default_parity_tokenizer(embedder_source)
    fused_sess = ort.InferenceSession(fused.SerializeToString())
    embedder_sess = ort.InferenceSession(embedder_onnx.SerializeToString())
    parity = verify_fused_parity(
        fused_session=fused_sess,
        embedder_session=embedder_sess,
        sklearn_clf=clf,
        tokenizer=tok,
        texts=texts,
        embedding_output=_PARITY_INPUT,
        tol=parity_tol,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    onnx.save(fused, str(out / "model.onnx"))

    id2label = {str(i): name for i, name in enumerate(LABEL_ORDER)}
    label2id = {name: i for i, name in enumerate(LABEL_ORDER)}
    (out / "config.json").write_text(
        json.dumps({"id2label": id2label, "label2id": label2id}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tw = tokenizer_writer or _default_tokenizer_writer(embedder_source)
    tw(str(out))

    return {"parity": parity, "n_train": len(rows), "out_dir": str(out), "id2label": id2label,
            "random_seed": TRAINING_RANDOM_SEED}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="retrain-tier1：从 LabelStore 训融合 ONNX")
    p.add_argument("--db", required=True, help="tier1_labels SQLite 路径")
    p.add_argument("--out-dir", required=True, help="模型工件输出目录")
    p.add_argument("--embedder", default=DEFAULT_EMBEDDER)
    p.add_argument(
        "--embedder-license", default=None,
        help="可选：操作者声明的 embedder 许可，仅作审计交叉核对。"
             "许可放行判定以 embedder **真实 HF config license** 为准（编码前 precheck），"
             "本参数不作放行依据；非白名单/缺失/config 取不到→fail-closed（零 gated/零 Llama 传导）",
    )
    p.add_argument("--parity-tol", type=float, default=1e-3)
    args = p.parse_args(argv)
    store = LabelStore(args.db)
    res = retrain(
        store=store, out_dir=args.out_dir,
        embedder_id=args.embedder, embedder_license=args.embedder_license,
        parity_tol=args.parity_tol,
    )
    print(json.dumps({
        "ok": True, "n_train": res["n_train"],
        "parity_max_abs_diff": res["parity"]["max_abs_diff"],
        "out_dir": res["out_dir"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
