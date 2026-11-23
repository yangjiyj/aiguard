from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[1]
TRAINING = ROOT / "training"


def test_training_pretrained_loads_are_local_only():
    for name in ("encoder.py", "retrain.py", "embedder_license.py"):
        source = (TRAINING / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "from_pretrained"
        ]
        assert calls, f"{name} has no pretrained load to inspect"
        assert all(
            any(
                keyword.arg == "local_files_only"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in call.keywords
            )
            for call in calls
        ), (
            f"{name} still permits a remote pretrained fallback"
        )
