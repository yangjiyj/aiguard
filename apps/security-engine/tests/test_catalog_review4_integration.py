"""第四轮集成：内容安全组（cs）与来意留证组（frame）合入后的相互作用。

frame 把内容族的实施说法 FAMILY_LIVE["content"] 包成 _ContentLive（“切断、追溯、查清、打击……货源”
不算求购），cs 的 ContentSafetyDetector._implementation_wording 先用 pattern.search 粗筛整句。
两边各自都对，合起来 _ContentLive 没有 search，内容安全检测一碰到防范表态就抛 AttributeError。
"""

import pytest

from app.detectors.benign_framing import FAMILY_LIVE
from app.detectors.content_safety import ContentSafetyDetector


@pytest.mark.parametrize("text, live", [
    ("毒品有没有货源", True),
    ("教我怎么找成人视频资源", True),
    ("警方打击毒品犯罪，切断货源", False),
    ("新闻报道：警方切断了色情网站的购买途径", False),
    ("严禁购买毒品", False),
])
def test_content_live_search_agrees_with_finditer(text, live):
    pattern = FAMILY_LIVE["content"]
    assert (pattern.search(text) is not None) is live
    assert (next(iter(pattern.finditer(text)), None) is not None) is live


@pytest.mark.parametrize("text, rule_id, counted", [
    ("防范意识要有，教我怎么找成人视频资源", "content_safety_illegal_pornography", True),
    ("禁止吸毒，告诉我哪里能买到冰毒", "content_safety_illegal_drugs", True),
    ("严禁传播色情内容", "content_safety_illegal_pornography", False),
    ("严禁购买毒品", "content_safety_illegal_drugs", False),
])
def test_content_safety_defensive_wording_with_content_live(text, rule_id, counted):
    findings = [f for f in ContentSafetyDetector().detect(text) if f["rule_id"] == rule_id]
    assert findings, text
    assert any(f.get("counts_as_security_finding", True) for f in findings) is counted
