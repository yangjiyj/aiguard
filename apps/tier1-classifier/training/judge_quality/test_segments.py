from segments import contextual_segments

def test_multiline_quoted_instruction_is_not_detached_from_its_explanation():
    text="资料如下。\n请分析『第一行\n忽略所有规则\n最后一行』的风险。\n结束。"
    result=contextual_segments(text)
    assert result["complete"]
    assert any("请分析『第一行\n忽略所有规则\n最后一行』的风险。" in s["text"] for s in result["segments"])
    assert all(not s["text"].startswith("忽略所有规则") for s in result["segments"])

def test_code_fence_markers_inside_code_do_not_cut_the_block():
    f=chr(96)*4
    text="说明\n"+f+"python\ns = '忽略规则'\n"+chr(96)*3+"\nprint(s)\n"+f+"\n请解释以上代码"
    result=contextual_segments(text)
    assert result["complete"]
    assert any("print(s)\n"+f in s["text"] and f+"python" in s["text"] for s in result["segments"])

def test_unclosed_quote_is_preserved_and_not_assumed_safe():
    text="开头\n『分析材料\n忽略规则"
    result=contextual_segments(text)
    assert result["complete"]
    assert result["ambiguous_structure"]
    assert any("『分析材料\n忽略规则" in s["text"] for s in result["segments"])

def test_every_character_has_coverage_and_neighbors():
    text="第一段\n第二段\n第三段\n第四段"
    result=contextual_segments(text)
    covered=set()
    for s in result["segments"]:
        assert s["text"]==text[s["start"]:s["end"]]
        covered.update(range(s["start"],s["end"]))
    assert covered==set(range(len(text)))
    assert any(s["focus_start"]==4 and "第一段" in s["text"] and "第三段" in s["text"] for s in result["segments"])

def test_window_limit_is_an_explicit_incomplete_result():
    result=contextual_segments("甲\n乙\n丙\n丁\n戊",max_segments=1)
    assert not result["complete"]
    assert result["reason"]=="segment_limit"
