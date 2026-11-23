from app.detectors.text_structure import code_context

def test_preserves_fence_length_and_full_surrounding_instructions():
    f=chr(96)*4
    text="请解释代码，不执行。\n"+f+"python\n"+chr(96)*3+"\nprint(1)\n"+f+"\n请指出错误。"
    ctx=code_context(text)
    assert len(ctx.fences)==1 and ctx.fences[0].closed
    assert ctx.surroundings==("请解释代码，不执行。\n","请指出错误。")
    pos=text.index("print")
    assert ctx.relation(pos,pos+8)=="inside"

def test_unclosed_fence_is_explicit():
    text="分析代码\n"+chr(96)*3+"python\nprint(1)"
    ctx=code_context(text)
    assert not ctx.fences[0].closed

def test_long_surroundings_are_not_silently_truncated():
    text="x"*600+"\n"+chr(96)*3+"\ncode\n"+chr(96)*3
    ctx=code_context(text,max_surroundings=100)
    assert ctx.surroundings is None

def test_indented_fence_like_data_does_not_close_a_block():
    f=chr(96)*3
    text=f+"python\n    "+f+"\nprint(1)\n"+f
    ctx=code_context(text)
    assert ctx.fences[0].body_end==text.rfind(f)
