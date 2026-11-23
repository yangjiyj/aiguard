"""Experimental structural windows. No risk keywords or label-driven selection.

Offsets refer to the supplied inspection view. Each focus keeps adjacent complete
units; unmatched quoting is explicit, never interpreted as a safe verdict.
"""
import re

def contextual_segments(text, *, max_segments=128):
    if max_segments<1:
        raise ValueError("max_segments must be positive")
    pairs={"「":"」","『":"』","“":"”","‘":"’",'"':'"'}
    stack=[]; fence=None; atoms=[]; start=0; offset=0
    for line in text.splitlines(keepends=True):
        stripped=line.lstrip(" ")
        fence_match=re.match(r"([~]{3,}|["+chr(96)+r"]{3,})(.*)",stripped)
        if fence is not None:
            if fence_match:
                marker=fence_match.group(1)
                if marker[0]==fence[0] and len(marker)>=fence[1] and not fence_match.group(2).strip():
                    fence=None
        elif not stack and fence_match:
            marker=fence_match.group(1)
            fence=(marker[0],len(marker))
        else:
            escaped=False
            for char in line:
                if escaped:
                    escaped=False;continue
                if char=="\\":
                    escaped=True;continue
                if stack and char==stack[-1]:
                    stack.pop()
                elif char in pairs:
                    stack.append(pairs[char])
        offset+=len(line)
        if not stack and fence is None:
            atoms.append((start,offset));start=offset
    if start<len(text):
        atoms.append((start,len(text)))
    if not atoms:
        atoms=[(0,len(text))]
    segments=[]
    for index,(focus_start,focus_end) in enumerate(atoms[:max_segments]):
        a=atoms[max(0,index-1)][0]
        b=atoms[min(len(atoms)-1,index+1)][1]
        segments.append({"start":a,"end":b,"focus_start":focus_start,"focus_end":focus_end,"text":text[a:b]})
    complete=len(segments)==len(atoms)
    return {"segments":segments,"complete":complete,"ambiguous_structure":bool(stack or fence),
            "reason":None if complete else "segment_limit"}
