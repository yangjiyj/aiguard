"""Bounded, non-executing Markdown structure used only as context evidence."""
from dataclasses import dataclass
import re

_FENCE = re.compile(r"^ {0,3}((?:\x60){3,}|~{3,})([^\r\n]*)$")

@dataclass(frozen=True)
class Fence:
    start: int
    end: int
    body_start: int
    body_end: int
    closed: bool

@dataclass(frozen=True)
class CodeContext:
    fences: tuple
    surroundings: tuple | None

    def relation(self,start,end):
        for fence in self.fences:
            if fence.body_start<=start and end<=fence.body_end:
                return "inside"
        if any(start<f.end and end>f.start for f in self.fences):
            return "mixed"
        return "outside"

def code_context(text, *, max_characters=131072, max_surroundings=512):
    if len(text)>max_characters:
        return None
    fences=[];pending=None;offset=0
    for line in text.splitlines(keepends=True):
        match=_FENCE.match(line.rstrip("\r\n"))
        if pending is None:
            if match:
                marker=match[1]
                pending=(offset,offset+len(line),marker[0],len(marker))
        elif match and match[1][0]==pending[2] and len(match[1])>=pending[3] and not match[2].strip():
            fences.append(Fence(pending[0],offset+len(line),pending[1],offset,True))
            pending=None
        offset+=len(line)
    if pending is not None:
        fences.append(Fence(pending[0],len(text),pending[1],len(text),False))
    if not fences:
        return None
    ranges=[];start=0
    for fence in fences:
        if start<fence.start:ranges.append((start,fence.start))
        start=fence.end
    if start<len(text):ranges.append((start,len(text)))
    complete=sum(b-a for a,b in ranges)<=max_surroundings and len(ranges)<=16
    surrounding=tuple(text[a:b] for a,b in ranges) if complete else None
    return CodeContext(tuple(fences),surrounding)
