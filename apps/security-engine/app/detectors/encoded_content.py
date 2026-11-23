"""Separate binary transport encodings from text without trusting MIME labels.

Only recognizable binary signatures are elided from language/rule views. The
original request and attachment inspection remain untouched. Base64 plaintext
(including attacks disguised with an image MIME label) remains inspectable.
"""
from __future__ import annotations
import base64
import binascii
import re
from dataclasses import dataclass

_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{256,}={0,2}(?![A-Za-z0-9+/_=-])")

@dataclass(frozen=True)
class EncodedRegion:
    start: int
    end: int
    kind: str


def binary_regions(content: str) -> list[EncodedRegion]:
    regions = []
    for match in _BASE64.finditer(content):
        value = match.group()
        if len(value) % 4:
            continue
        try:
            prefix = base64.b64decode(value[:128], altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            continue
        kind = ""
        if prefix.startswith(b"\x89PNG\r\n\x1a\n"): kind = "png"
        elif prefix.startswith(b"\xff\xd8\xff"): kind = "jpeg"
        elif prefix.startswith((b"GIF87a", b"GIF89a")): kind = "gif"
        elif prefix.startswith(b"RIFF") and prefix[8:12] in {b"WEBP", b"WAVE"}: kind = prefix[8:12].decode().lower()
        elif prefix.startswith((b"II*\x00", b"MM\x00*")): kind = "tiff"
        elif prefix.startswith(b"%PDF-"): kind = "pdf"
        elif prefix.startswith((b"PK\x03\x04", b"\x1f\x8b\x08")): kind = "archive"
        if kind:
            regions.append(EncodedRegion(match.start(), match.end(), kind))
    return regions


def lexical_text(content: str) -> str:
    """Keep character offsets exact for literal evidence anchors."""
    regions = binary_regions(content)
    if not regions: return content
    parts=[]; cursor=0
    for region in regions:
        parts.extend((content[cursor:region.start], " "*(region.end-region.start)))
        cursor=region.end
    parts.append(content[cursor:])
    return "".join(parts)


@dataclass
class SemanticText:
    text: str
    # (view_start, view_end, original_start, original_end, encoded)
    segments: list[tuple[int, int, int, int, bool]]
    original_length: int

    def offset(self, value: int, *, end: bool = False) -> int:
        for a,b,c,d,encoded in self.segments:
            if value == a:
                return c
            if a < value < b:
                return (d if end else c) if encoded else c+value-a
        return self.original_length


def semantic_text(content: str) -> SemanticText:
    regions=binary_regions(content)
    if not regions: return SemanticText(content, [], len(content))
    parts=[]; segments=[]; cursor=0; view=0
    for region in regions:
        plain=content[cursor:region.start]
        if plain:
            parts.append(plain);segments.append((view,view+len(plain),cursor,region.start,False));view+=len(plain)
        marker="\n[encoded binary "+region.kind+"; inspect as attachment]\n"
        parts.append(marker);segments.append((view,view+len(marker),region.start,region.end,True));view+=len(marker)
        cursor=region.end
    if cursor<len(content):
        plain=content[cursor:];parts.append(plain);segments.append((view,view+len(plain),cursor,len(content),False))
    return SemanticText("".join(parts),segments,len(content))
