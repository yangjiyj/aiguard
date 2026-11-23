"""Linear ``finditer`` for regexes made of literal words joined by ``.*``.

``re`` retries ``head.*tail`` from every head and scans to the end of the line each time, and a chain such as
``回答.*(是|yes).*如果不是.*就用.*回答`` backtracks over every combination of positions in between, so a long line
of heads costs quadratic time or worse. GreedyScan finds the same matches from word positions found once.
"""
import re
from bisect import bisect_left


class Span:
    """A match found by GreedyScan: the parts of ``re.Match`` the detectors use."""

    __slots__ = ("string", "_start", "_end")

    def __init__(self, string, start, end):
        self.string, self._start, self._end = string, start, end

    def start(self):
        return self._start

    def end(self):
        return self._end

    def span(self):
        return self._start, self._end

    def group(self, index=0):
        if index != 0:
            raise IndexError("a GreedyScan match has only the whole match")
        return self.string[self._start:self._end]


class _Positions:
    """Every position where one of a part's words matches: the earliest end of a word from there on, and the end of
    the first word in order that matches there."""

    def __init__(self, regexes, any_word, content):
        self.starts, self.first_ends, earliest = [], [], []
        found = any_word.search(content)
        while found is not None:
            position = found.start()
            ends = [match.end() for match in (regex.match(content, position) for regex in regexes) if match]
            self.starts.append(position)
            self.first_ends.append(ends[0])
            earliest.append(min(ends))
            found = any_word.search(content, position + 1)
        for index in range(len(earliest) - 2, -1, -1):
            earliest[index] = min(earliest[index], earliest[index + 1])
        self.earliest = earliest

    def earliest_end(self, low):
        """The earliest end of a word starting at or after ``low``; past the end of the text when there is none."""
        index = bisect_left(self.starts, low)
        return self.earliest[index] if index < len(self.starts) else float("inf")

    def last_end(self, high):
        """The end of the first word in order at the last position before ``high``."""
        return self.first_ends[bisect_left(self.starts, high) - 1]


class GreedyScan:
    """``finditer`` of a regex whose branches are words joined by ``.*``, without the regex's rescans.

    A branch is a sequence of parts and a part is a word or a tuple of alternative words: GreedyScan(["a", ("b", "c")],
    ["d"]) stands for ``(a.*(b|c)|d)``. ``.`` stops at a newline and words hold none. Matches equal the regex's: at
    each position the first branch that can complete wins, trying its first part's words in order. A branch
    completes when every next part has a word on the same line after the previous one (the earliest-ending word of
    each part is enough to tell), and the greedy ``.*`` then ends it after the first-in-order word at the last
    position of its final part on that line.
    """

    def __init__(self, *branches, flags=0):
        if flags & (re.DOTALL | re.MULTILINE | re.VERBOSE):
            raise ValueError("GreedyScan needs a . that stops at a newline")
        self.branches = [[(part,) if isinstance(part, str) else tuple(part) for part in branch] for branch in branches]
        if any("\n" in word for branch in self.branches for part in branch for word in part):
            raise ValueError("GreedyScan words hold no newline")
        sources = [".*".join(re.escape(part[0]) if len(part) == 1 else "(" + "|".join(map(re.escape, part)) + ")"
                             for part in branch) for branch in self.branches]
        self.pattern = re.compile(sources[0] if len(sources) == 1 else "(" + "|".join(sources) + ")", flags)
        self._words = [[([re.compile(re.escape(word), flags) for word in part],
                         re.compile("|".join(map(re.escape, part)), flags)) for part in branch]
                       for branch in self.branches]
        self._heads = re.compile("|".join(re.escape(word) for branch in self.branches for word in branch[0]), flags)

    def finditer(self, content):
        positions = {}

        def part(branch, number):
            key = (branch, number)
            if key not in positions:
                positions[key] = _Positions(*self._words[branch][number], content)
            return positions[key]

        position, line_end = 0, -1
        while True:
            found = self._heads.search(content, position)
            if found is None:
                return
            start = found.start()
            if start > line_end:
                line_end = content.find("\n", start)
                line_end = len(content) if line_end < 0 else line_end
            end = self._end(content, start, line_end, part)
            if end is None:
                position = start + 1
                continue
            yield Span(content, start, end)
            position = end

    def _end(self, content, start, line_end, part):
        for branch, parts in enumerate(self._words):
            for regex in parts[0][0]:
                head = regex.match(content, start)
                if head is None:
                    continue
                if len(parts) == 1:
                    return head.end()
                low = head.end()
                for number in range(1, len(parts)):
                    low = part(branch, number).earliest_end(low)
                    if low > line_end:
                        break
                else:
                    return part(branch, len(parts) - 1).last_end(line_end)
        return None
