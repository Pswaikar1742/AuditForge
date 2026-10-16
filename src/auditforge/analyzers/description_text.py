"""Bounded text views with code-point offsets into unchanged source strings.

Only selected presentation characters are folded. This is not a Unicode confusable
or multilingual detector. Offsets are Python string indices, not UTF-8 byte offsets.
"""
from array import array
from dataclasses import dataclass
import re
import unicodedata

MAX_CHARS = 131072
MAX_FIELDS = 512
MAX_NODES = 4096
MAX_DEPTH = 16
MAX_CLUSTER = 32
ZERO_WIDTH = frozenset(('\u200b', '\u2060', '\ufeff'))
VERSION = 'nfkc-cluster-map-v1'
_NEEDS_VIEW = re.compile(r'[^\x20-\x7e]|[*_]| {2,}')


class InspectionLimit(ValueError):
    """Input cannot be fully inspected under the deterministic budget."""


@dataclass
class TextView:
    source: str
    text: str
    starts: array | None = None
    ends: array | None = None

    def original_span(self, start, end):
        if not 0 <= start < end <= len(self.text):
            raise ValueError('invalid normalized span')
        return (start, end) if self.starts is None else (self.starts[start], self.ends[end - 1])

    def mapping(self, start, end):
        """Mapping for a match only; the complete map remains available on the view."""
        return [[i, i + 1] for i in range(start, end)] if self.starts is None else [
            [self.starts[i], self.ends[i]] for i in range(start, end)]


def normalize(source):
    if len(source) > MAX_CHARS:
        raise InspectionLimit('source character limit exceeded')
    if not _NEEDS_VIEW.search(source):
        return TextView(source, source)
    chars, starts, ends = [], array('I'), array('I')
    i = 0
    while i < len(source):
        begin = i
        i += 1
        # Combining sequences and Hangul Jamo composition are normalized as units.
        while i < len(source) and (unicodedata.combining(source[i]) or
                (0x1100 <= ord(source[i]) <= 0x11FF and 0x1100 <= ord(source[i - 1]) <= 0x11FF)):
            if i - begin >= MAX_CLUSTER:
                raise InspectionLimit('combining sequence exceeds normalization budget')
            i += 1
        folded = unicodedata.normalize('NFKC', source[begin:i])
        for ch in folded:
            if ch in ZERO_WIDTH:
                continue
            # Emphasis markers only at token boundaries, not underscores in identifiers.
            if ch in '*_' and (begin == 0 or i == len(source) or
                    not source[begin - 1].isalnum() or not source[i].isalnum()):
                continue
            if ch.isspace():
                ch = ' '
                if chars and chars[-1] == ' ':
                    ends[-1] = i
                    continue
            chars.append(ch)
            starts.append(begin)
            ends.append(i)
            if len(chars) > MAX_CHARS:
                raise InspectionLimit('normalized character limit exceeded')
    return TextView(source, ''.join(chars), starts, ends)


def source_fields(tool):
    """Yield raw string fields including schema keys/values, with bounded traversal.

    Avoid serializing an unbounded schema first. JSON-pointer paths identify raw strings.
    """
    total, fields, nodes = 0, 0, 0
    stack = [('input_schema', tool.input_schema, 0), ('description', tool.description, 0), ('name', tool.name, 0)]
    while stack:
        path, value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InspectionLimit('schema node/depth limit exceeded')
        if isinstance(value, str):
            total += len(value)
            fields += 1
            if total > MAX_CHARS or fields > MAX_FIELDS:
                raise InspectionLimit('aggregate text/field limit exceeded')
            yield path, value
        elif isinstance(value, dict):
            if len(value) + len(stack) > MAX_NODES:
                raise InspectionLimit('schema width limit exceeded')
            for key, item in reversed(tuple(value.items())):
                if not isinstance(key, str) or len(key) > MAX_CHARS:
                    raise InspectionLimit('invalid or oversized schema key')
                pointer = key.replace('~', '~0').replace('/', '~1')
                stack.append((path + '/' + pointer, item, depth + 1))
                stack.append((path + '/' + pointer + '/@key', key, depth + 1))
        elif isinstance(value, list):
            if len(value) + len(stack) > MAX_NODES:
                raise InspectionLimit('schema width limit exceeded')
            for index in range(len(value) - 1, -1, -1):
                stack.append((path + '/' + str(index), value[index], depth + 1))
