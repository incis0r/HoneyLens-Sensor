"""Shared property checks for the ICS decoders' tests.

Every decoder test file calls these on its own fixtures, so the Task 1 range
invariants hold for every frame any decoder test produces.
"""

from __future__ import annotations

import random
from collections.abc import Callable

from honeylens.ics.frame import Frame


def assert_frame_sane(f: Frame, raw: bytes) -> None:
    """Fields ascend without overlap and lie inside the input; the tail is honest.

    Defect pinned: a field that overlaps its neighbour or runs past the captured
    bytes paints the wrong bytes on the packet view; a tail without a reason (or a
    reason without a tail) leaves the screen unable to say why bytes are unplaced;
    a sentence mentioning None means a label was formatted from a value never read.
    """
    assert f.raw_len == len(raw)
    end = 0
    for x in f.fields:
        assert x.offset >= end, f"field {x.name} overlaps the previous one"
        assert x.length >= 0
        assert x.offset + x.length <= len(raw), f"field {x.name} runs past the input"
        assert isinstance(x.value, (int, str)) and not isinstance(x.value, bool)
        end = x.offset + x.length
    if f.tail_offset is not None:
        assert end <= f.tail_offset <= len(raw)
        assert f.tail_reason
    else:
        assert f.tail_reason is None
    if f.code is None:
        assert f.sentence is None or "None" not in f.sentence
    if f.sentence is not None:
        assert "None" not in f.sentence


def assert_value_types_are_stable(frames: list[Frame]) -> None:
    """One field name carries one value type across all frames.

    Defect pinned: a decoder returned an int for a 2-byte field and a hex string for
    a 4-byte one under the same field name, decided by size instead of by field.
    """
    seen: dict[str, type] = {}
    for f in frames:
        for x in f.fields:
            assert seen.setdefault(x.name, type(x.value)) is type(x.value), x.name


def fuzz_decoder_directly(
    decode: Callable[[bytes], Frame], seed: int, prefixes: tuple[bytes, ...] = (b"",)
) -> None:
    """Feed random bytes to the module's own decode(), never the containing dispatcher.

    Defect pinned: a no-raise test that went through honeylens.ics.decode() passed
    even if the decoder raised on every input, because the dispatcher swallows it.
    """
    rng = random.Random(seed)
    for _ in range(3000):
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        raw = rng.choice(prefixes) + body
        f = decode(raw)
        assert isinstance(f, Frame)
        assert_frame_sane(f, raw)


def assert_every_prefix_is_sane(decode: Callable[[bytes], Frame], raw: bytes) -> None:
    """Cut a complete frame at every length and call the module's own decode().

    Defect pinned: a frame cut at one particular byte (for example just after a length
    prefix) made a decoder index past the end. Random bytes rarely cut a *valid* frame
    at each boundary, so the boundaries are walked explicitly.
    """
    for n in range(len(raw) + 1):
        f = decode(raw[:n])
        assert isinstance(f, Frame)
        assert_frame_sane(f, raw[:n])
