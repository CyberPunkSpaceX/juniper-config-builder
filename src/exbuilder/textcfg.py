"""Block-style config text, as written by Arista EOS, Cisco IOS-XE and Ruckus FastIron.

A config is a list of top-level lines and blocks (``interface Ethernet1``
followed by indented lines). Adding to a block that already exists appends to
it, so different parts of the generator can fill the same interface.
"""

from __future__ import annotations


class Blocks:
    def __init__(self, indent: str = "   ", end: str = "!"):
        self.indent = indent
        self.end = end          # line between blocks ("!" on EOS/IOS)
        self._items: list = []  # ("comment", text) | ("line", text) | ("block", header)
        self._blocks: dict[str, list[str]] = {}

    def comment(self, text: str) -> None:
        self._items.append(("comment", text))

    def line(self, text: str) -> None:
        self._items.append(("line", text))

    def block(self, header: str, *lines: str) -> list[str]:
        """The body of block ``header`` (made on first use); ``lines`` are added once each."""
        body = self._blocks.get(header)
        if body is None:
            body = self._blocks[header] = []
            self._items.append(("block", header))
        for ln in lines:
            if ln not in body:
                body.append(ln)
        return body

    def has(self, header: str) -> bool:
        return header in self._blocks

    def text(self, comment_prefix: str = "!") -> str:
        out: list[str] = []
        for kind, value in self._items:
            if kind == "comment":
                if out and out[-1] != self.end:
                    out.append(self.end)
                out.append(f"{comment_prefix} {value}")
            elif kind == "line":
                if out and out[-1].startswith(self.indent):
                    out.append(self.end)  # a top-level line right after a block
                out.append(value)
            else:
                if out and out[-1] != self.end:
                    out.append(self.end)
                out.append(value)
                out.extend(self.indent + ln for ln in self._blocks[value])
        if out and out[-1] != self.end:
            out.append(self.end)
        out.append("end")
        return "\n".join(out) + "\n"
