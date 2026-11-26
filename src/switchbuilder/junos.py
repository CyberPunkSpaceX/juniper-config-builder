"""A small Junos configuration tree that prints as `set` commands or as the
curly-brace (hierarchical) format.

Statements are added as a path of container names plus one leaf, for example
``cfg.add(("interfaces", "irb", "unit 10", "family inet"), "address 10.0.0.1/24")``.
A leaf can also be a list (``cfg.add_list(path, "members", ["a", "b"])``),
which prints as ``members [ a b ];`` in hierarchical form and as one `set`
line per value.
"""

from __future__ import annotations

import re

_BARE = re.compile(r"^[A-Za-z0-9_.:/+@,*\-]+$")


def q(value) -> str:
    """Quote a value the way Junos does when it has spaces or special characters."""
    text = str(value)
    if text and _BARE.match(text):
        return text
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("\r\n", "\n").replace("\n", "\\n")
    return f'"{text}"'


class _List:
    def __init__(self):
        self.values: list[str] = []


class Config:
    def __init__(self):
        self._items: list[tuple] = []  # ("set", path, leaf) | ("list", path, key, value) | ("comment", text) | ("raw", line)
        self._seen: set = set()

    # ----------------------------------------------------------- building
    def add(self, path: tuple, leaf: str) -> None:
        key = ("set", tuple(path), leaf)
        if key not in self._seen:
            self._seen.add(key)
            self._items.append(key)

    def add_list(self, path: tuple, keyword: str, values) -> None:
        for value in values:
            key = ("list", tuple(path), keyword, str(value))
            if key not in self._seen:
                self._seen.add(key)
                self._items.append(key)

    def comment(self, text: str, gap: bool = True) -> None:
        self._items.append(("comment", text, gap))

    def raw_set(self, line: str) -> None:
        """A line that only makes sense in set form, such as `delete interfaces`."""
        self._items.append(("raw", line))

    # ----------------------------------------------------------- printing
    def to_set(self) -> str:
        out: list[str] = []
        for item in self._items:
            kind = item[0]
            if kind == "comment":
                if item[2] and out and out[-1] != "":
                    out.append("")
                out.append(f"# {item[1]}")
            elif kind == "raw":
                out.append(item[1])
            elif kind == "set":
                out.append("set " + " ".join([*item[1], item[2]]))
            else:
                out.append("set " + " ".join([*item[1], item[2], item[3]]))
        return "\n".join(out).strip() + "\n"

    def tree(self) -> dict:
        root: dict = {}
        for item in self._items:
            if item[0] not in ("set", "list"):
                continue
            node = root
            for part in item[1]:
                child = node.get(part)
                if not isinstance(child, dict):
                    child = {}
                    node[part] = child  # a container replaces a bare leaf of the same name
                node = child
            if item[0] == "set":
                if not isinstance(node.get(item[2]), dict):
                    node[item[2]] = None
            else:
                lst = node.get(item[2])
                if not isinstance(lst, _List):
                    lst = _List()
                    node[item[2]] = lst
                lst.values.append(item[3])
        return root

    def to_hierarchy(self) -> str:
        lines: list[str] = []

        def walk(node: dict, depth: int) -> None:
            pad = "    " * depth
            for key, val in node.items():
                if isinstance(val, dict):
                    lines.append(f"{pad}{key} {{")
                    walk(val, depth + 1)
                    lines.append(f"{pad}}}")
                elif isinstance(val, _List):
                    if len(val.values) == 1:
                        lines.append(f"{pad}{key} {val.values[0]};")
                    else:
                        lines.append(f"{pad}{key} [ {' '.join(val.values)} ];")
                else:
                    lines.append(f"{pad}{key};")

        walk(self.tree(), 0)
        return "\n".join(lines) + "\n"
