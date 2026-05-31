"""Shared helpers for agent-forge tooling (stdlib only).

Contains:
  * a small, dependency-free YAML loader for the controlled subset this repo
    uses (frontmatter, manifest.yaml, catalog.yaml);
  * a YAML emitter for that same subset;
  * frontmatter parsing;
  * registry walking + canonical data models.

The YAML subset supported: nested mappings (indentation, 2 spaces), block
sequences ("- "), inline flow sequences ("[a, b]"), scalars (str/int/float/
bool/null), and "#" comments. This is intentionally limited — we own every
YAML file in the repo, so we do not need a general parser, and a tiny parser
is far easier to audit than a vendored dependency.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PERMISSIVE_LICENSES = {
    "MIT", "APACHE-2.0", "APACHE2", "BSD", "BSD-2-CLAUSE", "BSD-3-CLAUSE",
    "ISC", "CC0", "CC0-1.0", "CC-BY", "CC-BY-4.0", "UNLICENSE", "0BSD",
}


def is_permissive(license_str: str | None) -> bool:
    if not license_str:
        return False
    return license_str.strip().upper() in PERMISSIVE_LICENSES


# --------------------------------------------------------------------------- #
# Minimal YAML loader
# --------------------------------------------------------------------------- #

def _scalar(token: str):
    t = token.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
        try:
            return json.loads(t)  # honor JSON escape sequences
        except ValueError:
            return t[1:-1]
    if len(t) >= 2 and t[0] == "'" and t[-1] == "'":
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    if t[0] == "[" and t[-1] == "]":
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in _split_flow(inner)]
    if t[0] == "{" and t[-1] == "}":
        inner = t[1:-1].strip()
        d = {}
        for part in _split_flow(inner):
            if not part.strip():
                continue
            k, _, v = part.partition(":")
            d[k.strip()] = _scalar(v.strip())
        return d
    return t


def _split_flow(s: str) -> list[str]:
    out, depth, buf = [], 0, []
    q = None
    for ch in s:
        if q:
            buf.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def _strip_comment(line: str) -> str:
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def load_yaml(text: str):
    raw_lines = text.splitlines()
    lines: list[tuple[int, str]] = []
    for ln in raw_lines:
        stripped = _strip_comment(ln).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))

    pos = 0

    def parse_block(min_indent: int):
        nonlocal pos
        if pos >= len(lines):
            return None
        indent, content = lines[pos]
        if content.startswith("- "):
            return parse_seq(indent)
        return parse_map(indent)

    def parse_seq(indent: int):
        nonlocal pos
        seq = []
        while pos < len(lines):
            cur_indent, content = lines[pos]
            if cur_indent < indent or not content.startswith("- "):
                break
            item = content[2:].strip()
            if item and item[0] in "{[":
                # inline flow mapping/sequence on the "- {..}" / "- [..]" line
                seq.append(_scalar(item))
                pos += 1
            elif ":" in item and not (item[0] in "\"'"):
                # inline mapping start on the "- key: value" line
                lines[pos] = (cur_indent + 2, item)
                seq.append(parse_map(cur_indent + 2))
            elif item == "":
                pos += 1
                seq.append(parse_block(cur_indent + 1))
            else:
                seq.append(_scalar(item))
                pos += 1
        return seq

    def parse_map(indent: int):
        nonlocal pos
        mapping = {}
        while pos < len(lines):
            cur_indent, content = lines[pos]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                break
            if content.startswith("- "):
                break
            if ":" not in content:
                pos += 1
                continue
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val and val[0] in "|>":
                # Block scalar (|, |-, >, >-, etc). Our preprocessing already
                # dropped blank lines and indentation, so we join the captured
                # lines: folded (>) with spaces, literal (|) with newlines.
                folded = val[0] == ">"
                chunk = []
                while pos < len(lines) and lines[pos][0] > indent:
                    chunk.append(lines[pos][1])
                    pos += 1
                mapping[key] = (" " if folded else "\n").join(chunk)
            elif val == "":
                # nested block (map or seq) or empty
                if pos < len(lines) and lines[pos][0] > indent:
                    mapping[key] = parse_block(indent + 1)
                elif pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
                    mapping[key] = parse_seq(indent)
                else:
                    mapping[key] = None
            else:
                mapping[key] = _scalar(val)
        return mapping

    result = parse_block(0)
    return result if result is not None else {}


# --------------------------------------------------------------------------- #
# Minimal YAML emitter (for catalog.yaml / lock-adjacent human files)
# --------------------------------------------------------------------------- #

def _emit_scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or any(c in s for c in ":#[]{}\n\"'") or s != s.strip():
        return json.dumps(s, ensure_ascii=False)
    return s


def dump_yaml(data, indent: int = 0) -> str:
    pad = "  " * indent
    out: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{k}:")
                out.append(dump_yaml(v, indent + 1))
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                out.append(f"{pad}{k}: {_emit_scalar(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                inner = dump_yaml(item, indent + 1)
                inner = inner[len(pad) + 2:] if inner.startswith(pad + "  ") else inner.lstrip()
                out.append(f"{pad}- {inner.lstrip()}")
            elif isinstance(item, list):
                out.append(f"{pad}-")
                out.append(dump_yaml(item, indent + 1))
            else:
                out.append(f"{pad}- {_emit_scalar(item)}")
    else:
        out.append(f"{pad}{_emit_scalar(data)}")
    return "\n".join(x for x in out if x != "")


# --------------------------------------------------------------------------- #
# Frontmatter
# --------------------------------------------------------------------------- #

def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body). Empty dict if no frontmatter."""
    if not text.startswith("---"):
        return {}, text
    lines = text.split("\n")
    if lines[0].strip() != "---":
        return {}, text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            fm = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1:])
            data = load_yaml(fm) if fm.strip() else {}
            return (data if isinstance(data, dict) else {}), body
    return {}, text


def build_frontmatter(data: dict) -> str:
    return "---\n" + dump_yaml(data) + "\n---\n"


# --------------------------------------------------------------------------- #
# Canonical models + registry walk
# --------------------------------------------------------------------------- #

@dataclass
class Item:
    kind: str           # "agent" | "skill"
    id: str             # unique slug
    name: str
    description: str
    path: Path          # agent.md file, or skill dir
    domain: str = ""
    tags: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    model: str = ""
    source_repo: str = ""
    source_commit: str = ""
    license: str = ""
    body: str = ""


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def load_registry(root: Path) -> list[Item]:
    items: list[Item] = []
    agents_root = root / "agents"
    if agents_root.is_dir():
        for af in sorted(agents_root.rglob("agent.md")):
            fm, body = parse_frontmatter(af.read_text(encoding="utf-8"))
            domain = af.relative_to(agents_root).parts[0]
            name = str(fm.get("name") or af.parent.name)
            src = fm.get("source") or {}
            items.append(Item(
                kind="agent", id=f"agent/{domain}/{af.parent.name}",
                name=name, description=str(fm.get("description", "")),
                path=af, domain=str(fm.get("domain", domain)),
                tags=_as_list(fm.get("tags")), tools=_as_list(fm.get("tools")),
                model=str(fm.get("model", "") or ""),
                source_repo=str((src or {}).get("repo", "")),
                source_commit=str((src or {}).get("commit", "")),
                license=str(fm.get("license", "")), body=body,
            ))
    skills_root = root / "skills"
    if skills_root.is_dir():
        for sf in sorted(skills_root.rglob("SKILL.md")):
            fm, body = parse_frontmatter(sf.read_text(encoding="utf-8"))
            name = str(fm.get("name") or sf.parent.name)
            src = fm.get("source") or {}
            items.append(Item(
                kind="skill", id=f"skill/{sf.parent.name}",
                name=name, description=str(fm.get("description", "")),
                path=sf.parent, domain=str(fm.get("domain", "")),
                tags=_as_list(fm.get("tags")),
                source_repo=str((src or {}).get("repo", "")),
                source_commit=str((src or {}).get("commit", "")),
                license=str(fm.get("license", "")), body=body,
            ))
    return items


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def safe_join(base: Path, *parts: str) -> Path:
    """Join under base and refuse any result that escapes base.

    Guards against path traversal from crafted item names (e.g. "../../etc").
    """
    base = base.resolve()
    target = (base / Path(*parts)).resolve()
    if base != target and base not in target.parents:
        raise ValueError(f"unsafe path escapes target: {Path(*parts)!r}")
    return target


def slug(name: str) -> str:
    """Filesystem-safe slug; also a second line of defense against traversal."""
    keep = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in name)
    return keep.strip("-.") or "item"


def copy_tree_confined(src: Path, dest_dir: Path) -> None:
    """Copy src/* into dest_dir, skipping VCS/cache noise. Read+copy only."""
    import shutil
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(src, dest_dir,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store"))
