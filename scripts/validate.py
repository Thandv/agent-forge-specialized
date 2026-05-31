#!/usr/bin/env python3
"""Validate the registry: schema, license gate, lock integrity, security.

Exit non-zero if any check fails. Run by CI and before every build.
Stdlib only; never executes registry content.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from adapters import common  # noqa: E402
from scripts import scan as scanner  # noqa: E402


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    reg = ROOT / "registry"
    items = common.load_registry(reg)

    if not items:
        errors.append("registry is empty — run scripts/sync.sh first")

    # schema + license gate + uniqueness
    seen: dict[str, Path] = {}
    for it in items:
        loc = it.path.relative_to(ROOT)
        if it.id in seen:
            errors.append(f"duplicate id {it.id} ({loc} and {seen[it.id]})")
        seen[it.id] = loc
        if not it.name:
            errors.append(f"{loc}: missing 'name'")
        if not it.description or len(it.description) < 10:
            errors.append(f"{loc}: missing or too-short 'description'")
        if it.kind == "agent" and not it.domain:
            errors.append(f"{loc}: agent missing 'domain'")
        if not common.is_permissive(it.license):
            errors.append(f"{loc}: license '{it.license or 'MISSING'}' is not in the "
                          f"permissive allow-list — vendored content must be permissive")
        if not it.source_repo:
            warnings.append(f"{loc}: missing source.repo provenance")

    # lock integrity
    lock_path = ROOT / "sources" / "lock.json"
    if lock_path.is_file():
        import hashlib
        lock = common.json.loads(lock_path.read_text(encoding="utf-8"))
        for rel, expected in lock.items():
            fp = ROOT / rel
            if not fp.is_file():
                errors.append(f"lock: missing file {rel}")
                continue
            h = hashlib.sha256(fp.read_bytes()).hexdigest()
            if h != expected:
                errors.append(f"lock: hash mismatch for {rel} (content changed since sync)")
    else:
        warnings.append("sources/lock.json not found — run scripts/sync.sh")

    # defense-in-depth: re-scan the vendored tree
    findings = scanner.scan_path(reg)
    blocks = [f for f in findings if f.severity == "block"]
    for f in blocks:
        errors.append(f"security: {f.path}:{f.line} {f.description}")

    # report
    for w in warnings:
        print(f"  warn:  {w}")
    for e in errors:
        print(f"  ERROR: {e}")
    n_agents = sum(1 for i in items if i.kind == "agent")
    n_skills = sum(1 for i in items if i.kind == "skill")
    print(f"\nvalidate: {n_agents} agents, {n_skills} skills, "
          f"{len(warnings)} warnings, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
