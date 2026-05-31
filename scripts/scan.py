#!/usr/bin/env python3
"""Security scanner for vendored agent/skill content.

Treats all scanned content as UNTRUSTED. Performs a *static* scan only — it
never imports, executes, or evaluates the content. Findings are classified as:

  block  -> must not enter the registry; fails the build / quarantines the item
  warn   -> surfaced for human review; does not fail unless --warn-as-error

Usage:
    scan.py PATH [PATH ...] [--json] [--warn-as-error]

Importable API:
    scan_path(path) -> list[Finding]   # recurse a dir or scan a single file
    worst_severity(findings) -> "block" | "warn" | None

Stdlib only. No third-party dependencies.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# --- file classification ----------------------------------------------------

CODE_EXTS = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts",
    ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd", ".lua", ".r",
}
TEXT_EXTS = {".md", ".markdown", ".txt", ".mdc", ".rst", ".yaml", ".yml", ".json", ".toml"}
# Binary / asset extensions are skipped for pattern scanning.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".wasm", ".so",
    ".dylib", ".pyc",
}

FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)

# --- rules ------------------------------------------------------------------
# Each rule: (id, category, severity, compiled regex, human description)
# CODE rules run against script files and fenced code blocks in markdown.
# TEXT rules run against the full text of any text file.


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


CODE_RULES = [
    # Remote code execution / piped installers
    ("rce.pipe_installer", "rce", "block",
     _r(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python[0-9.]*)\b"),
     "pipe-to-shell remote installer (curl|wget ... | sh)"),
    ("rce.eval_b64", "rce", "block",
     _r(r"(?<![.\w])(eval|exec)\s*\(\s*[^)]*b(ase)?64[._]?decode"),
     "execution of base64-decoded payload"),
    # Negative lookbehind for `.`/word char so JS `re.exec()` / `.eval()` method
    # calls are not mistaken for the Python builtins exec()/eval().
    ("rce.python_exec", "rce", "block",
     _r(r"(?<![.\w])exec\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|(?<![.\w])eval\s*\("),
     "dynamic code/command execution (exec/eval/os.system/os.popen)"),
    ("rce.shell_true", "rce", "block",
     _r(r"\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\([^)]*shell\s*=\s*True"),
     "subprocess with shell=True"),
    ("rce.shell_eval", "rce", "block",
     _r(r"(^|[;&|]\s*)eval\s+[\"$`]"),
     "shell eval of dynamic string"),
    ("rce.pickle", "rce", "block",
     _r(r"\b(pickle|cPickle|marshal)\.loads?\s*\("),
     "deserialization of untrusted data (pickle/marshal)"),
    ("rce.dynamic_import", "rce", "warn",
     _r(r"\b__import__\s*\(|\bimportlib\.import_module\s*\("),
     "dynamic import"),
    # Data exfiltration — secrets
    ("exfil.secret_paths", "exfil", "block",
     _r(r"(~|\$HOME)?/?\.(ssh|aws|gnupg)\b|\.aws/credentials|id_rsa\b"),
     "access to credential/key directories (.ssh/.aws/.gnupg/id_rsa)"),
    ("exfil.dotenv", "exfil", "warn",
     _r(r"\.env(\.|\b)"),
     "access to .env file"),
    # Block only on an actual *read* of a secret-named env var (via os.environ,
    # getenv, process.env, $VAR expansion). A bare mention of the name in prose
    # or a docstring is downgraded to a warning by exfil.secret_name below.
    ("exfil.secret_env_read", "exfil", "block",
     _r(r"(os\.environ|getenv|process\.env|ENV\[|\$\{?)[^\n]{0,30}"
        r"(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)"),
     "read of a secret-bearing environment variable"),
    ("exfil.secret_name", "exfil", "warn",
     _r(r"\b[A-Z][A-Z0-9_]{2,}(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)\b"),
     "mention of a secret-bearing identifier"),
    ("exfil.keychain", "exfil", "block",
     _r(r"\bsecurity\s+find-(generic|internet)-password\b|\bkeychain\b"),
     "macOS keychain access"),
    # Data exfiltration — network from a script
    ("exfil.net_lib", "exfil", "warn",
     _r(r"\b(requests|urllib|urllib2|httplib|http\.client|aiohttp|httpx)\b"),
     "network library use inside a script"),
    ("exfil.net_tool", "exfil", "warn",
     _r(r"(^|[;&|`$(\s])(nc|netcat|telnet|scp|sftp|rsync)\s"),
     "network/transfer tool use inside a script"),
    # Destructive operations
    ("destroy.rm_rf", "destructive", "block",
     _r(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|\*)"),
     "recursive force delete of a root/home/glob path"),
    ("destroy.disk", "destructive", "block",
     _r(r"\bdd\s+if=|\bmkfs\b|>\s*/dev/sd|>\s*/dev/disk"),
     "raw disk write / format"),
    ("destroy.forkbomb", "destructive", "block",
     _r(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:"),
     "fork bomb"),
    ("destroy.chmod_777", "destructive", "warn",
     _r(r"\bchmod\s+(-R\s+)?0?777\b"),
     "world-writable chmod 777"),
]

TEXT_RULES = [
    ("inject.ignore_prev", "injection", "block",
     _r(r"\bignore\s+(all\s+|the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts?|context)"),
     "prompt-injection: 'ignore previous instructions'"),
    ("inject.disregard", "injection", "block",
     _r(r"\bdisregard\s+(all\s+|the\s+)?(previous|prior|above|system)\b"),
     "prompt-injection: 'disregard the above/system'"),
    ("inject.fake_tool", "injection", "warn",
     _r(r"<\s*(function_calls|tool_call|invoke|antml:)"),
     "embedded fake tool-call / function-call markup"),
    ("inject.role_override", "injection", "warn",
     _r(r"<\|im_start\|>\s*system|<\|system\|>"),
     "embedded chat-template system role override"),
    ("inject.exfil_instr", "injection", "warn",
     _r(r"\b(send|post|exfiltrate|upload)\b[^\n]{0,40}\bto\b[^\n]{0,40}https?://"),
     "instruction to send data to an external URL"),
]

# Suspicious invisible / control characters used to hide instructions, keyed by
# codepoint (never written literally, so this rule cannot flag its own source).
# Allowed: \t \n \r and a BOM (U+FEFF) only at file start.
SUSPECT_UNICODE = {
    chr(0x200B): "zero-width space",
    chr(0x200C): "zero-width non-joiner",
    chr(0x200D): "zero-width joiner",
    chr(0x200E): "left-to-right mark",
    chr(0x200F): "right-to-left mark",
    chr(0x202A): "left-to-right embedding (bidi)",
    chr(0x202B): "right-to-left embedding (bidi)",
    chr(0x202C): "pop directional formatting (bidi)",
    chr(0x202D): "left-to-right override (bidi)",
    chr(0x202E): "right-to-left override (bidi)",
    chr(0x2060): "word joiner",
    chr(0x2066): "left-to-right isolate (bidi)",
    chr(0x2067): "right-to-left isolate (bidi)",
    chr(0x2068): "first strong isolate (bidi)",
    chr(0x2069): "pop directional isolate (bidi)",
}
_BOM = chr(0xFEFF)


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    category: str
    severity: str
    description: str
    excerpt: str


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _excerpt(text: str, idx: int, span: int = 80) -> str:
    start = max(0, idx - 10)
    snippet = text[start:idx + span].replace("\n", "\\n")
    return snippet.strip()[:120]


def _scan_code(text: str, rel: str, out: list[Finding]) -> None:
    for rid, cat, sev, rx, desc in CODE_RULES:
        for m in rx.finditer(text):
            out.append(Finding(rel, _line_of(text, m.start()), rid, cat, sev,
                               desc, _excerpt(text, m.start())))


def _scan_text(text: str, rel: str, out: list[Finding]) -> None:
    for rid, cat, sev, rx, desc in TEXT_RULES:
        for m in rx.finditer(text):
            out.append(Finding(rel, _line_of(text, m.start()), rid, cat, sev,
                               desc, _excerpt(text, m.start())))
    # Invisible-character check (skip a leading BOM).
    body = text[1:] if text[:1] == _BOM else text
    for ch, name in SUSPECT_UNICODE.items():
        idx = body.find(ch)
        if idx != -1:
            out.append(Finding(rel, _line_of(body, idx), "unicode.invisible",
                               "obfuscation", "block",
                               f"suspicious invisible/bidi character: {name}", ""))


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    rel = str(path.relative_to(root)) if root else str(path)
    ext = path.suffix.lower()
    if ext in SKIP_EXTS:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable -> not pattern-scannable
    out: list[Finding] = []
    if ext in CODE_EXTS:
        _scan_code(text, rel, out)
        _scan_text(text, rel, out)
    else:
        # Text/markdown: prose gets TEXT rules; fenced code blocks get CODE rules.
        _scan_text(text, rel, out)
        for m in FENCE_RE.finditer(text):
            _scan_code(m.group(1), rel, out)
    return out


def scan_path(path: str | Path) -> list[Finding]:
    p = Path(path)
    if p.is_file():
        return scan_file(p, p.parent)
    out: list[Finding] = []
    for f in sorted(p.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            out.extend(scan_file(f, p))
    return out


def worst_severity(findings: list[Finding]) -> str | None:
    sevs = {f.severity for f in findings}
    if "block" in sevs:
        return "block"
    if "warn" in sevs:
        return "warn"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Static security scanner for vendored content.")
    ap.add_argument("paths", nargs="+", help="files or directories to scan")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--warn-as-error", action="store_true",
                    help="treat warnings as blocking too")
    args = ap.parse_args(argv)

    findings: list[Finding] = []
    for p in args.paths:
        findings.extend(scan_path(p))

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("scan: clean — no findings")
        for f in findings:
            mark = "BLOCK" if f.severity == "block" else "warn "
            loc = f"{f.path}:{f.line}"
            print(f"[{mark}] {f.category:<11} {loc}  {f.description}")
            if f.excerpt:
                print(f"          | {f.excerpt}")
        blocks = sum(1 for f in findings if f.severity == "block")
        warns = sum(1 for f in findings if f.severity == "warn")
        print(f"\nsummary: {blocks} blocking, {warns} warnings, "
              f"{len(findings)} total across the scanned tree")

    worst = worst_severity(findings)
    if worst == "block" or (worst == "warn" and args.warn_as_error):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
