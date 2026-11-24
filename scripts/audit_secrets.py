#!/usr/bin/env python3
"""Fleet Muse — static secret-leak audit for the code layer.

Scans the code layer (docker/, scripts/, tests/, providers/ and repo-root
code files) for:
  * hardcoded UUIDs,
  * hardcoded API keys / tokens / secrets,
  * plaintext private keys,
  * debug statements that print environment variables (os.environ, etc.).

Never scans .secrets/, registry/, output/ or .git/ (those are runtime state,
not code). Exit 0 = clean, exit 1 = findings.

Usage:
    python3 scripts/audit_secrets.py [--root PATH]
"""
import argparse
import re
import sys
from pathlib import Path

# Directories that are runtime state, never code — never scanned.
EXCLUDE_DIRS = {".secrets", "registry", "output", ".git", "__pycache__", ".pytest_cache", "node_modules"}

# Only these file types are scanned.
SCAN_SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".md", ".txt", ""}
SCAN_FILENAMES = {"Dockerfile", "entrypoint.sh"}

# --- Patterns (each is (name, compiled regex)) ---
PATTERNS = [
    (
        "hardcoded-uuid",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "hardcoded-api-key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|"
            r"secret[_-]?key|client[_-]?secret|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
    (
        "hardcoded-password",
        re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    ),
    (
        "token-prefix",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|"
            r"xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{16})\b"
        ),
    ),
    (
        "vless-url-with-uuid",
        re.compile(r"vless://[0-9a-fA-F-]{36}@"),
    ),
    (
        "debug-print-environ",
        re.compile(
            r"(?:print|logging\.(?:debug|info|warning|error|critical)|"
            r"console\.log)\s*\(.*\bos\.environ\b"
        ),
    ),
    (
        "debug-print-getenv",
        re.compile(
            r"(?:print|logging\.(?:debug|info|warning|error|critical))\s*\(.*\bos\.getenv\b"
        ),
    ),
    (
        "env-dump-statement",
        # Built dynamically so the literal word never appears in this file
        # (otherwise the audit would flag its own pattern definition).
        re.compile(r"(?i)\b" + "print" + "env" + r"\b|\benv\s*\|\s*sort\b"),
    ),
    (
        "shell-echo-secret",
        re.compile(r"(?i)\becho\b[^#\n]*\$(?:UUID|API[_-]?KEY|SECRET|TOKEN|PASSWORD)\b"),
    ),
]


def iter_code_files(root: Path):
    """Yield code files under root, skipping runtime-state directories."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Skip any file inside an excluded directory.
        if any(part in EXCLUDE_DIRS for part in path.relative_to(root).parts):
            continue
        if path.suffix in SCAN_SUFFIXES or path.name in SCAN_FILENAMES:
            yield path


def scan_file(path: Path):
    """Return a list of (line_no, pattern_name, snippet) findings."""
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return []
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, regex in PATTERNS:
            if regex.search(line):
                findings.append((lineno, name, line.strip()[:160]))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the code layer for leaked secrets.")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Repo root to scan (default: parent of scripts/).",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()

    total = 0
    for path in iter_code_files(root):
        for lineno, name, snippet in scan_file(path):
            total += 1
            print(f"{path.relative_to(root)}:{lineno}: [{name}] {snippet}")
    if total:
        print(f"audit_secrets: FAIL — {total} finding(s)", file=sys.stderr)
        return 1
    print("audit_secrets: OK — no hardcoded secrets or env-dump statements found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
