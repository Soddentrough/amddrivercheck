#!/usr/bin/env python3
"""
verify_scripts.py - Validates PowerShell scripts and modules for basic syntax
and balanced delimiters.
"""

import re
import sys
from pathlib import Path

PARAM_IF_RE = re.compile(r'(?i)(?:^|\s)-[a-zA-Z][a-zA-Z0-9]*\s+(?:if|switch|foreach|for|while)\s*\(')

def check_file(filepath: Path) -> bool:
    content = filepath.read_text(encoding="utf-8")
    lines = content.splitlines()

    stack = []
    in_single_quote = False
    in_double_quote = False
    in_here_single = False
    in_here_double = False
    in_block_comment = False
    errors = []

    pairs = {')': '(', ']': '[', '}': '{'}

    for line_no, line in enumerate(lines, start=1):
        if in_here_single:
            if line.startswith("'@"):
                in_here_single = False
            continue
        if in_here_double:
            if line.startswith('"@'):
                in_here_double = False
            continue

        i = 0
        n = len(line)
        unquoted_chars = []
        while i < n:
            c = line[i]

            # Handle block comments <# ... #>
            if in_block_comment:
                if c == '#' and i + 1 < n and line[i+1] == '>':
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            if not in_single_quote and not in_double_quote:
                if c == '<' and i + 1 < n and line[i+1] == '#':
                    in_block_comment = True
                    i += 2
                    continue
                if c == '#':
                    # Single line comment to end of line
                    break
                if c == '@' and i + 1 == n - 1:
                    if line[i+1] == "'":
                        in_here_single = True
                        break
                    if line[i+1] == '"':
                        in_here_double = True
                        break

            # Handle quotes
            if c == "'" and not in_double_quote:
                # Handle escaped single quote in single quotes ''
                if in_single_quote and i + 1 < n and line[i+1] == "'":
                    i += 2
                    continue
                in_single_quote = not in_single_quote
                unquoted_chars.append(' ')
                i += 1
                continue

            if c == '"' and not in_single_quote:
                # Handle ` " or "" inside double quotes
                if in_double_quote:
                    if i > 0 and line[i-1] == '`':
                        i += 1
                        continue
                    if i + 1 < n and line[i+1] == '"':
                        i += 2
                        continue
                in_double_quote = not in_double_quote
                unquoted_chars.append(' ')
                i += 1
                continue

            if in_single_quote or in_double_quote:
                unquoted_chars.append(' ')
                i += 1
                continue

            unquoted_chars.append(c)

            # Check brackets
            if c in '({[':
                stack.append((c, line_no, i + 1))
            elif c in ')}]':
                expected = pairs[c]
                if not stack:
                    errors.append(f"Line {line_no}:{i+1} Unmatched closing '{c}'")
                else:
                    top, top_line, top_col = stack.pop()
                    if top != expected:
                        errors.append(f"Line {line_no}:{i+1} Mismatched closing '{c}', expected matching for '{top}' from line {top_line}:{top_col}")

            i += 1

        unquoted_line = "".join(unquoted_chars)
        m = PARAM_IF_RE.search(unquoted_line)
        if m:
            errors.append(
                f"Line {line_no}:{m.start() + 1} Unparenthesized control statement after parameter flag '{m.group(0).strip()}' (wrap in $(...))"
            )

    if in_block_comment:
        errors.append("Unclosed block comment '<#' at EOF")
    if in_single_quote:
        errors.append("Unclosed single quote at EOF")
    if in_double_quote:
        errors.append("Unclosed double quote at EOF")
    while stack:
        top, top_line, top_col = stack.pop()
        errors.append(f"Unclosed '{top}' from line {top_line}:{top_col}")

    if errors:
        print(f"[FAIL] {filepath.name}:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print(f"[OK]   {filepath.name} ({len(lines)} lines)")
        return True


def main():
    root = Path(__file__).resolve().parent.parent
    ps_files = (
        list(root.glob("*.ps1"))
        + list(root.glob("scripts/*.ps1"))
        + list(root.glob("scripts/modules/*.psm1"))
        + list(root.glob("tests/*.ps1"))
    )

    print("Verifying PowerShell scripts and modules...")
    all_ok = True
    for f in sorted(ps_files):
        if not check_file(f):
            all_ok = False

    if not all_ok:
        print("\nErrors detected in one or more scripts.")
        sys.exit(1)
    else:
        print(f"\nAll {len(ps_files)} PowerShell scripts passed verification cleanly!")


if __name__ == "__main__":
    main()
