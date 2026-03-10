"""JS break-out closer builder for script-context XSS injection.

Given the JavaScript source code that appears BEFORE the injection point
(inside a <script> block), this module figures out what unclosed brackets,
braces, and parentheses exist and returns the string that closes them.

Prepending that "closer" before a payload allows breaking out of arbitrarily
nested JS structures without knowing the exact code ahead of time.

Example:
    code before injection: ``function foo() { var x = "``
    closer for js_string_dq: ``";}``   → closes: string, statement, function body
    payload becomes: ``";}alert(domain)//``

Adapted from the jsContexter technique in XSStrike (s0md3v/XSStrike).
"""
from __future__ import annotations

import re


def _strip_closed_structures(code: str) -> str:
    """Remove already-closed string literals and block comments from *code*.

    This prevents their brackets from being counted as unclosed openers.
    We do a single pass with a state machine so nested quotes inside comments
    (and vice-versa) are handled correctly.
    """
    result: list[str] = []
    i = 0
    n = len(code)
    in_dq = False
    in_sq = False
    in_bt = False
    in_block_comment = False
    in_line_comment = False

    while i < n:
        c = code[i]

        # Line comment ends at newline
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue

        # Block comment ends at */
        if in_block_comment:
            if c == "*" and i + 1 < n and code[i + 1] == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        # Inside a double-quoted string
        if in_dq:
            if c == "\\" and i + 1 < n:
                i += 2  # skip escaped char
                continue
            if c == '"':
                in_dq = False
            i += 1
            continue

        # Inside a single-quoted string
        if in_sq:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "'":
                in_sq = False
            i += 1
            continue

        # Inside a backtick template literal (simplified — no nested ${})
        if in_bt:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "`":
                in_bt = False
            i += 1
            continue

        # Not inside any literal/comment — check for openers
        if c == "/" and i + 1 < n:
            if code[i + 1] == "*":
                in_block_comment = True
                i += 2
                continue
            if code[i + 1] == "/":
                in_line_comment = True
                i += 2
                continue

        if c == '"':
            in_dq = True
            i += 1
            continue
        if c == "'":
            in_sq = True
            i += 1
            continue
        if c == "`":
            in_bt = True
            i += 1
            continue

        result.append(c)
        i += 1

    return "".join(result)


def build_js_closer(content_before: str, quote_char: str = "") -> str:
    """Return the string to prepend before a payload to close open JS structures.

    Args:
        content_before: The JavaScript source between the opening ``<script>``
                        tag and the injection point. For ``js_string_*``
                        contexts this is the content inside the script block
                        up to (but not including) the opening quote of the
                        string the injection lands in.
        quote_char:     The quote character that wraps the injection for
                        ``js_string_*`` contexts (``"``, ``'``, or `` ` ``).
                        Pass ``""`` for ``js_code`` contexts.

    Returns:
        A string such as ``";}`` or ``');`` that, when prepended to the
        payload, cleanly breaks out of the surrounding JS context.
        Returns the quote char + ``;//`` at minimum for string contexts, or
        ``;//`` for code contexts, so callers always get a usable closer.
    """
    if not content_before and not quote_char:
        return ""

    stripped = _strip_closed_structures(content_before)

    # Track unclosed structural openers: { → }, ( → ), [ → ]
    # We collect expected closers in a stack (rightmost = most recent unclosed)
    stack: list[str] = []
    for ch in stripped:
        if ch == "{":
            stack.append("}")
        elif ch == "(":
            stack.append(")")
        elif ch == "[":
            stack.append("]")
        elif ch in ("}", ")", "]"):
            # Close the matching opener if present (handles partial code)
            if stack and stack[-1] == ch:
                stack.pop()

    # Build the closer from innermost to outermost.
    # Stack top is the innermost unclosed → goes first in the output.
    # Between each structural closer we insert ";" to terminate statements.
    parts: list[str] = []
    for closer in reversed(stack):
        parts.append(closer)
        if closer == "}":
            # After closing a block, add a statement terminator
            parts.append(";")

    structural_closer = "".join(parts)

    if quote_char:
        # Close the open string, then terminate the statement, then close structures
        return f"{quote_char};{structural_closer}"
    else:
        # Just terminate + close structures
        return f";{structural_closer}" if structural_closer else ""
