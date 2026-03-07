from __future__ import annotations

import curses

from ai_xss_generator.types import PayloadCandidate

_HELP = " >/<Space>: expand   <: collapse   a: all   c: collapse all   q: quit"

# Fixed column widths in the compact table row:
#   " > {#:>3} | {score:>3} | {payload} | {focus:<14} | {title:<20}"
#   1+1+1+3 + 3 + 3 + 3 = 15 before payload, 3+14+3+20 = 40 after = 55 total
_FIXED_COLS = 55


def run_interactive(payloads: list[PayloadCandidate], *, title: str = "") -> None:
    """Launch the curses-based interactive payload browser."""
    if not payloads:
        print("No payloads to display.")
        return
    try:
        curses.wrapper(_App(payloads, title).run)
    except Exception:
        # Terminal doesn't support curses — degrade to plain list
        from ai_xss_generator.output import render_list
        print(render_list(payloads))


class _App:
    def __init__(self, payloads: list[PayloadCandidate], title: str) -> None:
        self.payloads = payloads
        self.title = title
        self.selected = 0
        self.expanded: set[int] = set()
        self.scroll = 0  # topmost visible logical line

    def run(self, stdscr: "curses.window") -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)   # low risk
            curses.init_pair(2, curses.COLOR_YELLOW, -1)  # medium risk
            curses.init_pair(3, curses.COLOR_RED, -1)     # high risk
            curses.init_pair(4, curses.COLOR_CYAN, -1)    # UI chrome
            curses.init_pair(5, curses.COLOR_MAGENTA, -1) # expanded detail

        n = len(self.payloads)
        while True:
            self._draw(stdscr)
            key = stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                break
            elif key == curses.KEY_UP:
                self.selected = max(0, self.selected - 1)
            elif key == curses.KEY_DOWN:
                self.selected = min(n - 1, self.selected + 1)
            elif key in (curses.KEY_RIGHT, ord(" "), 10, 13):
                self.expanded.add(self.selected)
            elif key == curses.KEY_LEFT:
                self.expanded.discard(self.selected)
            elif key == ord("a"):
                self.expanded = set(range(n))
            elif key == ord("c"):
                self.expanded.clear()

    def _draw(self, stdscr: "curses.window") -> None:
        height, width = stdscr.getmaxyx()
        body_h = height - 2  # reserve top (header) and bottom (footer)
        lines = self._build_lines(width)

        # Keep selected row scrolled into view
        sel_line = next(
            (i for i, (k, idx, _) in enumerate(lines) if k == "row" and idx == self.selected),
            0,
        )
        if sel_line < self.scroll:
            self.scroll = sel_line
        elif sel_line >= self.scroll + body_h:
            self.scroll = sel_line - body_h + 1

        stdscr.erase()
        has_c = curses.has_colors()
        ui_attr = (curses.color_pair(4) | curses.A_BOLD) if has_c else curses.A_BOLD

        # Header
        hdr = f"  {self.title}  [{len(self.payloads)} payloads]"
        self._addstr(stdscr, 0, 0, hdr[:width - 1].ljust(width - 1), ui_attr)

        # Body
        visible = lines[self.scroll : self.scroll + body_h]
        for row_y, (kind, idx, text) in enumerate(visible, start=1):
            text = text[:width - 1]
            if kind == "row":
                is_sel = idx == self.selected
                if is_sel:
                    attr = curses.A_REVERSE
                elif has_c:
                    attr = self._risk_attr(self.payloads[idx].risk_score)
                else:
                    attr = 0
                padded = text.ljust(width - 1) if is_sel else text
                self._addstr(stdscr, row_y, 0, padded, attr)
            else:  # detail line
                attr = curses.color_pair(5) if has_c else 0
                self._addstr(stdscr, row_y, 0, text, attr)

        # Footer
        self._addstr(stdscr, height - 1, 0, _HELP[:width - 1].ljust(width - 1), ui_attr)
        stdscr.refresh()

    def _build_lines(self, width: int) -> list[tuple[str, int, str]]:
        payload_w = max(10, width - _FIXED_COLS)
        lines: list[tuple[str, int, str]] = []
        for i, p in enumerate(self.payloads):
            is_exp = i in self.expanded
            arrow = "v" if is_exp else ">"
            pl    = self._trunc(p.payload, payload_w)
            focus = self._trunc(p.target_sink or (p.tags[0] if p.tags else ""), 14)
            ttl   = self._trunc(p.title, 20)
            row = (
                f" {arrow} {i + 1:>3} | {p.risk_score:>3} | "
                f"{pl:<{payload_w}} | {focus:<14} | {ttl}"
            )
            lines.append(("row", i, row))
            if is_exp:
                pad = "             "  # aligns detail content under payload column
                lines.append(("detail", i, f"{pad}payload : {p.payload}"))
                lines.append(("detail", i, f"{pad}inject  : {p.test_vector}"))
                if p.tags:
                    lines.append(("detail", i, f"{pad}tags    : {', '.join(p.tags)}"))
                lines.append(("detail", i, f"{pad}why     : {p.explanation}"))
                lines.append(("detail", i, ""))  # blank separator between entries
        return lines

    @staticmethod
    def _trunc(s: str, n: int) -> str:
        return s[: n - 1] + "…" if len(s) > n else s

    @staticmethod
    def _risk_attr(score: int) -> int:
        if score >= 75:
            return curses.color_pair(3)
        if score >= 50:
            return curses.color_pair(2)
        return curses.color_pair(1)

    @staticmethod
    def _addstr(win: "curses.window", y: int, x: int, text: str, attr: int = 0) -> None:
        try:
            win.addstr(y, x, text, attr)
        except curses.error:
            pass  # ignore writes that go off-screen
