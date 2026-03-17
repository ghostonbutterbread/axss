from __future__ import annotations

import curses
import json
from pathlib import Path

from ai_xss_generator.auth import describe_auth
from ai_xss_generator.auth_profiles import (
    AuthImportPreview,
    apply_import_preview,
    AuthProfile,
    build_headers_from_profile,
    clear_active_profile,
    delete_profile,
    list_auth_profiles,
    load_auth_store,
    preview_auth_import,
    purge_invalid_profiles,
    record_profile_validation,
    resolve_profile_ref,
    set_active_profile,
    touch_profile_last_used,
    upsert_profile,
    validate_profile,
)


class _AuthTui:
    def __init__(self, stdscr: "curses._CursesWindow") -> None:
        self.stdscr = stdscr
        self.focus = "programs"
        self.program_index = 0
        self.profile_index = 0
        self.message = ""
        self._load_store(validate=True)

    def _load_store(self, *, validate: bool = False) -> None:
        if validate:
            self.store, removed = purge_invalid_profiles()
            if removed:
                removed_preview = ", ".join(profile.ref for profile, _ in removed[:2])
                suffix = f", +{len(removed) - 2} more" if len(removed) > 2 else ""
                self.message = f"Removed expired profiles: {removed_preview}{suffix}"
        else:
            self.store = load_auth_store()
        self.profiles = list_auth_profiles(self.store)
        self.programs = sorted({profile.program for profile in self.profiles}) or ["(none)"]
        if self.program_index >= len(self.programs):
            self.program_index = max(0, len(self.programs) - 1)
        self._normalize_profile_selection()

    def _normalize_profile_selection(self) -> None:
        profiles = self._profiles_for_selected_program()
        if not profiles:
            self.profile_index = 0
        elif self.profile_index >= len(profiles):
            self.profile_index = len(profiles) - 1

    def _selected_program(self) -> str:
        if not self.programs:
            return ""
        program = self.programs[self.program_index]
        return "" if program == "(none)" else program

    def _profiles_for_selected_program(self) -> list[AuthProfile]:
        program = self._selected_program()
        if not program:
            return []
        return [profile for profile in self.profiles if profile.program == program]

    def _selected_profile(self) -> AuthProfile | None:
        profiles = self._profiles_for_selected_program()
        if not profiles:
            return None
        return profiles[self.profile_index]

    def _draw_box(self, y: int, x: int, height: int, width: int, title: str) -> None:
        self.stdscr.addstr(y, x, "+" + "-" * (width - 2) + "+")
        self.stdscr.addstr(y + height - 1, x, "+" + "-" * (width - 2) + "+")
        for row in range(y + 1, y + height - 1):
            self.stdscr.addstr(row, x, "|")
            self.stdscr.addstr(row, x + width - 1, "|")
        title_text = f" {title} "
        if len(title_text) < width - 2:
            self.stdscr.addstr(y, x + 2, title_text)

    def _write_lines(self, y: int, x: int, width: int, lines: list[str], selected: int | None = None) -> None:
        for idx, line in enumerate(lines):
            clipped = line[: max(0, width - 1)]
            attr = curses.A_REVERSE if selected is not None and idx == selected else curses.A_NORMAL
            self.stdscr.addstr(y + idx, x, clipped.ljust(width - 1), attr)

    def _prompt(self, label: str, initial: str = "") -> str:
        max_y, max_x = self.stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        self.stdscr.move(max_y - 2, 1)
        self.stdscr.clrtoeol()
        prompt = f"{label}: "
        self.stdscr.addstr(max_y - 2, 1, prompt)
        self.stdscr.addstr(max_y - 1, 1, (" " * (max_x - 2)))
        self.stdscr.move(max_y - 1, 1)
        if initial:
            self.stdscr.addstr(max_y - 1, 1, initial[: max_x - 2])
            self.stdscr.move(max_y - 1, min(max_x - 2, len(initial) + 1))
        self.stdscr.refresh()
        value = self.stdscr.getstr(max_y - 1, 1, max(1, max_x - 3)).decode("utf-8", errors="replace").strip()
        curses.noecho()
        curses.curs_set(0)
        return value

    def _confirm(self, label: str) -> bool:
        answer = self._prompt(f"{label} [y/N]").lower()
        return answer in {"y", "yes"}

    def _choose_import_mode(self, preview: AuthImportPreview) -> str:
        if preview.existing_profile is None:
            return "save"
        answer = self._prompt(
            "Save mode [save/merge/replace/cancel]",
            "merge",
        ).lower()
        if answer in {"save", "merge", "replace"}:
            return answer
        return "cancel"

    def _render_details(self, profile: AuthProfile | None, width: int) -> list[str]:
        if profile is None:
            return [
                "No profile selected.",
                "",
                "Hotkeys:",
                "  i import   n import new",
                "  u use      o no auth",
                "  t test     r refresh",
                "  s export   x delete",
                "  q quit",
            ]
        auth_lines = describe_auth(build_headers_from_profile(profile))
        details = [
            f"Name:      {profile.name}",
            f"Program:   {profile.program}",
            f"Base URL:  {profile.base_url or 'n/a'}",
            f"Source:    {profile.source_type}",
            f"Domains:   {', '.join(profile.domains) if profile.domains else 'n/a'}",
            f"Headers:   {len(profile.headers)}",
            f"Cookies:   {len(profile.cookies)}",
            f"Created:   {profile.created_at or 'n/a'}",
            f"Updated:   {profile.updated_at or 'n/a'}",
            f"Checked:   {profile.last_validated_at or 'n/a'}",
            f"Last used: {profile.last_used_at or 'n/a'}",
            f"Invalid:   {profile.invalid_reason or 'no'}",
            "",
            "Auth material:",
        ]
        details.extend([f"  - {line}" for line in auth_lines] or ["  - No parsed auth material"])
        if profile.notes:
            details.extend(["", "Notes:", f"  {profile.notes}"])
        details.extend([
            "",
            "Hotkeys:",
            "  i import   n import new",
            "  u use      o no auth",
            "  t test     r refresh",
            "  s export   x delete",
            "  q quit",
        ])
        return [line[: max(0, width - 3)] for line in details]

    def _import_profile(self, *, preset_program: str = "", preset_name: str = "") -> None:
        source = self._prompt("Source path or one-line raw input")
        if not source:
            self.message = "Import cancelled."
            return
        program = self._prompt("Program", preset_program or self._selected_program() or "default")
        if not program:
            self.message = "Import cancelled."
            return
        name = self._prompt("Profile name", preset_name)
        if not name:
            self.message = "Import cancelled."
            return
        type_hint = self._prompt("Type [auto/burp_request/curl/cookies_txt/header_block]", "auto") or "auto"
        notes = self._prompt("Notes")
        try:
            preview = preview_auth_import(
                source=source,
                program=program,
                profile_name=name,
                source_type=type_hint,
                notes=notes,
            )
        except Exception as exc:
            self.message = f"Import failed: {exc}"
            return
        self.message = (
            f"Preview {preview.profile.ref}: headers={preview.header_count} "
            f"cookies={preview.cookie_count} domains={preview.domains_preview}"
            + (f" existing={preview.existing_profile.ref}" if preview.existing_profile else "")
        )
        self.render()
        mode = self._choose_import_mode(preview)
        if mode == "cancel":
            self.message = "Import cancelled."
            return
        _, profile = apply_import_preview(preview, mode=mode)
        self._load_store(validate=False)
        self.message = f"Imported {profile.ref} ({mode})"
        if profile.program in self.programs:
            self.program_index = self.programs.index(profile.program)
        selected = resolve_profile_ref(profile.ref, self.store)
        profiles = self._profiles_for_selected_program()
        if selected is not None and selected in profiles:
            self.profile_index = profiles.index(selected)

    def _use_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self.message = "No profile selected."
            return
        self.store, resolved = set_active_profile(profile.ref, self.store)
        if resolved is None:
            self.message = "Could not activate selected profile."
            return
        self.store = touch_profile_last_used(resolved.ref, self.store)
        self._load_store(validate=False)
        self.message = f"Active auth profile set: {resolved.ref}"

    def _clear_active(self) -> None:
        self.store = clear_active_profile(self.store)
        self._load_store(validate=False)
        self.message = "Active auth cleared."

    def _delete_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self.message = "No profile selected."
            return
        if not self._confirm(f"Delete {profile.ref}?"):
            self.message = "Delete cancelled."
            return
        self.store, deleted = delete_profile(profile.ref, self.store)
        self._load_store(validate=False)
        self.message = f"Deleted {profile.ref}" if deleted else "Delete failed."

    def _export_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self.message = "No profile selected."
            return
        output_path = self._prompt("Export path", f"{profile.name}.json")
        if not output_path:
            self.message = "Export cancelled."
            return
        Path(output_path).write_text(json.dumps(profile.to_dict(), indent=2) + "\n", encoding="utf-8")
        self.message = f"Exported {profile.ref} to {output_path}"

    def _test_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self.message = "No profile selected."
            return
        validation = validate_profile(profile)
        if validation.invalid:
            self.store, _ = delete_profile(profile.ref, self.store)
            self._load_store(validate=False)
            self.message = f"Removed expired profile {profile.ref}: {validation.reason}"
            return
        self.store = record_profile_validation(profile, validation, self.store)
        if validation.valid:
            self.store = touch_profile_last_used(profile.ref, self.store)
            self._load_store(validate=False)
            self.message = f"{profile.ref}: {validation.reason}"
        else:
            self._load_store(validate=False)
            self.message = f"{profile.ref}: {validation.reason}"

    def _move_selection(self, delta: int) -> None:
        if self.focus == "programs":
            self.program_index = max(0, min(len(self.programs) - 1, self.program_index + delta))
            self.profile_index = 0
        else:
            profiles = self._profiles_for_selected_program()
            if not profiles:
                self.profile_index = 0
                return
            self.profile_index = max(0, min(len(profiles) - 1, self.profile_index + delta))

    def render(self) -> None:
        self.stdscr.erase()
        max_y, max_x = self.stdscr.getmaxyx()
        curses.curs_set(0)
        title = "axss auth — profile manager"
        self.stdscr.addstr(0, 2, title[: max_x - 4], curses.A_BOLD)
        active_ref = str(self.store.get("active_profile", "") or "").strip() or "none"
        self.stdscr.addstr(1, 2, f"Active profile: {active_ref}"[: max_x - 4])

        body_y = 3
        body_height = max(8, max_y - 6)
        left_w = max(18, int(max_x * 0.22))
        mid_w = max(24, int(max_x * 0.28))
        right_w = max(24, max_x - left_w - mid_w - 6)

        self._draw_box(body_y, 1, body_height, left_w, "Programs")
        self._draw_box(body_y, left_w + 2, body_height, mid_w, "Profiles")
        self._draw_box(body_y, left_w + mid_w + 3, body_height, right_w, "Details")

        program_lines = self.programs[: max(0, body_height - 2)]
        self._write_lines(
            body_y + 1,
            3,
            left_w - 2,
            program_lines,
            selected=self.program_index if self.focus == "programs" else None,
        )

        profiles = self._profiles_for_selected_program()
        profile_lines = [profile.name + (" *" if profile.ref == active_ref else "") for profile in profiles]
        self._write_lines(
            body_y + 1,
            left_w + 4,
            mid_w - 2,
            profile_lines[: max(0, body_height - 2)],
            selected=self.profile_index if self.focus == "profiles" else None,
        )

        details = self._render_details(self._selected_profile(), right_w)
        self._write_lines(
            body_y + 1,
            left_w + mid_w + 5,
            right_w - 2,
            details[: max(0, body_height - 2)],
        )

        status = self.message or "Arrows/jk move  Tab switches pane  q quits"
        help_line = "n new  i import  u use  o no-auth  t test  s export  x delete  r refresh  q quit"
        self.stdscr.addstr(max_y - 2, 1, status[: max_x - 2].ljust(max_x - 2), curses.A_REVERSE)
        self.stdscr.addstr(max_y - 1, 1, help_line[: max_x - 2].ljust(max_x - 2), curses.A_REVERSE)
        self.stdscr.refresh()

    def run(self) -> int:
        while True:
            self.render()
            key = self.stdscr.getch()
            if key in {ord("q"), 27}:
                return 0
            if key in {curses.KEY_UP, ord("k")}:
                self._move_selection(-1)
            elif key in {curses.KEY_DOWN, ord("j")}:
                self._move_selection(1)
            elif key in {9, curses.KEY_RIGHT, curses.KEY_LEFT}:
                self.focus = "profiles" if self.focus == "programs" else "programs"
            elif key == ord("r"):
                self._load_store(validate=True)
                self.message = self.message or "Refreshed auth profiles."
            elif key == ord("u"):
                self._use_selected()
            elif key == ord("o"):
                self._clear_active()
            elif key == ord("x"):
                self._delete_selected()
            elif key == ord("s"):
                self._export_selected()
            elif key == ord("t"):
                self._test_selected()
            elif key == ord("i"):
                self._import_profile()
            elif key == ord("n"):
                self._import_profile(preset_program=self._selected_program())
def run_auth_tui() -> int:
    def _main(stdscr: "curses._CursesWindow") -> int:
        curses.use_default_colors()
        stdscr.keypad(True)
        tui = _AuthTui(stdscr)
        return tui.run()

    return curses.wrapper(_main)
