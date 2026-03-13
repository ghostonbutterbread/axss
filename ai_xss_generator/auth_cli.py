from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ai_xss_generator.auth import describe_auth
from ai_xss_generator.auth_profiles import (
    AuthImportPreview,
    AuthProfile,
    AUTH_PROFILES_PATH,
    apply_import_preview,
    build_headers_from_profile,
    clear_active_profile,
    delete_profile,
    get_active_profile,
    list_auth_profiles,
    load_auth_store,
    preview_auth_import,
    purge_invalid_profiles,
    resolve_profile_ref,
    set_active_profile,
    touch_profile_last_used,
    validate_profile,
)
from ai_xss_generator.console import info, success, warn


def build_auth_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axss auth",
        description="Manage reusable authenticated scan profiles.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("none", help="Clear the active auth profile and run future scans unauthenticated by default.")
    sub.add_parser("list", help="List auth profiles, grouped by program, and prune clearly invalid profiles.")

    show_parser = sub.add_parser("show", help="Show one auth profile.")
    show_parser.add_argument("profile", help="Profile ref: program/name or a unique profile name")

    use_parser = sub.add_parser("use", help="Set one auth profile as active.")
    use_parser.add_argument("profile", help="Profile ref: program/name or a unique profile name")

    del_parser = sub.add_parser("delete", help="Delete one auth profile.")
    del_parser.add_argument("profile", help="Profile ref: program/name or a unique profile name")

    export_parser = sub.add_parser("export", help="Export one auth profile as JSON.")
    export_parser.add_argument("profile", help="Profile ref: program/name or a unique profile name")
    export_parser.add_argument("--output", metavar="PATH", help="Write JSON to PATH instead of stdout.")

    import_parser = sub.add_parser("import", help="Import auth material from a request/curl/cookies/header source.")
    import_parser.add_argument("source", help="Path to a source file or pasted raw input.")
    import_parser.add_argument("--program", required=True, help="Program/engagement group name.")
    import_parser.add_argument("--profile", required=True, help="Profile name within the program.")
    import_parser.add_argument(
        "--type",
        choices=["auto", "burp_request", "curl", "cookies_txt", "header_block"],
        default="auto",
        help="Force the import parser type.",
    )
    import_parser.add_argument("--notes", default="", help="Optional notes to store with the profile.")
    import_parser.add_argument("--activate", action="store_true", help="Set the imported profile as active immediately.")
    import_parser.add_argument(
        "--mode",
        choices=["ask", "save", "replace", "merge"],
        default="ask",
        help="How to store the imported profile when the target ref already exists.",
    )
    import_parser.add_argument(
        "--preview-only",
        action="store_true",
        help="Parse the auth material and print the preview without saving.",
    )

    test_parser = sub.add_parser("test", help="Validate one auth profile against its base URL.")
    test_parser.add_argument("profile", help="Profile ref: program/name or a unique profile name")

    return parser


def _render_profile(profile: AuthProfile, *, active_ref: str = "") -> str:
    marker = "*" if profile.ref == active_ref else " "
    auth_lines = describe_auth(build_headers_from_profile(profile))
    auth_preview = "; ".join(auth_lines) if auth_lines else "No parsed auth material."
    return (
        f"{marker} {profile.ref}\n"
        f"    base_url: {profile.base_url or 'n/a'}\n"
        f"    source:   {profile.source_type}\n"
        f"    domains:  {', '.join(profile.domains) if profile.domains else 'n/a'}\n"
        f"    auth:     {auth_preview}\n"
        f"    updated:  {profile.updated_at or profile.created_at or 'n/a'}"
    )


def _print_grouped_profiles(store: dict) -> None:
    profiles = list_auth_profiles(store)
    active_ref = str(store.get("active_profile", "") or "").strip()
    if not profiles:
        info("No auth profiles stored.")
        info(f"Store path: {AUTH_PROFILES_PATH}")
        return
    grouped: dict[str, list[AuthProfile]] = {}
    for profile in profiles:
        grouped.setdefault(profile.program, []).append(profile)
    for program in sorted(grouped):
        print(f"[{program}]")
        for profile in grouped[program]:
            print(_render_profile(profile, active_ref=active_ref))
        print()
    if active_ref:
        success(f"Active profile: {active_ref}")
    else:
        info("Active profile: none")


def _render_import_preview(preview: AuthImportPreview) -> str:
    lines = [
        f"Import preview for {preview.profile.ref}",
        f"  source:   {preview.source_label}",
        f"  base_url: {preview.profile.base_url or 'n/a'}",
        f"  domains:  {preview.domains_preview}",
        f"  headers:  {preview.header_count}",
        f"  cookies:  {preview.cookie_count}",
    ]
    auth_lines = describe_auth(build_headers_from_profile(preview.profile))
    if auth_lines:
        lines.append("  auth:")
        lines.extend([f"    - {line}" for line in auth_lines])
    if preview.existing_profile is not None:
        lines.append(f"  existing: {preview.existing_profile.ref}")
    return "\n".join(lines)


def _prompt_import_mode(preview: AuthImportPreview) -> str:
    if preview.existing_profile is None:
        return "save"
    while True:
        answer = input("Save mode [s]ave/[m]erge/[r]eplace/[c]ancel: ").strip().lower()
        if answer in {"s", "save"}:
            return "save"
        if answer in {"m", "merge"}:
            return "merge"
        if answer in {"r", "replace"}:
            return "replace"
        if answer in {"c", "cancel", ""}:
            return "cancel"


def handle_auth_command(argv: list[str]) -> int:
    parser = build_auth_parser()
    args = parser.parse_args(argv)
    command = args.command or "tui"

    if command == "tui":
        if sys.stdin.isatty() and sys.stdout.isatty():
            from ai_xss_generator.auth_tui import run_auth_tui
            return run_auth_tui()
        command = "list"

    if command == "none":
        clear_active_profile()
        success("Active auth cleared. Future scans will run unauthenticated unless --profile is set.")
        return 0

    if command == "import":
        preview = preview_auth_import(
            source=args.source,
            program=args.program,
            profile_name=args.profile,
            source_type=args.type,
            notes=args.notes,
        )
        print(_render_import_preview(preview))
        if args.preview_only:
            return 0
        mode = args.mode
        if mode == "ask":
            mode = _prompt_import_mode(preview)
        if mode == "cancel":
            info("Import cancelled.")
            return 0
        try:
            store, profile = apply_import_preview(preview, mode=mode)
        except ValueError as exc:
            parser.error(str(exc))
        if args.activate:
            store, resolved = set_active_profile(profile.ref, store)
            if resolved is not None:
                touch_profile_last_used(resolved.ref, store)
                success(f"Imported and activated {resolved.ref}")
        else:
            success(f"Imported {profile.ref} ({mode})")
        print(_render_profile(profile, active_ref=str(store.get("active_profile", "") or "")))
        return 0

    store, removed = purge_invalid_profiles()
    for profile, validation in removed:
        warn(f"Removed expired auth profile {profile.ref}: {validation.reason}")

    if command == "list":
        _print_grouped_profiles(store)
        return 0

    if command == "show":
        profile = resolve_profile_ref(args.profile, store)
        if profile is None:
            parser.error(f"Unknown auth profile: {args.profile}")
        print(_render_profile(profile, active_ref=str(store.get("active_profile", "") or "")))
        if profile.notes:
            print(f"    notes:    {profile.notes}")
        if profile.last_validated_at:
            print(f"    checked:  {profile.last_validated_at}")
        return 0

    if command == "use":
        store, resolved = set_active_profile(args.profile, store)
        if resolved is None:
            parser.error(f"Unknown auth profile: {args.profile}")
        touch_profile_last_used(resolved.ref, store)
        success(f"Active auth profile set: {resolved.ref}")
        return 0

    if command == "delete":
        store, deleted = delete_profile(args.profile, store)
        if not deleted:
            parser.error(f"Unknown auth profile: {args.profile}")
        success(f"Deleted auth profile: {args.profile}")
        return 0

    if command == "export":
        profile = resolve_profile_ref(args.profile, store)
        if profile is None:
            parser.error(f"Unknown auth profile: {args.profile}")
        payload = json.dumps(profile.to_dict(), indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
            success(f"Exported {profile.ref} to {args.output}")
        else:
            print(payload, end="")
        return 0

    if command == "test":
        profile = resolve_profile_ref(args.profile, store)
        if profile is None:
            parser.error(f"Unknown auth profile: {args.profile}")
        validation = validate_profile(profile)
        if validation.invalid:
            delete_profile(profile.ref, store)
            warn(f"Removed expired auth profile {profile.ref}: {validation.reason}")
            return 1
        if validation.valid:
            success(f"{profile.ref}: {validation.reason}")
            if validation.final_url:
                info(f"Final URL: {validation.final_url}")
            touch_profile_last_used(profile.ref, store)
            return 0
        warn(f"{profile.ref}: {validation.reason}")
        if validation.final_url:
            info(f"Final URL: {validation.final_url}")
        return 1

    parser.print_help()
    return 0
