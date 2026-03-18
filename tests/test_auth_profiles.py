from __future__ import annotations

from types import SimpleNamespace

from ai_xss_generator.auth_profiles import (
    AuthProfile,
    apply_import_preview,
    import_auth_profile,
    load_auth_store,
    merge_scan_auth_headers,
    preview_auth_import,
    purge_invalid_profiles,
    resolve_scan_profile,
    set_active_profile,
    upsert_profile,
    validate_profile,
)


def test_import_burp_request_extracts_headers_and_cookies(tmp_path, monkeypatch) -> None:
    raw = (
        "GET /account HTTP/2\n"
        "Host: example.test\n"
        "Cookie: session=abc; pref=1\n"
        "Authorization: Bearer secret\n"
        "X-CSRF-Token: token123\n"
        "\n"
    )
    request_path = tmp_path / "request.txt"
    request_path.write_text(raw, encoding="utf-8")

    profile = import_auth_profile(
        source=str(request_path),
        program="demo",
        profile_name="admin",
    )

    assert profile.base_url == "https://example.test/account"
    assert profile.cookies == {"session": "abc", "pref": "1"}
    assert profile.headers["Authorization"] == "Bearer secret"
    assert profile.headers["X-CSRF-Token"] == "token123"
    assert profile.domains == ["example.test"]


def test_preview_and_merge_import_combines_existing_profile(tmp_path, monkeypatch) -> None:
    auth_path = tmp_path / "auth_profiles.json"
    monkeypatch.setattr("ai_xss_generator.auth_profiles.AUTH_PROFILES_PATH", auth_path)

    upsert_profile(AuthProfile(
        program="demo",
        name="admin",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer old"},
        cookies={"session": "abc"},
        notes="existing note",
    ))
    request_path = tmp_path / "request.txt"
    request_path.write_text(
        "GET /admin HTTP/2\n"
        "Host: example.test\n"
        "Cookie: pref=1\n"
        "X-CSRF-Token: token123\n\n",
        encoding="utf-8",
    )

    preview = preview_auth_import(
        source=str(request_path),
        program="demo",
        profile_name="admin",
        source_type="auto",
        notes="new note",
    )

    assert preview.existing_profile is not None
    store, merged = apply_import_preview(preview, mode="merge")

    assert merged.headers["Authorization"] == "Bearer old"
    assert merged.headers["X-CSRF-Token"] == "token123"
    assert merged.cookies["session"] == "abc"
    assert merged.cookies["pref"] == "1"
    assert "existing note" in merged.notes
    assert "new note" in merged.notes
    assert store["profiles"][0]["name"] == "admin"


def test_purge_invalid_profiles_removes_only_clear_invalid_profiles(tmp_path, monkeypatch) -> None:
    auth_path = tmp_path / "auth_profiles.json"
    monkeypatch.setattr("ai_xss_generator.auth_profiles.AUTH_PROFILES_PATH", auth_path)

    upsert_profile(AuthProfile(
        program="demo",
        name="good",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer ok"},
    ))
    upsert_profile(AuthProfile(
        program="demo",
        name="bad",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer dead"},
    ))

    def _fake_fetcher(url: str, headers: dict[str, str]) -> dict[str, object]:
        if headers.get("Authorization") == "Bearer dead":
            return {"status_code": 401, "final_url": url}
        return {"status_code": 200, "final_url": url}

    store, removed = purge_invalid_profiles(fetcher=_fake_fetcher)

    assert [profile.ref for profile, _ in removed] == ["demo/bad"]
    assert [item["program"] + "/" + item["name"] for item in store["profiles"]] == ["demo/good"]


def test_cli_scan_uses_explicit_profile_without_deleting_store(tmp_path, monkeypatch) -> None:
    from ai_xss_generator import cli

    auth_path = tmp_path / "auth_profiles.json"
    monkeypatch.setattr("ai_xss_generator.auth_profiles.AUTH_PROFILES_PATH", auth_path)
    monkeypatch.setattr("ai_xss_generator.auth_cli.AUTH_PROFILES_PATH", auth_path)

    store = upsert_profile(AuthProfile(
        program="demo",
        name="admin",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer abc"},
        cookies={"session": "cookie123"},
    ))
    set_active_profile("demo/admin", store)

    captured: dict[str, object] = {}

    def _fake_run_active_scan(*args, **kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "_run_active_scan", _fake_run_active_scan)

    rc = cli.main(["scan", "-u", "https://example.test/account", "--profile", "demo/admin", "--reflected"])

    assert rc == 0
    assert captured["auth_headers"]["Authorization"] == "Bearer abc"
    assert "Cookie" in captured["auth_headers"]

    store_after = load_auth_store()
    assert len(store_after["profiles"]) == 1
    assert store_after["profiles"][0]["name"] == "admin"


def test_validate_profile_marks_login_redirect_as_invalid() -> None:
    profile = AuthProfile(
        program="demo",
        name="admin",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer abc"},
    )

    validation = validate_profile(
        profile,
        fetcher=lambda url, headers: {
            "status_code": 200,
            "final_url": "https://example.test/login",
        },
    )

    assert validation.invalid is True
    assert validation.valid is False


def test_active_profile_matches_target_scope() -> None:
    store = {
        "active_profile": "demo/admin",
        "profiles": [AuthProfile(
            program="demo",
            name="admin",
            source_type="burp_request",
            base_url="https://example.test/account",
            domains=["example.test"],
            headers={"Authorization": "Bearer abc"},
        ).to_dict()],
    }

    profile, source = resolve_scan_profile(
        explicit_profile=None,
        target_url="https://api.example.test/v1/me",
        store=store,
    )

    assert profile is not None
    assert profile.ref == "demo/admin"
    assert source == "active"
    merged = merge_scan_auth_headers(profile=profile, extra_headers=["X-Test: 1"])
    assert merged["Authorization"] == "Bearer abc"
    assert merged["X-Test"] == "1"


def test_auth_list_prunes_invalid_profiles(tmp_path, monkeypatch, capsys) -> None:
    from ai_xss_generator.auth_cli import handle_auth_command

    auth_path = tmp_path / "auth_profiles.json"
    monkeypatch.setattr("ai_xss_generator.auth_profiles.AUTH_PROFILES_PATH", auth_path)
    monkeypatch.setattr("ai_xss_generator.auth_cli.AUTH_PROFILES_PATH", auth_path)

    upsert_profile(AuthProfile(
        program="demo",
        name="bad",
        source_type="burp_request",
        base_url="https://example.test/account",
        domains=["example.test"],
        headers={"Authorization": "Bearer dead"},
    ))

    monkeypatch.setattr(
        "ai_xss_generator.auth_cli.purge_invalid_profiles",
        lambda: (
            {"active_profile": "", "profiles": []},
            [(
                AuthProfile(
                    program="demo",
                    name="bad",
                    source_type="burp_request",
                    base_url="https://example.test/account",
                    domains=["example.test"],
                    headers={"Authorization": "Bearer dead"},
                ),
                SimpleNamespace(reason="Received HTTP 401."),
            )],
        ),
    )

    rc = handle_auth_command(["list"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "Removed expired auth profile demo/bad" in output


def test_auth_command_without_subcommand_opens_tui_when_interactive(monkeypatch) -> None:
    from ai_xss_generator.auth_cli import handle_auth_command

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("ai_xss_generator.auth_tui.run_auth_tui", lambda: 7)

    assert handle_auth_command([]) == 7


def test_auth_import_preview_only_prints_preview(tmp_path, monkeypatch, capsys) -> None:
    from ai_xss_generator.auth_cli import handle_auth_command

    auth_path = tmp_path / "auth_profiles.json"
    monkeypatch.setattr("ai_xss_generator.auth_profiles.AUTH_PROFILES_PATH", auth_path)
    monkeypatch.setattr("ai_xss_generator.auth_cli.AUTH_PROFILES_PATH", auth_path)
    request_path = tmp_path / "request.txt"
    request_path.write_text(
        "GET /account HTTP/2\nHost: example.test\nCookie: session=abc\n\n",
        encoding="utf-8",
    )

    rc = handle_auth_command([
        "import",
        str(request_path),
        "--program", "demo",
        "--profile", "admin",
        "--preview-only",
    ])

    assert rc == 0
    output = capsys.readouterr().out
    assert "Import preview for demo/admin" in output
    assert "cookies:  1" in output
    assert load_auth_store()["profiles"] == []
