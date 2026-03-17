from __future__ import annotations

from types import SimpleNamespace

from ai_xss_generator.browser_crawler import _process_raw_forms
from ai_xss_generator.crawler import _extract_links
from ai_xss_generator.session import compute_seed_hash
from ai_xss_generator.types import PostFormTarget, UploadTarget


def test_browser_process_raw_forms_discovers_upload_targets() -> None:
    seen_post_keys: set[str] = set()
    post_forms: list[PostFormTarget] = []
    upload_targets: list[UploadTarget] = []

    _process_raw_forms(
        raw_forms=[{
            "action": "/profile/avatar",
            "method": "POST",
            "enctype": "multipart/form-data",
            "fields": [
                ["_csrf", "hidden", "token123"],
                ["avatar", "file", ""],
                ["displayName", "text", ""],
            ],
        }],
        final_url="https://example.test/account",
        seen_post_keys=seen_post_keys,
        post_forms=post_forms,
        upload_targets=upload_targets,
    )

    assert len(upload_targets) == 1
    assert upload_targets[0].action_url == "https://example.test/profile/avatar"
    assert upload_targets[0].file_field_names == ["avatar"]
    assert upload_targets[0].companion_field_names == ["displayName"]
    assert upload_targets[0].csrf_field == "_csrf"

    assert len(post_forms) == 1
    assert post_forms[0].param_names == ["displayName"]


def test_http_crawler_preserves_real_file_field_names() -> None:
    _, raw_forms = _extract_links(
        """
        <form action="/profile/avatar" method="post" enctype="multipart/form-data">
          <input type="hidden" name="_csrf" value="token123">
          <input type="file" name="avatar">
          <input type="text" name="displayName">
        </form>
        """,
        "https://example.test/account",
    )

    assert len(raw_forms) == 1
    assert ("avatar", "file", "") in raw_forms[0]["fields"]


def test_seed_hash_includes_upload_targets() -> None:
    base = compute_seed_hash(
        urls=["https://example.test/account"],
        post_forms=[],
        upload_targets=[],
        scan_reflected=False,
        scan_stored=True,
        scan_uploads=False,
        scan_dom=False,
    )
    upload_hash = compute_seed_hash(
        urls=["https://example.test/account"],
        post_forms=[],
        upload_targets=[UploadTarget(
            action_url="https://example.test/upload",
            source_page_url="https://example.test/account",
            file_field_names=["avatar"],
            companion_field_names=["displayName"],
            csrf_field=None,
            hidden_defaults={},
        )],
        scan_reflected=False,
        scan_stored=True,
        scan_uploads=True,
        scan_dom=False,
    )

    assert base != upload_hash


def test_run_upload_worker_confirms_when_executor_fires(monkeypatch) -> None:
    from ai_xss_generator.active.worker import _run_upload
    from ai_xss_generator.active.executor import ExecutionResult

    class FakeExecutor:
        def __init__(self, auth_headers=None):
            self.auth_headers = auth_headers

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

        def fire_upload(self, **kwargs):
            return ExecutionResult(
                confirmed=True,
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["file_name"],
                param_name=kwargs["file_field_names"][0],
                fired_url=kwargs["source_page_url"],
            )

    monkeypatch.setattr("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor)

    collected = []
    _run_upload(
        upload_target=UploadTarget(
            action_url="https://example.test/upload",
            source_page_url="https://example.test/account/avatar",
            file_field_names=["avatar"],
            companion_field_names=["displayName"],
            csrf_field=None,
            hidden_defaults={},
        ),
        waf_hint="akamai",
        timeout_seconds=30,
        put_result=collected.append,
        auth_headers={"Authorization": "Bearer token"},
        sink_url="https://example.test/profile/avatar",
    )

    assert len(collected) == 1
    result = collected[0]
    assert result.status == "confirmed"
    assert result.kind == "upload"
    assert result.target_tier == "high_value"
    assert result.fallback_rounds == 1
    assert result.confirmed_findings[0].context_type == "stored_upload"
    assert result.confirmed_findings[0].sink_context == "upload_render"


def test_upload_only_batch_mode_crawls_each_seed(monkeypatch, tmp_path) -> None:
    from ai_xss_generator import cli
    from ai_xss_generator.crawler import CrawlResult

    seeds = [
        "https://example.test/account",
        "https://example.test/profile",
    ]
    url_file = tmp_path / "urls.txt"
    url_file.write_text("\n".join(seeds), encoding="utf-8")

    crawled: list[str] = []
    captured: dict[str, object] = {}

    def _fake_crawl(url, **kwargs):
        crawled.append(url)
        slug = url.rsplit("/", 1)[-1]
        return CrawlResult(
            get_urls=[],
            post_forms=[],
            upload_targets=[UploadTarget(
                action_url=f"{url}/upload",
                source_page_url=url,
                file_field_names=[f"{slug}File"],
                companion_field_names=["displayName"],
                csrf_field=None,
                hidden_defaults={},
            )],
            visited_urls=[url],
            detected_waf=None,
        )

    def _fake_run_active_scan(urls, scan_config, **kwargs):
        captured["urls"] = list(urls)
        captured["scan_uploads"] = scan_config.scan_uploads
        captured["scan_stored"] = scan_config.scan_stored
        captured["upload_targets"] = list(kwargs.get("upload_targets", []))
        return []

    monkeypatch.setattr("ai_xss_generator.cli.resolve_ai_config", lambda config, args=None: SimpleNamespace(
        model="qwen3.5:9b",
        cloud_model="anthropic/claude-3-5-sonnet",
        use_cloud=False,
        ai_backend="api",
        cli_tool="claude",
        cli_model=None,
    ))
    monkeypatch.setattr("ai_xss_generator.parser.read_url_list", lambda path: seeds)
    monkeypatch.setattr("ai_xss_generator.crawler.crawl", _fake_crawl)
    monkeypatch.setattr("ai_xss_generator.cli._resolve_session", lambda **kwargs: None)
    monkeypatch.setattr("ai_xss_generator.active.orchestrator.run_active_scan", _fake_run_active_scan)
    monkeypatch.setattr("ai_xss_generator.active.reporter.write_report", lambda *args, **kwargs: "/tmp/report.md")

    args = SimpleNamespace(
        urls=str(url_file),
        url=None,
        rate=5.0,
        depth=1,
        browser_crawl=False,
        no_crawl=False,
        verbose=0,
        workers=1,
        timeout=300,
        json_out=None,
        sink_url=None,
        attempts=1,
        header=[],
        headers=[],
        cookies=None,
        resume=False,
    )

    rc = cli._run_active_scan(
        args=args,
        config=SimpleNamespace(),
        resolved_waf=None,
        auth_headers=None,
        scan_reflected=False,
        scan_stored=False,
        scan_uploads=True,
        scan_dom=False,
    )

    assert rc == 0
    assert crawled == seeds
    assert captured["urls"] == seeds
    assert captured["scan_uploads"] is True
    assert captured["scan_stored"] is False
    assert len(captured["upload_targets"]) == 2
