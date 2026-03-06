from __future__ import annotations

import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parent.parent


class _FixtureHandler(BaseHTTPRequestHandler):
    pages = {
        "/one": """<!doctype html>
<html>
  <head><title>One</title></head>
  <body>
    <form action="/submit" method="post">
      <input name="q" id="q">
    </form>
    <script>eval(location.hash.slice(1))</script>
  </body>
</html>
""",
        "/two": """<!doctype html>
<html>
  <head><title>Two</title></head>
  <body data-reactroot="1">
    <div onclick="run()"></div>
    <script>document.body.innerHTML = location.search.slice(1)</script>
  </body>
</html>
""",
    }

    def do_GET(self) -> None:  # noqa: N802
        body = self.pages.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


@unittest.skipUnless(importlib.util.find_spec("scrapy") is not None, "Scrapy not installed")
class CliBatchUrlsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            host, port = sock.getsockname()
        cls.server = ThreadingHTTPServer((host, port), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _run_axss(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.setdefault("OLLAMA_HOST", "http://127.0.0.1:9")
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(
            [sys.executable, "axss.py", *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_single_url_json_output(self) -> None:
        result = self._run_axss("-u", f"{self.base_url}/one", "-o", "json", "-t", "3")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        json_start = result.stdout.find("{")
        self.assertNotEqual(json_start, -1, msg=result.stdout)
        payload = json.loads(result.stdout[json_start:])
        self.assertEqual(payload["context"]["source"], f"{self.base_url}/one")
        self.assertEqual(payload["context"]["title"], "One")
        self.assertGreaterEqual(len(payload["payloads"]), 1)

    def test_batch_urls_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            url_file = Path(tmpdir) / "urls.txt"
            url_file.write_text(
                f"{self.base_url}/one\n{self.base_url}/two\n",
                encoding="utf-8",
            )
            result = self._run_axss("--urls", str(url_file), "-o", "json", "-t", "2")

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["results"][0]["context"]["source"], f"{self.base_url}/one")
        self.assertEqual(payload["results"][1]["context"]["source"], f"{self.base_url}/two")
        self.assertIn("React", payload["results"][1]["context"]["frameworks"])
        self.assertGreaterEqual(len(payload["results"][0]["payloads"]), 1)


if __name__ == "__main__":
    unittest.main()
