"""
Minimal intentionally-vulnerable Flask server for axss end-to-end testing.

Endpoints
---------
GET  /reflected?q=<payload>        Reflects q directly into HTML body (no filter)
GET  /attr?name=<payload>          Reflects name into an HTML attribute value
GET  /js?data=<payload>            Reflects data into a JS string literal
POST /comment                      Accepts comment=<payload>, stores in memory, returns all stored comments
GET  /comments                     Shows all stored comments unescaped (stored XSS sink)
GET  /dom                          DOM XSS via location.hash → innerHTML
GET  /health                       Health check — returns 200 OK

USAGE
-----
    python3 tests/vuln_server.py          # listens on 127.0.0.1:7357

DO NOT expose this server to any network other than localhost.
"""

from __future__ import annotations

import sys
from flask import Flask, request, Response

app = Flask(__name__)
_stored_comments: list[str] = []


def _html(body: str, title: str = "Test") -> Response:
    return Response(
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body>{body}</body></html>",
        content_type="text/html; charset=utf-8",
    )


@app.get("/health")
def health():
    return "ok", 200


# ── Reflected XSS — raw reflection in HTML body ───────────────────────────────

@app.get("/reflected")
def reflected():
    q = request.args.get("q", "")
    return _html(
        f"<h1>Search results for: {q}</h1>"
        f"<p>No results found.</p>",
        title="Search",
    )


# ── Attribute XSS — reflection inside an HTML attribute ───────────────────────

@app.get("/attr")
def attr():
    name = request.args.get("name", "world")
    return _html(
        f'<h1>Hello</h1>'
        f'<div class="greeting" data-user="{name}">Welcome, {name}!</div>',
        title="Attribute",
    )


# ── JS context XSS — reflection inside a JS string ────────────────────────────

@app.get("/js")
def js_context():
    data = request.args.get("data", "")
    return _html(
        f"<h1>JS context</h1>"
        f"<script>var userInput = '{data}';</script>",
        title="JS Context",
    )


# ── Stored XSS — POST stores comment, GET shows all unescaped ─────────────────

@app.post("/comment")
def post_comment():
    comment = request.form.get("comment", "")
    if comment:
        _stored_comments.append(comment)
    return Response(
        "<!doctype html><html><body>"
        "<p>Comment saved! <a href='/comments'>View all comments</a></p>"
        "<form method='post' action='/comment'>"
        "<input name='comment' placeholder='Add comment'>"
        "<button type='submit'>Post</button>"
        "</form>"
        "</body></html>",
        content_type="text/html; charset=utf-8",
    )


@app.get("/comments")
def get_comments():
    items = "".join(f"<li>{c}</li>" for c in _stored_comments)
    return _html(
        f"<h1>Comments</h1><ul>{items or '<li>No comments yet</li>'}</ul>"
        "<form method='post' action='/comment'>"
        "<input name='comment' placeholder='Add comment'>"
        "<button type='submit'>Post</button>"
        "</form>",
        title="Comments",
    )


# ── DOM XSS — location.hash → innerHTML ───────────────────────────────────────

@app.get("/dom")
def dom_xss():
    return _html(
        "<h1>DOM XSS test</h1>"
        "<div id='output'></div>"
        "<script>"
        "  var hash = decodeURIComponent(window.location.hash.slice(1));"
        "  document.getElementById('output').innerHTML = hash;"
        "</script>",
        title="DOM XSS",
    )


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7357
    print(f"[vuln_server] listening on http://127.0.0.1:{port}")
    print("[vuln_server] endpoints: /reflected  /attr  /js  /comment  /comments  /dom  /health")
    app.run(host="127.0.0.1", port=port, debug=False)
