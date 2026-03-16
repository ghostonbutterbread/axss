"""Playwright stealth patches — reduces headless browser fingerprinting.

Applies a minimal set of in-page patches to make an automated Chromium
instance harder to fingerprint by WAF bot-detection scripts (Cloudflare,
DataDome, Kasada, PerimeterX, Akamai).
"""
from __future__ import annotations


def stealth_init_script() -> str:
    """Return a JS init script that patches the most-commonly-checked bot signals.

    Inject via page.add_init_script() *before* any navigation so patches
    take effect from the very first document evaluation.
    """
    return r"""
;(function () {
  'use strict';

  // 1. Remove navigator.webdriver — the most-checked automation signal
  try {
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
      configurable: true,
    });
  } catch (_) {}

  // 2. Restore window.chrome.runtime (missing in headless Chromium)
  try {
    if (!window.chrome) { window.chrome = {}; }
    if (!window.chrome.runtime) { window.chrome.runtime = {}; }
  } catch (_) {}

  // 3. Restore navigator.plugins (empty array is a reliable headless signal)
  try {
    var _pnames = ['Chrome PDF Plugin', 'Chrome PDF Viewer', 'Native Client'];
    var _plugins = _pnames.map(function (n) {
      return { name: n, filename: n.toLowerCase().replace(/ /g, '-'), description: '' };
    });
    _plugins.refresh    = function () {};
    _plugins.item       = function (i) { return _plugins[i]; };
    _plugins.namedItem  = function (n) { return _plugins.find(function (p) { return p.name === n; }); };
    Object.defineProperty(navigator, 'plugins', { get: function () { return _plugins; }, configurable: true });
  } catch (_) {}

  // 4. Restore navigator.languages (empty in some headless builds)
  try {
    Object.defineProperty(navigator, 'languages', {
      get: function () { return ['en-US', 'en']; },
      configurable: true,
    });
  } catch (_) {}

  // 5. Make Notification.permission return 'default' instead of 'denied'
  try {
    var _origPerms = window.navigator.permissions.query.bind(window.navigator.permissions);
    window.navigator.permissions.query = function (params) {
      if (params && params.name === 'notifications') {
        return Promise.resolve({ state: (typeof Notification !== 'undefined' && Notification.permission) || 'default' });
      }
      return _origPerms(params);
    };
  } catch (_) {}
})();
""".strip()


def stealth_launch_args() -> list[str]:
    """Extra Chromium flags that suppress automation-specific behaviour."""
    return [
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
    ]


def stealth_context_kwargs() -> dict:
    """Extra kwargs for browser.new_context() to appear more like a real user."""
    return {
        "viewport": {"width": 1366, "height": 768},
        "locale": "en-US",
        "timezone_id": "America/New_York",
    }
