#!/usr/bin/env python3
"""Submit HoneyPot public URLs to IndexNow for faster crawler discovery.

Usage:
  python scripts/ping_indexing.py --base-url https://your-domain.example --key YOUR_INDEXNOW_KEY

The key must also be publicly reachable at:
  https://your-domain.example/indexnow-key.txt
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

DEFAULT_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api/meta",
    "/api/docs",
    "/swagger.json",
]


def normalized_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("base URL must be an absolute http(s) URL")
    return value.rstrip("/")


def build_urls(base_url: str, paths: list[str]) -> list[str]:
    return [urljoin(base_url + "/", path.lstrip("/")) for path in paths]


def submit_indexnow(base_url: str, key: str, paths: list[str], dry_run: bool = False) -> int:
    host = urlparse(base_url).netloc
    urls = build_urls(base_url, paths)
    payload = {
        "host": host,
        "key": key,
        "keyLocation": urljoin(base_url + "/", "indexnow-key.txt"),
        "urlList": urls,
    }
    body = json.dumps(payload).encode("utf-8")
    if dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    request = urllib.request.Request(
        "https://api.indexnow.org/indexnow",
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            print(f"IndexNow accepted {len(urls)} URLs with HTTP {response.status}")
            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"IndexNow HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"IndexNow request failed: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit HoneyPot public URLs to IndexNow.")
    parser.add_argument("--base-url", required=True, type=normalized_base_url, help="Public HTTPS origin, e.g. https://honeypot.example.com")
    parser.add_argument("--key", required=True, help="IndexNow key configured as HONEYPOT_INDEXNOW_KEY")
    parser.add_argument("--path", action="append", dest="paths", help="Extra path to submit; can be repeated")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without sending")
    args = parser.parse_args()

    paths = DEFAULT_PATHS + (args.paths or [])
    return submit_indexnow(args.base_url, args.key.strip(), paths, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
