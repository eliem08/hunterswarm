"""Tests for hunterswarm. All network access is mocked — no real requests."""

import io
import json
import unittest
from unittest.mock import patch

from hunterswarm import recon, fingerprint, surface, checks, report


class FakeHeaders(dict):
    def items(self):
        return super().items()


class FakeResponse:
    """Minimal urlopen stand-in: context manager with status/headers/read."""

    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = FakeHeaders(headers or {})
        self._body = body

    def read(self, n=-1):
        if n is None or n < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _no_sleep():
    return None


class ReconTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(recon, "POLITE_DELAY", 0)
        p.start()
        self.addCleanup(p.stop)

    def test_enumerate_subdomains_parses_crtsh(self):
        payload = json.dumps([
            {"name_value": "www.example.com\nexample.com"},
            {"name_value": "*.api.example.com"},
            {"name_value": "mail.other.com"},
        ]).encode()
        with patch.object(
            recon.urllib.request, "urlopen", return_value=FakeResponse(200, {}, payload)
        ):
            subs = recon.enumerate_subdomains("example.com")
        self.assertEqual(subs, ["api.example.com", "www.example.com"])

    def test_enumerate_subdomains_failure_returns_empty(self):
        with patch.object(
            recon.urllib.request, "urlopen", side_effect=Exception("down")
        ):
            self.assertEqual(recon.enumerate_subdomains("example.com"), [])

    def test_resolve_dns(self):
        fake = [(2, 1, 6, "", ("93.184.216.34", 443)),
                (10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0))]
        with patch.object(recon.socket, "getaddrinfo", return_value=fake):
            ips = recon.resolve_dns("example.com")
        self.assertIn("93.184.216.34", ips)
        self.assertEqual(len(ips), 2)

    def test_resolve_dns_failure(self):
        with patch.object(recon.socket, "getaddrinfo",
                          side_effect=recon.socket.gaierror("nope")):
            self.assertEqual(recon.resolve_dns("example.com"), [])

    def test_extract_js_urls(self):
        html = ('<script src="/app.js"></script>'
                '<script src="https://cdn.x/y.js"></script>'
                '<script src="data:text/javascript,1"></script>')
        urls = recon.extract_js_urls("https://example.com/", html)
        self.assertEqual(urls, ["https://example.com/app.js",
                                "https://cdn.x/y.js"])

    def test_parse_sitemap_urls(self):
        xml = ("<urlset><url><loc>https://a.test/1</loc></url>"
               "<url><loc> https://a.test/2 </loc></url></urlset>")
        self.assertEqual(recon.parse_sitemap_urls(xml),
                         ["https://a.test/1", "https://a.test/2"])

    def test_run_recon_orchestrates(self):
        with patch.object(recon, "enumerate_subdomains", return_value=["a.example.com"]), \
             patch.object(recon, "resolve_dns", return_value=["1.2.3.4"]), \
             patch.object(recon, "fetch_homepage",
                          return_value=(200, {"server": "nginx"}, "<html></html>")), \
             patch.object(recon, "fetch_robots_txt", return_value="User-agent: *"), \
             patch.object(recon, "fetch_sitemap_urls", return_value=[]):
            data = recon.run_recon("example.com")
        self.assertEqual(data["subdomains"], ["a.example.com"])
        self.assertEqual(data["ips"], ["1.2.3.4"])
        self.assertEqual(data["homepage_status"], 200)


class FingerprintTests(unittest.TestCase):
    def test_header_and_html_sigs(self):
        techs = fingerprint.fingerprint(
            {"Server": "nginx", "X-Powered-By": "Express"},
            '<html><body><div id="__NEXT_DATA__"></div></body></html>',
        )
        self.assertIn("nginx", techs)
        self.assertIn("Express.js", techs)
        self.assertIn("Next.js", techs)

    def test_wordpress(self):
        techs = fingerprint.fingerprint({}, '<link href="/wp-content/x.css">')
        self.assertIn("WordPress", techs)

    def test_empty(self):
        self.assertEqual(fingerprint.fingerprint({}, "<html></html>"), [])


class SurfaceTests(unittest.TestCase):
    def test_extract_api_paths(self):
        js = '''
          fetch("/api/v1/users");
          axios.post('/rest/orders', {});
          const g = "/graphql";
          var x = "not a path";
          fetch("https://api.other.com/v2/things");
        '''
        paths = surface.extract_api_paths(js)
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/rest/orders", paths)
        self.assertIn("/graphql", paths)
        self.assertIn("https://api.other.com/v2/things", paths)
        self.assertNotIn("not a path", paths)

    def test_discover_common_paths_records_status(self):
        def fake_get(url, timeout=10):
            if url.endswith("/.git/HEAD"):
                return 200, {}, b"ref: refs/heads/main\n"
            if url.endswith("security.txt"):
                return 404, {}, b""
            return 404, {}, b""
        with patch.object(surface, "http_get", side_effect=fake_get):
            out = surface.discover_common_paths("example.com")
        by_path = {e["path"]: e for e in out}
        self.assertEqual(len(out), 5)
        self.assertTrue(by_path["/.git/HEAD"]["looks_like_git"])
        self.assertEqual(by_path["/.well-known/security.txt"]["status"], 404)

    def test_fetch_js_files_respects_limit(self):
        calls = []

        def fake_capped(url, max_bytes=200_000, timeout=10):
            calls.append(url)
            return 200, {}, b"var a=1;"

        with patch.object(surface, "http_get_capped", side_effect=fake_capped):
            out = surface.fetch_js_files(["u1", "u2", "u3"], limit=2)
        self.assertEqual(len(out), 2)
        self.assertEqual(len(calls), 2)


class ChecksTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(checks, "_polite_sleep", _no_sleep)
        p.start()
        self.addCleanup(p.stop)
        p2 = patch.object(recon, "POLITE_DELAY", 0)
        p2.start()
        self.addCleanup(p2.stop)

    def test_missing_headers(self):
        findings = checks.check_security_headers("example.com", {"server": "x"})
        ids = {f["id"] for f in findings}
        self.assertIn("missing-content-security-policy", ids)
        self.assertIn("missing-strict-transport-security", ids)
        self.assertTrue(all(f["severity"] in ("info", "low") for f in findings))

    def test_no_missing_headers_when_present(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=1",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
        self.assertEqual(checks.check_security_headers("example.com", headers), [])

    def test_exposed_git(self):
        common = [{"path": "/.git/HEAD", "status": 200, "looks_like_git": True,
                   "url": "https://example.com/.git/HEAD"}]
        findings = checks.check_exposed_git("example.com", common)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_verbose_error_page(self):
        body = b"<html><body><pre>Traceback (most recent call last):\n  File x</pre></body></html>"
        with patch.object(checks, "http_get", return_value=(500, {}, body)):
            findings = checks.check_verbose_errors("example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "verbose-error-page")

    def test_quiet_error_page(self):
        with patch.object(checks, "http_get", return_value=(404, {}, b"<h1>Not found</h1>")):
            self.assertEqual(checks.check_verbose_errors("example.com"), [])

    def test_cors_reflect_with_credentials(self):
        resp = FakeResponse(200, {
            "Access-Control-Allow-Origin": "https://hunterswarm-probe.invalid",
            "Access-Control-Allow-Credentials": "true",
        }, b"")
        with patch.object(checks.urllib.request, "urlopen", return_value=resp):
            findings = checks.check_cors("example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "cors-arbitrary-origin-credentials")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_cors_wildcard(self):
        resp = FakeResponse(200, {"Access-Control-Allow-Origin": "*"}, b"")
        with patch.object(checks.urllib.request, "urlopen", return_value=resp):
            findings = checks.check_cors("example.com")
        self.assertEqual(findings[0]["id"], "cors-wildcard")

    def test_security_txt_present(self):
        common = [{"path": "/.well-known/security.txt", "status": 200,
                   "url": "https://example.com/.well-known/security.txt"}]
        findings = checks.check_security_txt("example.com", common)
        self.assertEqual(findings[0]["id"], "security-txt-present")


class ReportTests(unittest.TestCase):
    def test_banner_and_structure(self):
        recon_data = {
            "domain": "example.com",
            "subdomains": ["a.example.com"],
            "ips": ["1.2.3.4"],
            "technologies": ["nginx"],
            "api_paths": ["/api/x"],
            "common_paths": [{"path": "/.git/HEAD", "status": 404,
                              "url": "https://example.com/.git/HEAD"}],
            "js_urls": [],
            "robots_txt": None,
            "sitemap_urls": [],
            "homepage_status": 200,
        }
        findings = [{
            "id": "missing-x-frame-options", "severity": "info",
            "title": "Missing X-Frame-Options header",
            "asset": "https://example.com/",
            "evidence": "header absent", "impact": "framing",
            "remediation": "set header",
        }]
        md = report.generate_report("example.com", recon_data, findings)
        self.assertIn("DRAFT — human verification required", md)
        self.assertIn("### 1. [INFO] Missing X-Frame-Options header", md)
        self.assertIn("a.example.com", md)
        self.assertIn("/api/x", md)
        self.assertIn("passive", md.lower())

    def test_no_findings_message(self):
        md = report.generate_report("example.com", {}, [])
        self.assertIn("No passive findings", md)

    def test_sample_findings_json_renders(self):
        import os
        sample = os.path.join(os.path.dirname(__file__), "..",
                              "examples", "sample-findings.json")
        with open(sample, encoding="utf-8") as fh:
            data = json.load(fh)
        md = report.generate_report(data["domain"], data["recon"], data["findings"])
        self.assertIn("demo-target.test", md)
        self.assertIn("DRAFT", md)


class CliTests(unittest.TestCase):
    def test_rejects_bad_domain(self):
        from hunterswarm.cli import cmd_recon
        import argparse
        args = argparse.Namespace(domain="not a domain!!", output=None,
                                  max_subdomains=50, save_json=None)
        self.assertEqual(cmd_recon(args), 2)


if __name__ == "__main__":
    unittest.main()
