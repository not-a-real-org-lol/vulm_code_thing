import os
import sys
import unittest
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


class TestScannerFunctions(unittest.TestCase):
    def test_sanitize_filename_normal(self):
        result = scanner_mod.sanitize_filename("camera_01")
        self.assertEqual(result, "camera_01")

    def test_sanitize_filename_path_traversal(self):
        result = scanner_mod.sanitize_filename("../../etc/passwd")
        self.assertEqual(result, "passwd")

    def test_sanitize_filename_special_chars(self):
        result = scanner_mod.sanitize_filename("cam:1/sub?stream=true&val=1")
        self.assertNotIn(":", result)
        self.assertNotIn("/", result)
        self.assertNotIn("?", result)
        self.assertNotIn("&", result)

    def test_sanitize_filename_empty(self):
        result = scanner_mod.sanitize_filename("")
        self.assertEqual(result, "unknown_stream")

    def test_is_valid_rtsp_url_valid(self):
        self.assertTrue(scanner_mod.is_valid_rtsp_url("rtsp://192.168.1.50:554/live"))
        self.assertTrue(scanner_mod.is_valid_rtsp_url("rtsps://camera.lan/stream1"))

    def test_is_valid_rtsp_url_invalid_schemes(self):
        self.assertFalse(scanner_mod.is_valid_rtsp_url("http://example.com/video"))
        self.assertFalse(scanner_mod.is_valid_rtsp_url("https://example.com/video"))
        self.assertFalse(scanner_mod.is_valid_rtsp_url("file:///etc/passwd"))

    def test_is_valid_rtsp_url_localhost_blocked(self):
        self.assertFalse(scanner_mod.is_valid_rtsp_url("rtsp://localhost:554/live"))
        self.assertFalse(scanner_mod.is_valid_rtsp_url("rtsp://127.0.0.1:554/live"))
        self.assertFalse(scanner_mod.is_valid_rtsp_url("rtsp://[::1]:554/live"))

    def test_is_valid_rtsp_url_empty_or_none(self):
        self.assertFalse(scanner_mod.is_valid_rtsp_url(""))
        self.assertFalse(scanner_mod.is_valid_rtsp_url(None))


if __name__ == "__main__":
    unittest.main()
