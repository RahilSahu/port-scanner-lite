import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from port_scan import check_port, parse_ports, scan


class ParsePortsTests(unittest.TestCase):
    def test_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_mixed_and_deduped(self):
        self.assertEqual(parse_ports("80, 79-81"), [79, 80, 81])

    def test_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(5)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"TestBanner/1.0\r\n")

    def tearDown(self):
        self.server.close()

    def test_open_port_is_found_with_banner(self):
        result = check_port("127.0.0.1", self.port, timeout=2.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "TestBanner/1.0")

    def test_closed_port_returns_none(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        self.assertIsNone(check_port("127.0.0.1", closed_port, timeout=1.0))

    def test_scan_returns_sorted_open_ports(self):
        results = scan("127.0.0.1", [self.port], timeout=2.0)
        self.assertEqual([r.port for r in results], [self.port])


if __name__ == "__main__":
    unittest.main()
