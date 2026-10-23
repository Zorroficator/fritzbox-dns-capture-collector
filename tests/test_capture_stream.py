import http.client
import socket
import threading
import time
import unittest

import helpers as h
import capture

HDR = b"HTTP/1.0 200 OK\r\n\r\n"


def make(idle=30):
    a, b = socket.socketpair()
    resp = http.client.HTTPResponse(b)
    c = capture.Capture("http://fritz.box", idle_timeout=idle)
    return a, b, resp, c


class StreamTests(unittest.TestCase):
    def _wire(self, c, resp, sock):
        resp.begin()
        c._resp, c._sock = resp, sock
        c.status = resp.status

    def test_pause_longer_than_poll_no_error(self):
        a, b, resp, c = make()
        a.sendall(HDR + h.pcap_global())
        self._wire(c, resp, b)
        got = []
        def writer():
            time.sleep(0.3)
            a.sendall(b"second-chunk")
            time.sleep(0.2)
            a.close()
        t = threading.Thread(target=writer); t.start()
        for ch in c.chunks():
            got.append(ch)
        t.join()
        self.assertEqual(b"".join(got), h.pcap_global() + b"second-chunk")
        self.assertEqual(c.first_bytes, h.pcap_global()[:16])

    def test_abort_is_normal_end(self):
        a, b, resp, c = make()
        a.sendall(HDR + h.pcap_global())
        self._wire(c, resp, b)
        threading.Timer(0.3, c.abort).start()
        got = list(c.chunks())
        self.assertEqual(b"".join(got), h.pcap_global())
        a.close()

    def test_not_pcap(self):
        a, b, resp, c = make()
        a.sendall(HDR + b"<html>Login</html>")
        self._wire(c, resp, b)
        with self.assertRaises(capture.CaptureError):
            list(c.chunks())
        self.assertEqual(c.first_bytes, b"<html>Login</html>"[:16])
        a.close()

    def test_empty_stream(self):
        a, b, resp, c = make()
        a.sendall(HDR)
        a.close()
        self._wire(c, resp, b)
        with self.assertRaises(capture.CaptureError) as cm:
            list(c.chunks())
        self.assertIn("another capture", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
