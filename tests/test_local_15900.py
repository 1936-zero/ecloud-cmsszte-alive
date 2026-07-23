"""Unit tests for l3.local_15900 — framing, HEART no-reply, PORT++.

No live VDI required.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
import unittest

from l3.local_15900 import (
    DEFAULT_PORT,
    MIN_WIRE_LEN,
    MsgType,
    bind_port_with_increment,
    decode_msg,
    encode_app_message,
    encode_msg,
    handle_received_type,
    Local15900Server,
    parse_inner,
    should_auto_reply,
)
from l3.path_a_session import PathASession


class EncodeDecodeTests(unittest.TestCase):
    def test_plain_json_roundtrip_protocol_vector(self):
        # protocol §2.3: EncodeMsg(utf8('{"type":1,"timestamp":1}'))
        payload = b'{"type":1,"timestamp":1}'
        wire = encode_msg(payload)
        self.assertEqual(
            wire.hex(),
            "7b2274797065223a312c2274696d657374616d70223a317d0d",
        )
        msgs = decode_msg(wire)
        self.assertEqual(msgs, [payload])

    def test_escape_vector_0d_0e(self):
        # protocol §2.3: EncodeMsg([0x0d,0x0e,0x01,0x0d])
        payload = bytes([0x0D, 0x0E, 0x01, 0x0D])
        wire = encode_msg(payload)
        self.assertEqual(
            list(wire),
            [0x0E, 0x02, 0x0E, 0x01, 0x01, 0x0E, 0x02, 0x0D],
        )
        self.assertEqual(decode_msg(wire), [payload])

    def test_multi_frame_in_one_chunk(self):
        a = encode_msg(b"AAA")
        b = encode_msg(b"BBB")
        msgs = decode_msg(a + b)
        self.assertEqual(msgs, [b"AAA", b"BBB"])

    def test_app_message_inner_layout(self):
        wire = encode_app_message(MsgType.COMMAND_HEART_BEAT, "m1", "CMSSZTE", {"t": 1})
        inner = decode_msg(wire)[0]
        msg_type, jlen = struct.unpack_from("<II", inner, 0)
        self.assertEqual(msg_type, 1)
        body = inner[8 : 8 + jlen]
        self.assertIn(b"CMSSZTE", body)
        parsed = parse_inner(inner)
        self.assertEqual(parsed.msg_type, 1)
        self.assertEqual(parsed.machine_id, "m1")
        self.assertEqual(parsed.company_code, "CMSSZTE")
        self.assertEqual(parsed.data, {"t": 1})


class HeartPolicyTests(unittest.TestCase):
    def test_should_not_auto_reply_heart(self):
        self.assertFalse(should_auto_reply(MsgType.COMMAND_HEART_BEAT))
        self.assertEqual(handle_received_type(1), "ignore_no_reply")

    def test_server_ignores_heart_no_write_back(self):
        srv = Local15900Server(start_port=25900)
        port = srv.start()
        self.addCleanup(srv.stop)

        wire = encode_app_message(1, "desk-1", "CMSSZTE", None)
        # Peer that records any bytes written back by server
        replies = bytearray()

        def client():
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.settimeout(0.8)
            s.sendall(wire)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    replies.extend(chunk)
            except socket.timeout:
                pass
            s.close()

        t = threading.Thread(target=client)
        t.start()
        t.join(timeout=3)
        # allow server to process
        time.sleep(0.1)

        self.assertGreaterEqual(srv.heartbeats_ignored, 1)
        self.assertEqual(srv.auto_replies_sent, 0)
        self.assertEqual(bytes(replies), b"")
        self.assertTrue(any(m.msg_type == 1 for m in srv.received))


class PortIncrementTests(unittest.TestCase):
    def test_port_plus_plus_on_inuse(self):
        # occupy a free high port then bind_port_with_increment must bump
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        occupied = holder.getsockname()[1]
        holder.listen(1)
        self.addCleanup(holder.close)

        result = bind_port_with_increment("127.0.0.1", occupied, max_tries=8)
        self.addCleanup(result.sock.close)
        self.assertGreater(result.port, occupied)
        self.assertEqual(result.host, "127.0.0.1")

    def test_server_start_reports_actual_port(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        occupied = holder.getsockname()[1]
        holder.listen(1)
        self.addCleanup(holder.close)

        srv = Local15900Server(start_port=occupied)
        port = srv.start()
        self.addCleanup(srv.stop)
        self.assertNotEqual(port, occupied)
        self.assertEqual(srv.port, port)


class PathASessionSkeletonTests(unittest.TestCase):
    def test_prepare_binds_and_exposes_socket_port(self):
        sess = PathASession(origin_company_code="CMSSZTE", machine_id="inst-1")
        port = sess.prepare()
        self.addCleanup(sess.stop)
        self.assertIsInstance(port, int)
        self.assertGreaterEqual(port, DEFAULT_PORT)
        fields = sess.connect_json_socket_fields()
        self.assertEqual(fields["socketPort"], str(port))
        self.assertEqual(fields["socketHost"], "127.0.0.1")
        self.assertFalse(sess.notes.get("heart_auto_reply"))

    def test_min_wire_gate_constant(self):
        self.assertEqual(MIN_WIRE_LEN, 0x18)


if __name__ == "__main__":
    unittest.main()
