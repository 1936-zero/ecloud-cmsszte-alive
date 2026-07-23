"""Path A session integration: sim TCP client (no live VDI).

Proves Local15900Server + PathASession control-plane loop:
- sim client connects to session-bound socketPort
- sends EncodeMsg HEART(type=1) and a non-HEART frame
- HEART → ignore, no auto-reply
- non-HEART → received/handled without crash
- optional PORT++ when start_port is occupied
"""

from __future__ import annotations

import socket
import time
import unittest
from typing import List, Optional

from l3.local_15900 import (
    DEFAULT_PORT,
    MsgType,
    encode_app_message,
)
from unittest.mock import MagicMock

from l3.path_a_session import PathASession, dry_run_pipeline, live_pipeline
from l3.rsa_connect import DRY_STUB_PREFIX
from l3.vdi_launcher import LiveLaunchDenied, REDACTED


MACHINE_ID = "sim-machine-1"
COMPANY = "CMSSZTE"


def _wait_until(pred, timeout: float = 2.0, interval: float = 0.02) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return False


def _sim_client_send(host: str, port: int, frames: List[bytes], collect_replies: bool = True) -> bytes:
    """Connect as pseudo-VDI, send frames, optionally drain any server replies."""
    replies = bytearray()
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.settimeout(0.4)
        for frame in frames:
            sock.sendall(frame)
        if collect_replies:
            # give server a beat to (not) reply
            end = time.time() + 0.5
            while time.time() < end:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                replies.extend(chunk)
    return bytes(replies)


class PathASessionIntegrationTests(unittest.TestCase):
    def test_sim_client_heart_and_nonheart(self):
        handled: List[int] = []

        sess = PathASession(
            origin_company_code=COMPANY,
            machine_id=MACHINE_ID,
            start_port=DEFAULT_PORT,
        )
        port = sess.prepare()
        self.addCleanup(sess.stop)
        self.assertIsInstance(port, int)
        self.assertIsNotNone(sess.server)
        assert sess.server is not None

        # install app_handler for non-HEART observability
        sess.server.app_handler = lambda msg: handled.append(msg.msg_type)

        fields = sess.connect_json_socket_fields()
        self.assertEqual(fields["socketPort"], str(port))
        self.assertEqual(fields["socketHost"], "127.0.0.1")

        heart = encode_app_message(
            MsgType.COMMAND_HEART_BEAT, MACHINE_ID, COMPANY, {"t": 1}
        )
        non_heart = encode_app_message(
            MsgType.COMMAND_CLIENT_CONNECTED_NOTIFICATION,
            MACHINE_ID,
            COMPANY,
            {"state": "connected"},
        )

        replies = _sim_client_send("127.0.0.1", port, [heart, non_heart])

        ok = _wait_until(
            lambda: (
                sess.server is not None
                and any(m.msg_type == MsgType.COMMAND_HEART_BEAT for m in sess.server.received)
                and any(
                    m.msg_type == MsgType.COMMAND_CLIENT_CONNECTED_NOTIFICATION
                    for m in sess.server.received
                )
            )
        )
        self.assertTrue(ok, "server did not receive HEART + non-HEART frames in time")

        assert sess.server is not None
        self.assertGreaterEqual(sess.server.heartbeats_ignored, 1)
        self.assertEqual(sess.server.auto_replies_sent, 0)
        self.assertEqual(replies, b"", "HEART must not elicit auto-reply bytes")
        self.assertFalse(sess.notes.get("heart_auto_reply"))

        # non-HEART logged/handled
        self.assertIn(MsgType.COMMAND_CLIENT_CONNECTED_NOTIFICATION, handled)
        non_heart_msgs = [
            m
            for m in sess.server.received
            if m.msg_type == MsgType.COMMAND_CLIENT_CONNECTED_NOTIFICATION
        ]
        self.assertEqual(non_heart_msgs[0].machine_id, MACHINE_ID)
        self.assertEqual(non_heart_msgs[0].company_code, COMPANY)

    def test_session_port_plus_plus_when_occupied(self):
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        occupied = holder.getsockname()[1]
        holder.listen(1)
        self.addCleanup(holder.close)

        sess = PathASession(
            origin_company_code=COMPANY,
            machine_id="sim-port-bump",
            start_port=occupied,
        )
        port = sess.prepare()
        self.addCleanup(sess.stop)
        self.assertNotEqual(port, occupied)
        self.assertGreater(port, occupied)
        fields = sess.connect_json_socket_fields()
        self.assertEqual(fields["socketPort"], str(port))

        # still accept a HEART after PORT++
        heart = encode_app_message(
            MsgType.COMMAND_HEART_BEAT, "sim-port-bump", COMPANY, None
        )
        replies = _sim_client_send("127.0.0.1", port, [heart])
        ok = _wait_until(
            lambda: sess.server is not None and sess.server.heartbeats_ignored >= 1
        )
        self.assertTrue(ok)
        assert sess.server is not None
        self.assertEqual(sess.server.auto_replies_sent, 0)
        self.assertEqual(replies, b"")

    def test_prepare_desktop_dict_resolves_cmsszte(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "instanceId": "desk-99",
            "machineId": "desk-99",
        }
        sess = PathASession(origin_company_code="", machine_id="")
        port = sess.prepare(desktop=desktop)
        self.addCleanup(sess.stop)
        self.assertEqual(sess.machine_id, "desk-99")
        self.assertIsNotNone(sess.vendor)
        assert sess.vendor is not None
        self.assertEqual(sess.vendor.vendor_id, "CMSSZTE")
        self.assertEqual(sess.connect_json_socket_fields()["socketPort"], str(port))

    def test_dry_run_pipeline_full_wire(self):
        """prepare → connect_schema → rsa(dry) → vdi_launcher(dry); HEART still swallows."""
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "instanceId": "pipe-m1",
            "machineId": "pipe-m1",
            "desktopname": "demo",
            "serverIp": "10.0.0.2",
            "serverPort": 443,
        }
        sess = PathASession(
            origin_company_code="CMSSZTE",
            machine_id="pipe-m1",
            start_port=27900,
        )
        plan = sess.dry_run_pipeline(desktop=desktop, rsa_dry_run=True)
        self.addCleanup(sess.stop)

        self.assertEqual(plan["stage"], "dry_run_pipeline")
        self.assertEqual(plan["vendor_id"], "CMSSZTE")
        self.assertFalse(plan["live_vdi"])
        self.assertFalse(plan["heart_auto_reply"])
        self.assertEqual(plan["socketPort"], sess.socket_port)
        self.assertEqual(
            plan["plain_redacted"]["socketPort"], str(sess.socket_port)
        )
        self.assertTrue(plan["rsa"]["cipher_is_stub"])
        self.assertEqual(plan["rsa"]["cipher_display"], REDACTED)
        self.assertEqual(plan["rsa"]["stub_prefix"], DRY_STUB_PREFIX)
        # argv redacted; no live launch
        self.assertIn(REDACTED, plan["argv_display"])
        self.assertTrue(any("--json" in a or a == "--json" for a in plan["argv_display"]))
        # full cipher body must not appear in argv_display
        for a in plan["argv_display"]:
            self.assertFalse(str(a).startswith(DRY_STUB_PREFIX))
        # pubkey slot logical only
        self.assertIn("publicKey", plan["pubkey_slot"])
        # server still accepts HEART with no reply
        assert sess.server is not None
        heart = encode_app_message(
            MsgType.COMMAND_HEART_BEAT, "pipe-m1", COMPANY, None
        )
        replies = _sim_client_send("127.0.0.1", sess.socket_port, [heart])
        ok = _wait_until(
            lambda: sess.server is not None and sess.server.heartbeats_ignored >= 1
        )
        self.assertTrue(ok)
        self.assertEqual(sess.server.auto_replies_sent, 0)
        self.assertEqual(replies, b"")
        self.assertIs(sess.last_plan, plan)

    def test_module_dry_run_pipeline_stops(self):
        desktop = {
            "originCompanyCode": "CMSSZTE",
            "instanceId": "one-shot",
            "machineId": "one-shot",
        }
        plan = dry_run_pipeline(
            "CMSSZTE", desktop=desktop, start_port=28900, stop_after=True
        )
        self.assertEqual(plan["origin"], "CMSSZTE")
        self.assertGreaterEqual(plan["socketPort"], 28900)
        self.assertTrue(plan["rsa"]["cipher_is_stub"])
        self.assertFalse(plan["live_vdi"])

    def test_live_pipeline_denied_without_allow_live(self):
        with self.assertRaises(LiveLaunchDenied):
            live_pipeline(
                "CMSSZTE",
                desktop={"machineId": "deny-m1", "originCompanyCode": "CMSSZTE"},
                start_port=29200,
                allow_live=False,
                stop_after=True,
            )

    def test_live_pipeline_refuses_stub_cipher(self):
        sess = PathASession(
            origin_company_code="CMSSZTE",
            machine_id="stub-refuse",
            start_port=29210,
        )
        self.addCleanup(sess.stop)
        with self.assertRaises(RuntimeError) as ctx:
            sess.live_pipeline(
                allow_live=True,
                require_binaries=False,
                allow_stub_cipher=False,
            )
        self.assertIn("stub", str(ctx.exception).lower())

    def test_live_pipeline_mock_popen_argv_json_cipher(self):
        """allow_live + allow_stub_cipher + mock Popen → argv VDI --json <cipher>."""
        mock_proc = MagicMock()
        mock_proc.pid = 9001
        mock_proc.poll.return_value = None

        def fake_popen(argv, **kwargs):
            fake_popen.last_argv = list(argv)  # type: ignore[attr-defined]
            return mock_proc

        desktop = {
            "originCompanyCode": "CMSSZTE",
            "instanceId": "live-m1",
            "machineId": "live-m1",
            "desktopname": "demo",
            "serverIp": "10.0.0.2",
            "serverPort": 443,
        }
        sess = PathASession(
            origin_company_code="CMSSZTE",
            machine_id="live-m1",
            start_port=29220,
        )
        plan = sess.live_pipeline(
            desktop=desktop,
            allow_live=True,
            require_binaries=False,
            allow_stub_cipher=True,
            popen=fake_popen,
        )
        self.addCleanup(sess.stop)

        self.assertEqual(plan["stage"], "live_pipeline")
        self.assertTrue(plan["live_vdi"])
        self.assertFalse(plan["heart_observed"])
        self.assertFalse(plan["heart_auto_reply"])
        self.assertEqual(plan["rsa"]["cipher_display"], REDACTED)
        self.assertIn(REDACTED, plan["argv_display"])
        self.assertTrue(any(a == "--json" for a in plan["argv_display"]))
        # real argv to Popen has cipher after --json
        argv = fake_popen.last_argv  # type: ignore[attr-defined]
        # shell_wrapper (default/P17): [shell, wrapper, --json, cipher] → json at [-2]
        # direct_client: [client, --json, cipher] → json at [1]
        self.assertGreaterEqual(len(argv), 3)
        self.assertIn(len(argv), (3, 4))
        self.assertEqual(argv[-2], "--json")
        self.assertTrue(str(argv[-1]).startswith(DRY_STUB_PREFIX))
        self.assertEqual(plan["live_result"]["pid"], 9001)
        # redacted display must not leak full cipher body
        for a in plan["argv_display"]:
            self.assertFalse(str(a).startswith(DRY_STUB_PREFIX))


if __name__ == "__main__":
    unittest.main()
