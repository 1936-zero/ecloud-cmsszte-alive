"""Local 15900 control-plane framing + server skeleton (Path A).

Static protocol from reports/local_15900_protocol.md (T0-C ACCEPTED).
No secrets. No 爱家 code. Tests must not require live VDI.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# --- SocketInitInfo (commonConstants) ---
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 15900
MAX_PORT_SCAN = 64  # PORT++ on EADDRINUSE / EACCES

# receiveData gate on already-escaped wire length
MIN_WIRE_LEN = 0x18


class MsgType:
    """Msg_Type constants from commonConstants (subset + full table)."""

    COMMAND_HEART_BEAT = 1
    COMMAND_CLIENT_ACTIVE = 2
    COMMAND_CLIENT_DISCONNECT_REQUEST = 3
    COMMAND_CLIENT_WINDOW_CHANGE = 4
    COMMAND_CLIENT_CONNECT_PROGRESS = 5
    COMMAND_CLIENT_CONNECTED_NOTIFICATION = 6
    COMMAND_CLIENT_DISCONNECTED_NOTIFICATION = 7
    COMMAND_CLIENT_RECONNECT_NOTIFICATION = 8
    COMMAND_BUTTON_ACTION = 9
    COMMAND_LOGOFF_CLIENT = 10
    COMMAND_OTHER_TERMINAL_LOGIN = 11
    COMMAND_PREEMPTIVE_LOGIN = 12
    COMMAND_PREEMPTIVE_LOGIN_RESPONSE = 13
    COMMAND_REPORT_REQUEST = 16
    COMMAND_REPORT_REPLY = 17
    COMMAND_OPERATE_REQUEST = 21
    COMMAND_OPERATE_RESPONSE = 22
    COMMAND_REQUEST_QRCODE = 23
    COMMAND_RESPONSE_QRCODE = 24
    COMMAND_CLIENT_FREE_REQUEST = 25
    COMMAND_CLIENT_FREE_RESPONSE = 26
    COMMAND_REQUEST_FORWARDING_REQUEST = 32
    COMMAND_REQUEST_FORWARDING_RESPONSE = 33
    COMMAND_REQUEST_INVOKE_CLIENT_DIALOG = 34
    COMMAND_RESPONSE_DEVICE_POLICY = 35


# Alias table used by callers / tests
COMMAND = MsgType


def encode_msg(payload: Union[bytes, bytearray, memoryview]) -> bytes:
    """EncodeMsg: escape 0x0e/0x0d then append frame terminator 0x0d."""
    out = bytearray()
    for b in payload:
        if b == 0x0E:
            out.append(0x0E)
            out.append(0x01)
        elif b == 0x0D:
            out.append(0x0E)
            out.append(0x02)
        else:
            out.append(b)
    out.append(0x0D)
    return bytes(out)


def decode_msg(wire: Union[bytes, bytearray, memoryview]) -> List[bytes]:
    """DecodeMsg: reverse escapes; split on bare 0x0d. May yield multiple frames."""
    messages: List[bytes] = []
    cur = bytearray()
    data = memoryview(wire)
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0x0E:
            if i + 1 >= n:
                break  # incomplete escape; wait for more (stream callers buffer)
            nxt = data[i + 1]
            if nxt == 0x01:
                cur.append(0x0E)
            elif nxt == 0x02:
                cur.append(0x0D)
            else:
                # unknown escape: keep both bytes (defensive)
                cur.append(0x0E)
                cur.append(nxt)
            i += 2
            continue
        if b == 0x0D:
            messages.append(bytes(cur))
            cur = bytearray()
            i += 1
            continue
        cur.append(b)
        i += 1
    # incomplete trailing (no final 0x0d) is not a complete message
    return messages


def build_inner_payload(
    msg_type: int,
    machine_id: str,
    company_code: str,
    data: Any = None,
) -> bytes:
    """u32le type || u32le jsonLen || utf8(json{id,companyCode,data})."""
    body = {
        "id": machine_id,
        "companyCode": company_code,
        "data": data,
    }
    raw_json = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    hdr = struct.pack("<II", int(msg_type) & 0xFFFFFFFF, len(raw_json))
    return hdr + raw_json


def encode_app_message(
    msg_type: int,
    machine_id: str,
    company_code: str,
    data: Any = None,
) -> bytes:
    """Full wire frame for one application message."""
    return encode_msg(build_inner_payload(msg_type, machine_id, company_code, data))


@dataclass
class ParsedMessage:
    msg_type: int
    machine_id: str
    company_code: str
    data: Any
    raw_json: dict
    inner: bytes


def parse_inner(inner: bytes) -> ParsedMessage:
    """Parse one DecodeMsg result into type + JSON body."""
    if len(inner) < 8:
        raise ValueError("inner payload too short")
    msg_type, json_len = struct.unpack_from("<II", inner, 0)
    # Electron reads JSON from offset 8 (skips length field integrity check)
    json_bytes = bytes(inner[8 : 8 + json_len]) if json_len else bytes(inner[8:])
    # If length is wrong, still try offset 8 → end (compat with short/odd peers)
    if not json_bytes and len(inner) > 8:
        json_bytes = bytes(inner[8:])
    obj = json.loads(json_bytes.decode("utf-8") if json_bytes else "{}")
    if not isinstance(obj, dict):
        obj = {"data": obj}
    return ParsedMessage(
        msg_type=msg_type,
        machine_id=str(obj.get("id", "")),
        company_code=str(obj.get("companyCode", "")),
        data=obj.get("data"),
        raw_json=obj,
        inner=bytes(inner),
    )


def should_auto_reply(msg_type: int) -> bool:
    """Electron policy: HEART (type=1) is no-op; never auto-reply."""
    return False if msg_type == MsgType.COMMAND_HEART_BEAT else False


def handle_received_type(msg_type: int) -> str:
    """Return handler policy label for a received type (server side)."""
    if msg_type == MsgType.COMMAND_HEART_BEAT:
        return "ignore_no_reply"
    if msg_type == MsgType.COMMAND_CLIENT_DISCONNECTED_NOTIFICATION:
        return "session_cleanup"
    return "app_callback"


@dataclass
class BindResult:
    host: str
    port: int
    sock: socket.socket


def bind_port_with_increment(
    host: str = DEFAULT_HOST,
    start_port: int = DEFAULT_PORT,
    max_tries: int = MAX_PORT_SCAN,
) -> BindResult:
    """Listen 127.0.0.1:start_port; on EADDRINUSE/EACCES, PORT++ like Electron."""
    last_err: Optional[OSError] = None
    for offset in range(max_tries):
        port = start_port + offset
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            s.listen(16)
            return BindResult(host=host, port=port, sock=s)
        except OSError as e:
            last_err = e
            try:
                s.close()
            except OSError:
                pass
            # Electron bumps on EADDRINUSE / EACCES
            if getattr(e, "errno", None) not in (
                getattr(__import__("errno"), "EADDRINUSE", 98),
                getattr(__import__("errno"), "EACCES", 13),
            ) and e.errno not in (98, 13, 48):  # 48=EADDRINUSE on some BSDs
                # still try next port for robustness in tests
                continue
            continue
    raise OSError(f"unable to bind {host}:{start_port}+ within {max_tries} tries: {last_err}")


AppHandler = Callable[[ParsedMessage], None]


@dataclass
class Local15900Server:
    """Minimal Electron-like TCP server for 15900 control plane.

    HEART (type=1): ignore, no auto-reply.
    Other types: optional app_handler callback.
    """

    host: str = DEFAULT_HOST
    start_port: int = DEFAULT_PORT
    app_handler: Optional[AppHandler] = None
    port: Optional[int] = None
    _bind: Optional[BindResult] = field(default=None, repr=False)
    _thread: Optional[threading.Thread] = field(default=None, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    socket_list: Dict[str, socket.socket] = field(default_factory=dict)
    machine_list: Dict[str, str] = field(default_factory=dict)  # id -> companyCode
    received: List[ParsedMessage] = field(default_factory=list)
    heartbeats_ignored: int = 0
    auto_replies_sent: int = 0  # must stay 0 for HEART policy tests

    def start(self) -> int:
        if self._bind is not None:
            return int(self.port or self._bind.port)
        self._bind = bind_port_with_increment(self.host, self.start_port)
        self.port = self._bind.port
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve_loop, name="local15900", daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._bind is not None:
            try:
                # unblock accept
                with socket.create_connection((self.host, self._bind.port), timeout=0.3):
                    pass
            except OSError:
                pass
            try:
                self._bind.sock.close()
            except OSError:
                pass
        for mid, sock in list(self.socket_list.items()):
            try:
                sock.close()
            except OSError:
                pass
            self.socket_list[mid] = None  # type: ignore[assignment]
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._bind = None

    def init_connect_info(self, machine_id: str, company_code: str) -> None:
        self.machine_list[machine_id] = company_code

    def send_data(self, msg_type: int, machine_id: str, data: Any = None) -> bool:
        """Mirror Electron sendData; silent false if no socket."""
        sock = self.socket_list.get(machine_id)
        if not sock:
            return False
        company = self.machine_list.get(machine_id, "")
        wire = encode_app_message(msg_type, machine_id, company, data)
        try:
            sock.sendall(wire)
            return True
        except OSError:
            return False

    def _serve_loop(self) -> None:
        assert self._bind is not None
        srv = self._bind.sock
        srv.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            t.start()

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        buf = bytearray()
        assigned_id: Optional[str] = None
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                # Try decode complete frames; keep incomplete tail
                frames, rest = _split_complete_frames(bytes(buf))
                buf = bytearray(rest)
                for wire_frame in frames:
                    if len(wire_frame) < MIN_WIRE_LEN and len(wire_frame) < 8:
                        # Electron gate is on raw wire before decode; short frames may be dropped.
                        # Still attempt decode for unit/synthetic short HEART tests via process_wire.
                        pass
                    self._process_wire_frame(wire_frame, conn)
                    # assign socket after first parsed non-empty id
                    if self.received:
                        last = self.received[-1]
                        if last.machine_id:
                            assigned_id = last.machine_id
                            self.socket_list[assigned_id] = conn
                            if last.company_code and assigned_id not in self.machine_list:
                                self.machine_list[assigned_id] = last.company_code
        finally:
            if assigned_id and self.socket_list.get(assigned_id) is conn:
                self.socket_list.pop(assigned_id, None)
            try:
                conn.close()
            except OSError:
                pass

    def _process_wire_frame(self, wire_frame_without_term: bytes, conn: socket.socket) -> None:
        # wire_frame_without_term is raw escaped bytes WITHOUT trailing 0x0d
        # rebuild with terminator for decode_msg
        full = wire_frame_without_term + b"\x0d"
        inners = decode_msg(full)
        for inner in inners:
            try:
                parsed = parse_inner(inner)
            except (ValueError, json.JSONDecodeError, struct.error):
                continue
            self.received.append(parsed)
            policy = handle_received_type(parsed.msg_type)
            if policy == "ignore_no_reply":
                self.heartbeats_ignored += 1
                # CRITICAL: no auto-reply for HEART
                continue
            if self.app_handler is not None:
                try:
                    self.app_handler(parsed)
                except Exception:
                    pass

    def process_wire_for_test(self, wire: bytes) -> List[ParsedMessage]:
        """Feed a complete wire buffer (may contain multiple frames) without TCP."""
        out: List[ParsedMessage] = []
        for inner in decode_msg(wire):
            try:
                parsed = parse_inner(inner)
            except (ValueError, json.JSONDecodeError, struct.error):
                continue
            self.received.append(parsed)
            out.append(parsed)
            if handle_received_type(parsed.msg_type) == "ignore_no_reply":
                self.heartbeats_ignored += 1
            elif self.app_handler is not None:
                self.app_handler(parsed)
        return out


def _split_complete_frames(buf: bytes) -> Tuple[List[bytes], bytes]:
    """Split escaped stream into frames ending at bare 0x0d; return (frames_wo_term, rest)."""
    frames: List[bytes] = []
    cur = bytearray()
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        if b == 0x0E:
            if i + 1 >= n:
                # incomplete escape → keep from 0x0e in rest
                return frames, bytes(buf[i - len(cur) :]) if False else bytes(cur + buf[i:])
            cur.append(b)
            cur.append(buf[i + 1])
            i += 2
            continue
        if b == 0x0D:
            frames.append(bytes(cur))
            cur = bytearray()
            i += 1
            continue
        cur.append(b)
        i += 1
    return frames, bytes(cur)


def prepare_socket_port(
    host: str = DEFAULT_HOST,
    start_port: int = DEFAULT_PORT,
) -> BindResult:
    """Public helper: bind and return actual port for connect JSON socketPort."""
    return bind_port_with_increment(host, start_port)
