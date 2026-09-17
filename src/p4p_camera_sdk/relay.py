"""
UBox/Ucon P4P relay-path session establishment.

Empirically validated against a real packet capture of the Ucon app's own
live-view session for a 4G/cellular "B4HUNT" camera
(2026-09-17, see /memories/repo/camera-api-findings.md): for this camera,
the real app NEVER uses the direct P2P path at all - message types
0x0012xxxx (camera knock, direct video) never appear anywhere in a full
live-view session. Every single control and video packet goes through the
relay (0x0042xxxx / 0x0024xxxx), continuously and bidirectionally, for the
whole session duration - not a one-way ~1 GOP bootstrap as documented by
the ubox-p4p project for their (WiFi) camera. This matches a cellular
carrier-grade-NAT device: the camera cannot be reached with a client-
initiated direct knock, so the vendor's own app relies on the relay path
exclusively.

Crypto/framing (p4p_crypto.build_relay_login, build_rlystreamreq,
parse_rlystreamrsp, build_relay_bind, wrap_relay_kcp) and the generic
ioctl-over-KCP envelope (build_ioctrl_frame) were vendored from
https://github.com/mahumadad/ubox-p4p (MIT, see LICENSE_ubox_p4p.md) and
confirmed byte-for-byte correct against the real capture: a captured
client->relay ioctl frame decoded to iotype=960 (0x03c0), which matches
AVIOCTRLDEFs.IOTYPE_USER_IPCAM_GET_ADVANCESETTINGS_REQ from the decompiled
Ucon Java exactly.

Key real-traffic facts used below:
  - The relay responds to our stream request with EITHER a full-candidate
    0x00421206 packet (whose byte layout differs from what ubox-p4p's
    parse_rlystreamrsp expects) OR a compact 36-byte 0x00421406 "alive"
    packet - which DOES match parse_rlystreamrsp's offsets exactly
    (routing_tag @6, conv @24). We rely on the alive packet, matching
    ubox-p4p's own approach of treating 0x00421406 as the practical
    rlystreamrsp.
  - After that, the client sends a relay_bind (0x00241405) keepalive
    roughly once per second, indefinitely, for the life of the session -
    not just as a one-time echo.
"""

from __future__ import annotations

import secrets
import socket
import struct
import sys
import time

from kcp.extension import KCP

from .p4p_crypto import (
    MSG_RLYSTREAMRSP,
    MSG_RLYSTREAMRSP_ALIVE_ALIAS,
    build_knock,
    build_queryreq,
    build_relay_bind,
    build_relay_logout,
    build_rlystreamreq,
    decode,
    encode,
    parse_rlystreamrsp,
    wrap_relay_kcp,
)

# RDT video framing (vendored constants, from ubox-p4p's docs/KCP_DEMUX.md):
# 32-byte header, unit type as u32 @0, payload length+16 as u32 @8.
# 0x11=HEVC video, 0x13=metadata, 0x04=control, 0x1000004=JPEG data. Not yet cross-checked against
# a real Ucon capture beyond "this is what's interleaved with our ioctl
# frames on the same KCP conv" - if video ever desyncs the demuxer, this is
# the first place to re-verify against a fresh capture.
RDT_HEADER_LEN = 32
RDT_LEN_ADJUST = 16
RDT_TYPES = frozenset({0x04, 0x11, 0x13, 0x1000004})
RDT_IOTYPE_BASE = 0x10000  # tag for RDT-framed responses, see poll_ioctrl docstring


def _is_ioctrl_marker(marker: int) -> bool:
    """True if the first 4 bytes (as u32 LE) look like our ioctl envelope:
    u16 marker=0x0003 @0, channel byte @2, reserved byte @3 (top byte of the
    u32 must be 0; channel occupies the third byte)."""
    return (marker & 0xFFFF) == 0x0003 and (marker >> 24) == 0


MASTERS = [
    ("175.178.248.245", 10240),
    ("121.199.12.37", 10240),
    ("43.153.110.207", 10240),
    ("8.208.11.50", 10240),
    ("43.134.10.68", 10240),
    ("43.157.31.112", 10240),
]

RELAYS = [
    ("170.101.97.155", 20001),
    ("51.222.110.215", 20001),
    ("49.51.188.113", 20001),
    ("43.156.14.205", 20001),
    ("57.129.121.120", 20001),  # observed live in a real Ucon session, 2026-09-17
]

KNOWN_SERVERS = {h for h, _ in MASTERS + RELAYS}
RLYSTREAMRSP_TYPES = {MSG_RLYSTREAMRSP, MSG_RLYSTREAMRSP_ALIVE_ALIAS}


def try_decode(data: bytes) -> bytes:
    if len(data) < 4 or data[:4] == b"\x07\x18\x10\x00":
        return data
    try:
        return decode(data)
    except Exception:
        return data


def build_ioctrl_frame(channel: int, iotype: int, data: bytes) -> bytes:
    """Generic ioctl-over-KCP envelope, confirmed byte-for-byte against a
    real capture (see module docstring): marker u16 @0, channel @2, data
    length u32 @8, iotype u32 @12, payload after byte 16."""
    buf = bytearray(16 + len(data))
    struct.pack_into("<H", buf, 0, 0x0003)
    buf[2] = channel & 0xFF
    struct.pack_into("<I", buf, 8, len(data))
    struct.pack_into("<I", buf, 12, iotype)
    buf[16:] = data
    return bytes(buf)


def parse_ioctrl_frame(payload: bytes) -> tuple[int, bytes] | None:
    if len(payload) < 16:
        return None
    length = struct.unpack_from("<I", payload, 8)[0]
    iotype = struct.unpack_from("<I", payload, 12)[0]
    data = payload[16:16 + length]
    return iotype, data


def _get_public_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


def parse_queryrsp_relay_candidates(plain: bytes) -> list[tuple[str, int]]:
    """Extract relay candidate IPv4 addresses from a 152-byte master
    queryrsp (msg 0x00821052). Confirmed empirically (2026-09-17 real
    capture, see /memories/repo/camera-api-findings.md): bytes[72:88] hold
    four 4-byte IPv4 addresses; the real app used the first one that
    answered. Port is always 20001 in every observation so far."""
    candidates: list[tuple[str, int]] = []
    if len(plain) < 88:
        return candidates
    for offset in range(72, 88, 4):
        octets = plain[offset:offset + 4]
        if len(octets) != 4 or octets[0] in (0, 127, 255):
            continue
        candidates.append((".".join(str(b) for b in octets), 20001))
    return candidates


class RelaySession:
    """A bidirectional KCP session established over the relay path.

    Usage:
        with RelaySession(uid, password) as session:
            session.send_ioctrl(0, 256, payload)
            for iotype, data in session.poll_ioctrl(timeout=5):
                ...
    """

    def __init__(self, uid: str, password: str, wake_sec: float = 4.0, stream_sec: float = 8.0):
        self.uid = uid
        self.password = password
        self.wake_sec = wake_sec
        self.stream_sec = stream_sec
        self.sock: socket.socket | None = None
        self.relay_addr = None
        self.kcp: KCP | None = None
        self._app_buf = bytearray()
        self._rsp = None
        self._ts_base = 0

    def __enter__(self) -> "RelaySession":
        self._establish()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _establish(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        local_port = sock.getsockname()[1]
        local_ip = _get_public_ip()
        session_tag = secrets.token_bytes(8)
        conv4 = session_tag[:4]

        for host, port in MASTERS:
            sock.sendto(build_queryreq(self.uid), (host, port))
        print(f"[relay] local {local_ip}:{local_port}, queryreq -> {len(MASTERS)} masters", file=sys.stderr)

        discovered_relays: list[tuple[str, int]] = []
        query_deadline = time.time() + 2.0
        sock.settimeout(0.3)
        while time.time() < query_deadline and not discovered_relays:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            plain = try_decode(data)
            if len(plain) >= 12 and struct.unpack_from("<I", plain, 8)[0] == 0x00821052:
                discovered_relays = parse_queryrsp_relay_candidates(plain)
        relay_targets = discovered_relays or RELAYS
        print(f"[relay] relay candidates from queryrsp: {discovered_relays or '(none, using static fallback)'}",
              file=sys.stderr)

        # Real Ucon app traffic (captured 2026-09-17) sends ONLY a knock/wake
        # burst here - no separate relay_login packet. The single 0x00241205
        # packet sent afterward (build_rlystreamreq, STREAM flag set) serves
        # as both login and stream request in one shot.
        wake = build_knock(self.uid)

        sock.settimeout(0.05)
        wake_end = time.time() + self.wake_sec
        wake_sent = 0
        last_wake = 0.0
        wake_responders: set = set()
        while time.time() < wake_end:
            if time.time() - last_wake >= 0.05:
                for host, port in relay_targets:
                    sock.sendto(wake, (host, port))
                    wake_sent += 1
                last_wake = time.time()
            try:
                data, addr = sock.recvfrom(65535)
                plain = try_decode(data)
                if len(plain) >= 12:
                    mt = struct.unpack_from("<I", plain, 8)[0]
                    if mt == 0x00421202:
                        wake_responders.add(addr)
            except socket.timeout:
                pass
        print(f"[relay] wake burst: {wake_sent} knocks sent to {len(relay_targets)} relays; "
              f"{len(wake_responders)} ACKed: {sorted(wake_responders)}", file=sys.stderr)
        targets = list(wake_responders) if wake_responders else relay_targets

        streamreq = encode(build_rlystreamreq(self.uid, self.password, conv4, local_ip, local_port))
        for host, port in targets:
            sock.sendto(streamreq, (host, port))

        rsp = None
        relay_addr = None
        sock.settimeout(0.3)
        deadline = time.time() + self.stream_sec
        last_req = time.time()
        unrecognized: dict[str, int] = {}
        while time.time() < deadline and rsp is None:
            if time.time() - last_req > 0.7:
                for host, port in targets:
                    sock.sendto(streamreq, (host, port))
                last_req = time.time()
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            plain = try_decode(data)
            if len(plain) >= 12:
                mt = struct.unpack_from("<I", plain, 8)[0]
                if mt in RLYSTREAMRSP_TYPES and len(plain) >= 36:
                    parsed = parse_rlystreamrsp(plain)
                    if parsed is not None:
                        rsp = parsed
                        relay_addr = addr
                        print(f"[relay] got rlystreamrsp/alive 0x{mt:08x} from {addr}", file=sys.stderr)
                else:
                    label = f"{addr[0]}:0x{mt:08x}:{len(data)}B"
                    unrecognized[label] = unrecognized.get(label, 0) + 1
            else:
                label = f"{addr[0]}:undecodable:{len(data)}B"
                unrecognized[label] = unrecognized.get(label, 0) + 1

        if not rsp:
            print(f"[relay] no rsp; unrecognized packets seen: {unrecognized}", file=sys.stderr)

        if not rsp:
            sock.close()
            raise TimeoutError(
                "no rlystreamrsp/alive from any relay - camera offline, wrong "
                "UID/password, or relay infrastructure changed"
            )

        sock.sendto(encode(build_relay_bind(rsp)), relay_addr)

        conv = struct.unpack_from("<I", rsp["conv"], 0)[0]
        conv_signed = conv if conv < 0x80000000 else conv - 0x100000000
        kcp = KCP(conv_signed)

        routing_tag = rsp["routing_tag"]

        @kcp.outbound_handler
        def on_out(_kcp_inst, raw):
            sock.sendto(wrap_relay_kcp(bytes(raw), routing_tag), relay_addr)

        kcp.set_window_size(512, 512)
        try:
            kcp.set_performance_options(0, 0, 0, 1)
        except Exception:
            pass

        self.sock = sock
        self.relay_addr = relay_addr
        self.kcp = kcp
        self.keepalive = encode(build_relay_bind(rsp))
        self._rsp = rsp
        self._ts_base = int(time.time() * 1000) & 0xFFFFFFFF
        print(f"[relay] session established via {relay_addr}, conv=0x{conv:08x}", file=sys.stderr)

    def _clock(self) -> int:
        return (int(time.time() * 1000) - self._ts_base) & 0xFFFFFFFF

    def send_ioctrl(self, channel: int, iotype: int, data: bytes) -> None:
        assert self.kcp is not None
        frame = build_ioctrl_frame(channel, iotype, data)
        self.kcp.enqueue(frame)
        self.kcp.update(self._clock())
        self.kcp.flush()

    def poll_ioctrl(self, timeout: float = 5.0):
        """Yield (iotype, data) tuples for ioctrl responses received within
        `timeout` seconds. Also sends the ~1s relay_bind keepalive the real
        app uses to keep the session alive indefinitely."""
        assert self.sock is not None and self.kcp is not None
        deadline = time.time() + timeout
        last_keepalive = time.time()
        last_status = time.time()
        pkt_count = 0
        while time.time() < deadline:
            now = time.time()
            if now - last_keepalive >= 1.0:
                self.sock.sendto(self.keepalive, self.relay_addr)
                last_keepalive = now
            if now - last_status >= 2.0:
                print(f"[relay] poll: {pkt_count} video/KCP packets received so far", file=sys.stderr)
                last_status = now
            self.kcp.update(self._clock())
            self.kcp.flush()
            try:
                self.sock.settimeout(0.05)
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            plain = try_decode(data)
            if len(plain) < 16:
                continue
            mt = struct.unpack_from("<I", plain, 8)[0]
            if mt == 0x00421406:
                continue  # keepalive echo, not data
            if mt != 0x0042140A:
                continue  # e.g. 0x00421206 candidate rebroadcasts - not data
            pkt_count += 1
            body = plain[16:]
            try:
                self.kcp.receive(body)
            except Exception:
                continue
            try:
                app_data = self.kcp.get_received()
            except Exception:
                app_data = None
            if app_data:
                self._app_buf.extend(app_data)
                yield from self._drain_frames()

    def _drain_frames(self):
        """Demux the reassembled KCP byte stream into our ioctl frames and
        RDT video frames (the camera streams live video unsolicited the
        moment a relay session exists - see module docstring). Yields
        (iotype, data) for our own ioctl envelope responses AND for RDT
        control (0x04) / metadata (0x13) frames - device command responses
        were empirically found to arrive as RDT control frames, not our
        assumed marker=0x0003 envelope (see PROTOCOL_SDCARD.md /
        camera-api-findings.md). RDT frames are tagged with a synthesized
        iotype (RDT_IOTYPE_BASE + unit type) so callers can distinguish them
        from real ioctl envelope responses. Pure video (0x11) is discarded
        silently."""
        while True:
            buf = bytes(self._app_buf)
            if len(buf) < 4:
                return
            marker = struct.unpack_from("<I", buf, 0)[0]
            if _is_ioctrl_marker(marker):
                if len(buf) < 16:
                    return
                data_len = struct.unpack_from("<I", buf, 8)[0]
                iotype = struct.unpack_from("<I", buf, 12)[0]
                total = 16 + data_len
                if len(buf) < total or data_len > 4096:
                    return  # wait for more bytes, or bogus length - stop rather than misparse
                self._app_buf = self._app_buf[total:]
                yield iotype, buf[16:total]
                continue
            if marker in RDT_TYPES:
                if len(buf) < RDT_HEADER_LEN:
                    return
                length = struct.unpack_from("<I", buf, 8)[0]
                payload_len = length - RDT_LEN_ADJUST
                if payload_len < 0:
                    self._app_buf = self._app_buf[1:]  # resync: drop one byte and retry
                    continue
                total = RDT_HEADER_LEN + payload_len
                if len(buf) < total:
                    return
                self._app_buf = self._app_buf[total:]
                if marker in (0x04, 0x13, 0x1000004):
                    yield RDT_IOTYPE_BASE + marker, buf[RDT_HEADER_LEN:total]
                continue
            # Unknown marker: drop one byte and try to resync rather than stall forever.
            self._app_buf = self._app_buf[1:]

    def close(self) -> None:
        if self.sock and self.relay_addr and self._rsp:
            try:
                for _ in range(3):
                    self.sock.sendto(encode(build_relay_logout(self._rsp)), self.relay_addr)
            except Exception:
                pass
        if self.sock:
            self.sock.close()
