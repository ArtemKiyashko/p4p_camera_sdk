"""
UBox P4P crypto - reverse engineered from libUBICAPIs29.so (ARM64)

Vendored verbatim from https://github.com/mahumadad/ubox-p4p (MIT license,
see LICENSE_ubox_p4p.md in this directory). Not modified. Reused here because
the Ucon app (cn.ubia.ucon) ships the same "P4P" SDK family as UBox/UBIA
(confirmed via the shared native library naming and the
`com.tutk.IOTC.st_LanSearchInfo2` string baked into libUBICAPIs.so): this is
a TUTK IOTC rebadge, and the wire crypto/handshake is shared across brands
from the same vendor (cn.ubia).

Algorithm per 16-byte block:
  ENCODE: rotate_right(i+1) -> XOR(key) -> Swap -> rotate_right(i+3)
  DECODE: rotate_left(i+3) -> inv_Swap -> XOR(key) -> rotate_left(i+1)

Tail (< 16B): XOR(key) only (swap falls through to memcpy for
non-power-of-2 sizes)
Key: "I believe 1 ^ill win the battle!" (hardcoded at 0xb889 in .rodata)
"""

import struct

KEY = b"I believe 1 ^ill win the battle!"

SWAP16 = [11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3]
INV_SWAP16 = [0] * 16
for _i, _v in enumerate(SWAP16):
    INV_SWAP16[_v] = _i


def _rot32(val, shift, left=True):
    shift &= 0x1f
    if left:
        return ((val << shift) | (val >> (32 - shift))) & 0xffffffff
    return ((val >> shift) | (val << (32 - shift))) & 0xffffffff


def _permute16(block, perm):
    return bytes(block[perm[i]] for i in range(16))


def encode(plaintext: bytes) -> bytes:
    data = bytearray(plaintext)
    pos = 0
    rem = len(data)

    while rem >= 16:
        buf = bytearray(16)
        for i in range(0, 16, 4):
            val = struct.unpack_from('<I', data, pos + i)[0]
            struct.pack_into('<I', buf, i, _rot32(val, i + 1, left=False))
        for j in range(16):
            buf[j] ^= KEY[j]
        buf = bytearray(_permute16(buf, SWAP16))
        for i in range(0, 16, 4):
            val = struct.unpack_from('<I', buf, i)[0]
            struct.pack_into('<I', buf, i, _rot32(val, i + 3, left=False))
        data[pos:pos+16] = buf
        pos += 16
        rem -= 16

    if rem > 0:
        for j in range(rem):
            data[pos + j] ^= KEY[j]

    return bytes(data)


def decode(ciphertext: bytes) -> bytes:
    data = bytearray(ciphertext)
    pos = 0
    rem = len(data)

    while rem >= 16:
        buf = bytearray(16)
        for i in range(0, 16, 4):
            val = struct.unpack_from('<I', data, pos + i)[0]
            struct.pack_into('<I', buf, i, _rot32(val, i + 3, left=True))
        buf = bytearray(_permute16(buf, INV_SWAP16))
        for j in range(16):
            buf[j] ^= KEY[j]
        for i in range(0, 16, 4):
            val = struct.unpack_from('<I', buf, i)[0]
            struct.pack_into('<I', buf, i, _rot32(val, i + 1, left=True))
        data[pos:pos+16] = buf
        pos += 16
        rem -= 16

    if rem > 0:
        for j in range(rem):
            data[pos + j] ^= KEY[j]

    return bytes(data)


MAGIC = 0x00101807
PAYLOAD_LEN = 0x2C
MSG_QUERYREQ = 0x00281051
MSG_KNOCK = 0x00241201
MSG_RELAY_LOGIN = 0x00241205
MSG_KNOCK_CAM_IN = 0x0012130E
MSG_KNOCK_CAM_OUT = 0x0021130B
MSG_KNOCK_R = 0x0021130D
HANDSHAKE_PKT_LEN = 60
RELAY_LOGIN_LEN = 124
KNOCK_CAM_LEN = 84

# --- Relay-data (TURN) path - captured by forcing direct-punch failure on
# the phone ---
MSG_RLYSTREAMREQ = 0x00241205   # same wire type as relay_login, "stream" variant
MSG_RLYSTREAMRSP = 0x00421206   # relay -> client: rlystreamrsp per receiver dispatch table
# NOTE: In practice this relay implementation never sends 0x00421206 to our VPS. It
# instead sends 0x00421406 (handle_alive) which coincidentally carries a routing
# tag + conv layout compatible with our parser, and treating it as the "rsp" is
# what actually lets us open the KCP flow. So we accept both.
MSG_RLYSTREAMRSP_ALIVE_ALIAS = 0x00421406
MSG_RELAY_BIND = 0x00241405     # client -> relay: echo of the rsp
MSG_RELAY_KCP = 0x00241409      # client -> relay: KCP data (ioctrl / acks)
MSG_RELAY_VIDEO = 0x0042140A    # relay -> client: forwarded camera KCP video


def build_rlystreamreq(uid, password, conv4, local_ip="0.0.0.0", local_port=0):
    """124B relay stream request (0x00241205). conv4 = 4-byte conv id
    proposed by us (the relay echoes it back in the rsp).

    Byte [82] was assumed to be 0x01 ("stream", vs 0x02 for a plain register)
    based on the upstream project's own capture. A real capture of the Ucon
    app's successful live-view session (2026-09-17, see
    /memories/repo/camera-api-findings.md) shows [82]=0x02 for a working
    stream request against this account/camera - the flag's real meaning
    differs from that assumption, so we match the empirically confirmed
    working value instead of the inferred one.
    """
    buf = bytearray(RELAY_LOGIN_LEN)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<I", buf, 4, 0x6C)
    struct.pack_into("<I", buf, 8, MSG_RLYSTREAMREQ)
    buf[16] = 0x01
    parts = [int(x) for x in local_ip.split(".")]
    if len(parts) == 4:
        buf[28:32] = bytes(parts)
    struct.pack_into(">H", buf, 32, local_port & 0xFFFF)
    buf[40:60] = _uid_bytes(uid)
    buf[60:76] = _password_bytes(password)
    buf[82] = 0x02                       # STREAM flag (empirically confirmed, see docstring)
    buf[88:92] = conv4[:4].ljust(4, b"\x00")
    buf[92:97] = b"admin"
    buf[108] = 0x09
    buf[111] = 0x01
    buf[116:118] = b"\x2d\x9c"           # nonce/counter (observed; relay seems lax)
    return bytes(buf)


def parse_rlystreamrsp(data):
    """Parse relay stream response (0x00421406, 36B). Returns routing tag, conv,
    and the 20-byte payload to echo back in the relay bind, or None."""
    plain = data if data[:4] == struct.pack("<I", MAGIC) else decode(data)
    if len(plain) < 36 or plain[:4] != struct.pack("<I", MAGIC):
        return None
    if struct.unpack_from("<I", plain, 8)[0] not in (MSG_RLYSTREAMRSP, MSG_RLYSTREAMRSP_ALIVE_ALIAS):
        return None
    return {
        "routing_tag": bytes(plain[6:8]),   # goes in every relay packet's offset 12
        "low_tag": bytes(plain[12:14]),     # goes in the bind's offset 6
        "conv": bytes(plain[24:28]),        # KCP conv for the relayed stream
        "payload": bytes(plain[16:36]),     # echoed verbatim in the bind
        "plaintext": plain,
    }


def build_relay_bind(rsp):
    """36B relay bind (0x00241405) - echoes the rlystreamrsp back to the relay."""
    buf = bytearray(36)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<H", buf, 4, 0x14)
    buf[6:8] = rsp["low_tag"]
    struct.pack_into("<I", buf, 8, MSG_RELAY_BIND)
    buf[12:14] = rsp["routing_tag"]
    buf[16:36] = rsp["payload"]
    return bytes(buf)


def build_relay_logout(rsp):
    """100B relay logout (0x00241207) - clean close so the camera frees the session
    immediately (it otherwise holds one session until an auto-close timeout).
    Mirrors the direct logout 0x00211309 (100B, [16]=01) with the relay prefix
    + routing tag."""
    buf = bytearray(100)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<H", buf, 4, 0x54)          # payload_len 84
    buf[6:8] = rsp["low_tag"]
    struct.pack_into("<I", buf, 8, 0x00241207)
    buf[12:14] = rsp["routing_tag"]
    buf[16] = 0x01
    buf[24:28] = rsp["conv"]
    struct.pack_into("<H", buf, 76, 1)
    struct.pack_into("<H", buf, 78, 1)
    return bytes(buf)


def wrap_relay_kcp(kcp_payload, routing_tag):
    """P4P envelope for relay KCP data (0x00241409): magic|len u16@4|0@6|msg|tag@12."""
    buf = bytearray(16 + len(kcp_payload))
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<H", buf, 4, len(kcp_payload) & 0xFFFF)
    struct.pack_into("<I", buf, 8, MSG_RELAY_KCP)
    buf[12:14] = routing_tag
    buf[16:] = kcp_payload
    return bytes(buf)


def build_handshake_plaintext(uid: str, msg_type: int, extra_dword: int = 0) -> bytes:
    """Build the 60-byte handshake plaintext buffer."""
    buf = bytearray(HANDSHAKE_PKT_LEN)
    uid_bytes = uid.encode("ascii")[:20].ljust(20, b"\x00")
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<I", buf, 4, PAYLOAD_LEN)
    struct.pack_into("<I", buf, 8, msg_type)
    if extra_dword:
        struct.pack_into("<I", buf, 16, extra_dword)
    buf[20:40] = uid_bytes
    return bytes(buf)


def build_queryreq(uid: str) -> bytes:
    return encode(build_handshake_plaintext(uid, MSG_QUERYREQ))


def build_knock(uid: str) -> bytes:
    return encode(build_handshake_plaintext(uid, MSG_KNOCK, extra_dword=0x00000101))


def _uid_bytes(uid: str) -> bytes:
    return uid.encode("ascii")[:20].ljust(20, b"\x00")


def _password_bytes(password: str) -> bytes:
    return password.encode("ascii")[:16].ljust(16, b"\x00")


def build_relay_login(
    uid: str,
    password: str,
    session_tag: bytes,
    local_ip: str = "0.0.0.0",
    local_port: int = 0,
    attempt: int = 1,
) -> bytes:
    """124B plaintext relay registration - triggers camera knock."""
    buf = bytearray(RELAY_LOGIN_LEN)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<I", buf, 4, 0x6C)
    struct.pack_into("<I", buf, 8, MSG_RELAY_LOGIN)
    struct.pack_into("<I", buf, 16, attempt)
    parts = [int(x) for x in local_ip.split(".")]
    if len(parts) != 4:
        parts = [0, 0, 0, 0]
    buf[28:32] = bytes(parts[:4])
    struct.pack_into(">H", buf, 32, local_port & 0xFFFF)
    buf[40:60] = _uid_bytes(uid)
    buf[60:76] = _password_bytes(password)
    struct.pack_into(">I", buf, 80, 0x00000200)
    buf[88:92] = session_tag[:4].ljust(4, b"\x00")
    buf[92:97] = b"admin"
    struct.pack_into(">I", buf, 104, 0x00000009)
    struct.pack_into(">I", buf, 108, 0x00000100)
    struct.pack_into(">I", buf, 112, 0x000000E6)
    struct.pack_into(">I", buf, 116, 0x2A000000)
    return bytes(buf)


def build_knock_response(
    uid: str,
    password: str,
    knock_plain: bytes,
) -> bytes:
    """84B plaintext knock reply - echoes network addr from camera knock."""
    buf = bytearray(KNOCK_CAM_LEN)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<I", buf, 4, 0x44)
    struct.pack_into("<I", buf, 8, MSG_KNOCK_CAM_OUT)
    buf[16:36] = _uid_bytes(uid)
    buf[36:56] = password.encode("ascii")[:20].ljust(20, b"\x00")
    if knock_plain and len(knock_plain) >= 68:
        buf[58:68] = knock_plain[58:68]
    buf[68:73] = b"admin"
    return bytes(buf)


MSG_P2P_BIND = 0x00211405


def build_p2p_bind(knock_plain: bytes) -> bytes:
    """36B P2P/KCP channel bind - sent after device_info, before knock_r.

    Registers the KCP channel (conv + addr tags) with the camera so it routes
    video back to us. All fields derive from the camera knock[58:68] block.
    """
    buf = bytearray(36)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<H", buf, 4, 0x0014)      # payload len = 20
    buf[6:8] = knock_plain[58:60]               # wrapper tag (e.g. 0x000c)
    struct.pack_into("<I", buf, 8, MSG_P2P_BIND)
    buf[12:14] = knock_plain[62:64]             # inbound tag (e.g. ef 1f)
    # payload [16:36]
    buf[17] = knock_plain[58]                   # 0x0c
    buf[20:24] = knock_plain[60:64]             # 2c 18 ef 1f
    buf[24:28] = knock_plain[64:68]             # conv id
    return bytes(buf)


def build_knock_r(knock_plain: bytes, device_info_plain: bytes | None = None) -> bytes:
    """52B plaintext knock_r - echoes network addr fields."""
    buf = bytearray(52)
    struct.pack_into("<I", buf, 0, MAGIC)
    struct.pack_into("<I", buf, 4, 0x24)
    struct.pack_into("<I", buf, 8, MSG_KNOCK_R)
    if device_info_plain and len(device_info_plain) >= 48:
        buf[36:38] = device_info_plain[36:38]
        buf[40:48] = device_info_plain[40:48]
    elif knock_plain and len(knock_plain) >= 68:
        buf[42:52] = knock_plain[58:68]
    return bytes(buf)


def parse_camera_knock(data: bytes) -> dict | None:
    """Decode 84B camera knock (wire may be encrypted)."""
    if len(data) < KNOCK_CAM_LEN:
        return None
    plain = data
    if data[:4] != struct.pack("<I", MAGIC):
        try:
            plain = decode(data)
        except Exception:
            return None
    if plain[:4] != struct.pack("<I", MAGIC):
        return None
    msg_type = struct.unpack_from("<I", plain, 8)[0]
    if msg_type not in (MSG_KNOCK_CAM_IN, MSG_KNOCK_CAM_OUT):
        return None
    return {
        "uid": plain[20:40].split(b"\x00")[0].decode("ascii", errors="replace"),
        "password": plain[40:56].split(b"\x00")[0].decode("ascii", errors="replace"),
        "session_tag": bytes(plain[56:64]),
        "plaintext": plain,
    }


def hexdump(data, prefix=""):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{prefix}{i:4d}: {hexs:<48s} {asc}")


if __name__ == "__main__":
    queryreq_enc = bytes.fromhex(
        "81a68d0d62bdd8d2254d498d2ccacbda"
        "3190d87c34e8bcc7642b490cafcbaeab"
        "04a48c0d62bcd8d261da0d7f49f9d8dd"
        "492062656c69657665203120"
    )

    print("=== QUERYREQ ===")
    dec = decode(queryreq_enc)
    hexdump(dec)
    assert encode(dec) == queryreq_enc, "Roundtrip failed!"
    print("Roundtrip OK\n")
