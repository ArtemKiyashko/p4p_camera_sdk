"""
SD-card ioctl builders and parsers for the Ucon/UBIA P4P protocol.

Extracted directly from decompiled Ucon app code (cn.ubia.ucon, jadx
decompilation of the APK), NOT from the ubox-p4p project (which never
implemented this - see its own docs/ENDPOINTS.md section 4: "Playback SD /
PTZ via P2P - NO aun"). This module is the new contribution of this
project's PoC.

Sources (see /memories/repo/camera-api-findings.md and
research/p4p_poc/PROTOCOL_SDCARD.md for the full trail):
  - com/ubia/IOTC/AVIOCTRLDEFs.java       -> numeric ioctrl command IDs
  - com/apiv3/bean/AdvancedSettings.java  -> request byte layouts
  - cn/ubia/player/fragment/LiveEventListFragment.java -> response byte
    layouts (IOCtrlResultCallback handler)

All multi-byte integers are little-endian unless noted, matching
Packet.intToByteArray_Little / shortToByteArray_Little used throughout the
Java SDK.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# --- ioctrl command IDs (from AVIOCTRLDEFs.java) ---
IOTYPE_GET_SD_STATUS_REQ = 520
IOTYPE_GET_SD_STATUS_RSP = 521
IOTYPE_GET_ADVANCE_SETTINGS_REQ = 960
IOTYPE_GET_ADVANCE_SETTINGS_RSP = 961

IOTYPE_LISTEVENT_REQ = 256
IOTYPE_LISTEVENT_RSP = 257

IOTYPE_RECORD_BITMAP_REQ = 258
IOTYPE_RECORD_BITMAP_RSP = 259

IOTYPE_DOWNLOAD_VIDEO_FILE_REQ = 260
IOTYPE_DOWNLOAD_VIDEO_FILE_RSP = 261

IOTYPE_VIDEO_FILE_DATA_REQ = 262
IOTYPE_VIDEO_FILE_DATA_RSP = 263

VIDEO_FILE_DATA_CHUNK_SIZE = 1200  # confirmed by LiveEventListFragment's segment loop

# --- File type constants (cn/ubia/bean/EventResult.java) ---
FILE_TYPE_VIDEO = 1
FILE_TYPE_THUMBNAIL = 2
FILE_TYPE_BIG_PICTURE = 3
FILE_TYPE_8MP_PIC = 6


def build_get_sd_status() -> bytes:
    """getSdStatus(): 4-byte zero payload. Smallest possible probe to check
    whether an arbitrary (non-video-start) ioctl round-trips through the
    established KCP session at all, before attempting the larger SD-card
    commands below."""
    return bytes(4)


def build_list_event(begin_epoch: int, end_epoch: int, channel: int = 0) -> bytes:
    """getRecordEventList(begin, end, channel) -> IOTYPE_LISTEVENT_REQ (256).
    20-byte payload:
      byte[5]      = channel
      byte[6]      = 0x3C (fixed sub-command marker, observed constant)
      bytes[8:12]  = begin (u32 LE, epoch seconds)
      bytes[12:16] = end   (u32 LE, epoch seconds)
    """
    buf = bytearray(20)
    buf[5] = channel & 0xFF
    buf[6] = 0x3C
    struct.pack_into("<I", buf, 8, begin_epoch & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 12, end_epoch & 0xFFFFFFFF)
    return bytes(buf)


@dataclass(frozen=True, slots=True)
class EventListResponse:
    channel: int
    count: int
    total: int
    records: list[bytes]  # each record is 8 raw bytes, format not yet decoded


@dataclass(frozen=True, slots=True)
class EventRecord:
    start_time: int
    length: int
    event_type: int
    src_event: int
    src_status: int
    driving_mode: bool


EVENT_TYPE_NAMES = {
    3: "Network wakeup",
    4: "Activity detected",
}


def parse_event_record(record: bytes) -> EventRecord:
    """Decode one 8-byte record using Ucon's EventResult field offsets."""
    if len(record) != 8:
        raise ValueError(f"event record must be 8 bytes, got {len(record)}")
    src_event = record[6]
    event_type = src_event & 0x7F
    return EventRecord(
        start_time=struct.unpack_from("<I", record, 0)[0],
        length=struct.unpack_from("<H", record, 4)[0],
        event_type=event_type,
        src_event=src_event,
        src_status=record[7],
        driving_mode=bool(src_event & 0x80),
    )


def parse_list_event_response(data: bytes) -> EventListResponse:
    """Parse IOTYPE_LISTEVENT_RSP (257).
      bytes[0:4]  = channel (u32 LE)
      byte[7]     = count (records in this response)
      bytes[8:10] = total (u16 LE, total records across the queried range)
      bytes[12:]  = `count` * 8-byte records

    NOTE: the 8-byte record layout itself was not fully decoded from the
    Java source (it is copied opaquely into fileByteList); expect to reverse
    it empirically from a real capture (likely: u32 timestamp + u16 index/
    duration + remaining flag/type bytes, mirroring the EventResult fields
    populated elsewhere: stTime, index, offset, fileType).
    """
    channel = struct.unpack_from("<I", data, 0)[0]
    count = data[7]
    total = struct.unpack_from("<H", data, 8)[0]
    records = [bytes(data[12 + i * 8:20 + i * 8]) for i in range(count)]
    return EventListResponse(channel=channel, count=count, total=total, records=records)


def build_event_calendar(begin_epoch: int, end_epoch: int) -> bytes:
    """getEventCalendar(begin, end) -> IOTYPE_RECORD_BITMAP_REQ (258).
    20-byte payload:
      byte[6]      = 0x91 (-111 signed, fixed sub-command marker)
      bytes[8:12]  = begin (u32 LE)
      bytes[12:16] = end   (u32 LE)
    """
    buf = bytearray(20)
    buf[6] = 0x91
    struct.pack_into("<I", buf, 8, begin_epoch & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 12, end_epoch & 0xFFFFFFFF)
    return bytes(buf)


def parse_event_calendar_response(data: bytes, day_count: int = 31) -> list[int]:
    """Parse IOTYPE_RECORD_BITMAP_RSP (259): a per-day bitmap (TFCalendarR in
    the Java source), 8 days per byte, MSB-first within each byte. Returns
    the list of 1-based day numbers that have at least one recording."""
    days_with_events: list[int] = []
    day_number = 0
    for byte_value in data:
        for bit in range(8):
            day_number += 1
            if day_number > day_count:
                return days_with_events
            if (byte_value >> (7 - bit)) & 1:
                days_with_events.append(day_number)
    return days_with_events


def build_download_sd_file(
    file_type: int, start_time_epoch: int, length: int, src_event: int, src_status: int
) -> bytes:
    """downloadSdFile(fileType, stTime, length, srcEvent, srcStatus) ->
    IOTYPE_DOWNLOAD_VIDEO_FILE_REQ (260). 16-byte payload:
      byte[5]      = fileType
      bytes[8:12]  = stTime (u32 LE, epoch seconds identifying the recording)
      bytes[12:14] = length (u16 LE)
      byte[14]     = srcEvent
      byte[15]     = srcStatus
    """
    buf = bytearray(16)
    buf[5] = file_type & 0xFF
    struct.pack_into("<I", buf, 8, start_time_epoch & 0xFFFFFFFF)
    struct.pack_into("<H", buf, 12, length & 0xFFFF)
    buf[14] = src_event & 0xFF
    buf[15] = src_status & 0xFF
    return bytes(buf)


@dataclass(frozen=True, slots=True)
class DownloadSdFileResponse:
    total_size: int
    is_md5_or_crc: int
    checksum_hex: str
    file_name: str


def parse_download_sd_file_response(data: bytes) -> DownloadSdFileResponse:
    """Parse IOTYPE_DOWNLOAD_VIDEO_FILE_RSP (261).
      bytes[8:12]  = total file size (u32 LE)
      byte[6]      = file name length
      byte[7]      = is_md5_or_crc flag
      bytes[12:28] = checksum (16 bytes, md5 or crc depending on the flag)
      bytes[28:28+name_len] = ASCII file name
    """
    total_size = struct.unpack_from("<I", data, 8)[0]
    name_len = data[6]
    is_md5_or_crc = data[7]
    checksum = data[12:28]
    file_name = data[28:28 + name_len].decode("ascii", errors="replace")
    return DownloadSdFileResponse(
        total_size=total_size,
        is_md5_or_crc=is_md5_or_crc,
        checksum_hex=checksum.hex(),
        file_name=file_name,
    )


def build_video_file_data(
    file_type: int,
    timestamp: int,
    channel: int,
    offset: int,
    size: int,
    seq: int = 0,
    extra: bytes = b"",
) -> bytes:
    """getVideoFileData(fileType, timestamp, channel, offset, size, seq, buf)
    -> IOTYPE_VIDEO_FILE_DATA_REQ (262). Fixed 1224-byte payload:
      bytes[4:8]    = timestamp (u32 LE)
      byte[9]       = fileType
      bytes[10:12]  = seq (u16 LE)
      bytes[12:1212]= extra buffer, 1200 bytes (zero-filled unless resuming)
      bytes[1212:1214] = channel (u16 LE)
      bytes[1216:1220] = offset (u32 LE)
      bytes[1220:1224] = size (u32 LE, typically VIDEO_FILE_DATA_CHUNK_SIZE)
    """
    buf = bytearray(1224)
    struct.pack_into("<I", buf, 4, timestamp & 0xFFFFFFFF)
    buf[9] = file_type & 0xFF
    struct.pack_into("<H", buf, 10, seq & 0xFFFF)
    padded_extra = extra[:1200].ljust(1200, b"\x00")
    buf[12:1212] = padded_extra
    struct.pack_into("<H", buf, 1212, channel & 0xFFFF)
    struct.pack_into("<I", buf, 1216, offset & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 1220, size & 0xFFFFFFFF)
    return bytes(buf)


@dataclass(frozen=True, slots=True)
class VideoFileDataResponse:
    file_type: int
    index: int
    offset: int
    size: int
    payload: bytes


def parse_video_file_data_response(data: bytes) -> VideoFileDataResponse:
    """Parse IOTYPE_VIDEO_FILE_DATA_RSP (263).
      byte[10]     = fileType
      bytes[14:16] = index (u16 LE)
      bytes[16:20] = offset (u32 LE)
      bytes[20:24] = size (u32 LE)
      bytes[24:24+size] = raw chunk bytes (video/photo file data)

    NOTE: the Java source has a second code path for thumbnails that copies
    from byte offset 0 instead of 24 - if payload looks wrong for
    FILE_TYPE_THUMBNAIL, try data[0:size] instead of data[24:24+size].
    """
    file_type = data[10]
    index = struct.unpack_from("<H", data, 14)[0]
    offset = struct.unpack_from("<I", data, 16)[0]
    size = struct.unpack_from("<I", data, 20)[0]
    payload = data[24:24 + size]
    return VideoFileDataResponse(file_type=file_type, index=index, offset=offset, size=size, payload=payload)
