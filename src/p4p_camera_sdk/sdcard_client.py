"""High-level SD-card operations over an established P4P relay session."""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .sdcard import (
    FILE_TYPE_VIDEO,
    IOTYPE_DOWNLOAD_VIDEO_FILE_REQ,
    IOTYPE_GET_ADVANCE_SETTINGS_REQ,
    IOTYPE_LISTEVENT_REQ,
    IOTYPE_LISTEVENT_RSP,
    IOTYPE_VIDEO_FILE_DATA_REQ,
    VIDEO_FILE_DATA_CHUNK_SIZE,
    build_download_sd_file,
    build_list_event,
    build_video_file_data,
    parse_event_record,
    parse_list_event_response,
)

if TYPE_CHECKING:
    from .relay import RelaySession

RDT_FILE_DATA = 0x10000 + 0x1000004
RDT_CONTROL = 0x10000 + 0x04
RDT_METADATA = 0x10000 + 0x13
LOGGER = logging.getLogger(__name__)
FILENAME_RE = re.compile(rb"(20\d{6})_(\d{6})_\d{3}_\d{3}_N\.(?:jpg|jp\+ELE|mp4)")


@dataclass(frozen=True, slots=True)
class SdCardEvent:
    start_time: int
    length: int
    event_type: int
    src_event: int
    src_status: int


class SdCardClient:
    def __init__(self, session: RelaySession, channel: int = 0) -> None:
        self._session = session
        self._channel = channel

    def list_events(self, begin_epoch: int, end_epoch: int) -> list[SdCardEvent]:
        self._session.send_ioctrl(self._channel, IOTYPE_GET_ADVANCE_SETTINGS_REQ, bytes(4))
        self._session.send_ioctrl(
            self._channel,
            IOTYPE_LISTEVENT_REQ,
            build_list_event(begin_epoch, end_epoch, self._channel),
        )
        events: list[SdCardEvent] = []
        frame_counts: dict[int, int] = {}
        for iotype, data in self._session.poll_ioctrl(timeout=12):
            frame_counts[iotype] = frame_counts.get(iotype, 0) + 1
            if iotype != IOTYPE_LISTEVENT_RSP:
                if iotype not in (RDT_CONTROL, RDT_METADATA):
                    continue
                for match in FILENAME_RE.finditer(data):
                    start_time = int(
                        datetime.strptime(
                            f"{match.group(1).decode()}_{match.group(2).decode()}",
                            "%Y%m%d_%H%M%S",
                        )
                        .replace(tzinfo=UTC)
                        .timestamp()
                    )
                    if not any(event.start_time == start_time for event in events):
                        events.append(SdCardEvent(start_time, 0, 4, 0, 0))
                continue
            response = parse_list_event_response(data)
            events.extend(
                SdCardEvent(
                    start_time=record.start_time,
                    length=record.length,
                    event_type=record.event_type,
                    src_event=record.src_event,
                    src_status=record.src_status,
                )
                for raw in response.records
                for record in [parse_event_record(raw)]
                if record.length > 0
            )
        LOGGER.info("SD event-list response frames: %s", frame_counts)
        return events

    def download_video(self, event: SdCardEvent, destination: Path) -> int:
        self._session.send_ioctrl(
            self._channel,
            IOTYPE_DOWNLOAD_VIDEO_FILE_REQ,
            build_download_sd_file(
                FILE_TYPE_VIDEO,
                event.start_time,
                event.length,
                event.src_event,
                event.src_status,
            ),
        )
        content = bytearray()
        offset = 0
        while True:
            size = VIDEO_FILE_DATA_CHUNK_SIZE
            self._session.send_ioctrl(
                self._channel,
                IOTYPE_VIDEO_FILE_DATA_REQ,
                build_video_file_data(
                    FILE_TYPE_VIDEO,
                    event.start_time,
                    self._channel,
                    offset,
                    size,
                    seq=offset // VIDEO_FILE_DATA_CHUNK_SIZE,
                ),
            )
            block = self._receive_block(offset)
            content.extend(block)
            offset += len(block)
            if len(block) < size:
                break
            if offset > 100 * 1024 * 1024:
                raise RuntimeError("camera video exceeded the 100 MiB transfer limit")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        return len(content)

    def _receive_block(self, expected_offset: int) -> bytes:
        for iotype, data in self._session.poll_ioctrl(timeout=8):
            if iotype != RDT_FILE_DATA or len(data) < 8:
                continue
            offset, size = struct.unpack_from("<II", data, 0)
            if offset != expected_offset or size <= 0 or size > len(data) - 8:
                continue
            return data[8:8 + size]
        raise TimeoutError(f"timed out waiting for video block at offset {expected_offset}")
