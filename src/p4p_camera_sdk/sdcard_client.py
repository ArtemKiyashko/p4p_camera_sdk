"""High-level SD-card operations over an established P4P relay session."""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .sdcard import (
    FILE_TYPE_VIDEO,
    IOTYPE_DOWNLOAD_VIDEO_FILE_REQ,
    IOTYPE_DOWNLOAD_VIDEO_FILE_RSP,
    IOTYPE_GET_ADVANCE_SETTINGS_REQ,
    IOTYPE_LISTEVENT_REQ,
    IOTYPE_LISTEVENT_RSP,
    IOTYPE_VIDEO_FILE_DATA_REQ,
    VIDEO_FILE_DATA_CHUNK_SIZE,
    build_download_sd_file,
    build_list_event,
    build_video_file_data,
    parse_download_sd_file_response,
    parse_event_record,
    parse_list_event_response,
    parse_rdt_event_records,
)

if TYPE_CHECKING:
    from .relay import RelaySession

RDT_FILE_DATA = 0x10000 + 0x1000004
RDT_CONTROL = 0x10000 + 0x04
RDT_METADATA = 0x10000 + 0x13
IOTYPE_SD_LIVE_COMPANION_REQ = 0x211A
SD_LIST_TIMEOUT = 90.0
SD_DOWNLOAD_METADATA_TIMEOUT = 60.0
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
        self._session.wait_for_live_stream()
        self._session.send_ioctrl(self._channel, IOTYPE_GET_ADVANCE_SETTINGS_REQ, bytes(4))
        self._session.send_ioctrl(self._channel, IOTYPE_SD_LIVE_COMPANION_REQ, bytes(4))
        self._session.send_avctrl(2, playrecord=0, streamindex=0, with_audio=1, param=0)
        self._session.send_ioctrl(
            self._channel,
            IOTYPE_LISTEVENT_REQ,
            build_list_event(begin_epoch, end_epoch, self._channel),
        )
        self._session.send_ioctrl(self._channel, IOTYPE_GET_ADVANCE_SETTINGS_REQ, bytes(4))
        events: list[SdCardEvent] = []
        frame_counts: dict[int, int] = {}
        for iotype, data in self._session.poll_ioctrl(timeout=SD_LIST_TIMEOUT):
            frame_counts[iotype] = frame_counts.get(iotype, 0) + 1
            if iotype != IOTYPE_LISTEVENT_RSP:
                if iotype not in (RDT_CONTROL, RDT_METADATA):
                    continue
                if iotype == RDT_CONTROL:
                    for record in parse_rdt_event_records(data):
                        if not begin_epoch <= record.start_time <= end_epoch:
                            continue
                        if not any(event.start_time == record.start_time for event in events):
                            events.append(
                                SdCardEvent(
                                    start_time=record.start_time,
                                    length=record.length,
                                    event_type=record.event_type,
                                    src_event=record.src_event,
                                    src_status=record.src_status,
                                )
                            )
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
        self._receive_download_metadata()
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

    def _receive_download_metadata(self) -> None:
        for iotype, data in self._session.poll_ioctrl(timeout=SD_DOWNLOAD_METADATA_TIMEOUT):
            if iotype == IOTYPE_DOWNLOAD_VIDEO_FILE_RSP:
                metadata = parse_download_sd_file_response(data)
                LOGGER.info(
                    "SD download metadata: file=%s size=%d checksum=%s",
                    metadata.file_name,
                    metadata.total_size,
                    metadata.checksum_hex,
                )
                return
            if iotype == RDT_CONTROL:
                match = FILENAME_RE.search(data)
                if match:
                    LOGGER.info("SD RDT download metadata: file=%s", match.group().decode("ascii"))
                    return
        raise TimeoutError("timed out waiting for SD download metadata")

    def _receive_block(self, expected_offset: int) -> bytes:
        for iotype, data in self._session.poll_ioctrl(timeout=8):
            if iotype != RDT_FILE_DATA or len(data) < 8:
                continue
            offset, size = struct.unpack_from("<II", data, 0)
            if offset != expected_offset or size <= 0 or size > len(data) - 8:
                continue
            return data[8:8 + size]
        raise TimeoutError(f"timed out waiting for video block at offset {expected_offset}")
