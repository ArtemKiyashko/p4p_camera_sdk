import struct

from p4p_camera_sdk.sdcard import (
    IOTYPE_DOWNLOAD_VIDEO_FILE_REQ,
    IOTYPE_GET_ADVANCE_SETTINGS_REQ,
    IOTYPE_LISTEVENT_REQ,
    IOTYPE_VIDEO_FILE_DATA_REQ,
    build_list_event,
)
from p4p_camera_sdk.sdcard_client import (
    IOTYPE_SD_LIVE_COMPANION_REQ,
    RDT_CONTROL,
    RDT_FILE_DATA,
    SD_AVCTRL_PARAM,
    SD_AVCTRL_ST_TIME_DAY,
    SD_LIVE_COMPANION_AFTER_LIST,
    SD_LIVE_COMPANION_INITIAL,
    SdCardClient,
    SdCardEvent,
)


class FakeSession:
    def __init__(self) -> None:
        self.sent: list[tuple[int, int, bytes]] = []
        self.avctrl: list[tuple[int, dict]] = []
        self.responses = [
            [(257, self._event_response())],
        ]

    @staticmethod
    def _event_response() -> bytes:
        record = struct.pack("<IHB B", 1_700_000_000, 30, 4, 0)
        response = bytearray(12)
        response[7] = 1
        struct.pack_into("<H", response, 8, 1)
        return bytes(response) + record

    def send_ioctrl(self, channel: int, iotype: int, data: bytes) -> None:
        self.sent.append((channel, iotype, data))

    def send_ioctrl_batch(self, channel: int, commands: list[tuple[int, bytes]]) -> None:
        for iotype, data in commands:
            self.send_ioctrl(channel, iotype, data)

    def send_avctrl(self, command: int, **kwargs) -> None:
        self.avctrl.append((command, kwargs))

    def wait_for_live_stream(self) -> None:
        pass

    def poll_ioctrl(self, timeout: float):
        yield from self.responses.pop(0)


def test_list_events_initializes_session_before_listing() -> None:
    session = FakeSession()
    events = SdCardClient(session).list_events(1, 2)

    assert [item[1] for item in session.sent] == [
        IOTYPE_GET_ADVANCE_SETTINGS_REQ,
        IOTYPE_SD_LIVE_COMPANION_REQ,
        IOTYPE_LISTEVENT_REQ,
        IOTYPE_SD_LIVE_COMPANION_REQ,
    ]
    assert [item[2] for item in session.sent] == [
        bytes(4),
        SD_LIVE_COMPANION_INITIAL,
        build_list_event(1, 2),
        SD_LIVE_COMPANION_AFTER_LIST,
    ]
    assert session.avctrl == [
        (
            2,
            {
                "playrecord": 0,
                "streamindex": 0,
                "with_audio": 1,
                "st_time_day": SD_AVCTRL_ST_TIME_DAY,
                "param": SD_AVCTRL_PARAM,
            },
        )
    ]
    assert events[0].start_time == 1_700_000_000
    assert events[0].length == 30


def test_list_events_parses_ucon_filename_metadata() -> None:
    session = FakeSession()
    session.responses = [[
        (RDT_CONTROL, b"\x00\x0020260917_142655_995_016_N.jpg\x00"),
    ]]

    events = SdCardClient(session).list_events(1, 2)

    assert events == []


def test_list_events_ignores_rdt_records_outside_requested_range() -> None:
    session = FakeSession()
    session.responses = [[(RDT_CONTROL, bytes.fromhex("050004013b36ab6a"))]]

    events = SdCardClient(session).list_events(1, 2)

    assert events == []


def test_list_events_parses_rdt_event_records() -> None:
    session = FakeSession()
    session.responses = [[(RDT_CONTROL, bytes.fromhex("050004013b36ab6a"))]]

    events = SdCardClient(session).list_events(0x6AAB3630, 0x6AAB3640)

    assert events[0].start_time == 0x6AAB363B
    assert events[0].length == 5
    assert events[0].event_type == 4


def test_download_video_waits_for_metadata_before_file_blocks(tmp_path) -> None:
    session = FakeSession()
    metadata = bytearray(28 + len("clip.mp4"))
    metadata[6] = len("clip.mp4")
    struct.pack_into("<I", metadata, 8, 4)
    metadata[28:] = b"clip.mp4"
    session.responses = [
        [(261, bytes(metadata))],
        [(RDT_FILE_DATA, struct.pack("<II", 0, 4) + b"data")],
    ]

    size = SdCardClient(session).download_video(
        SdCardEvent(start_time=1_700_000_000, length=30, event_type=4, src_event=4, src_status=0),
        tmp_path / "clip.mp4",
    )

    assert size == 4
    assert (tmp_path / "clip.mp4").read_bytes() == b"data"
    assert [item[1] for item in session.sent] == [IOTYPE_DOWNLOAD_VIDEO_FILE_REQ, IOTYPE_VIDEO_FILE_DATA_REQ]


def test_download_video_accepts_rdt_filename_metadata(tmp_path) -> None:
    session = FakeSession()
    session.responses = [
        [(RDT_CONTROL, b"prefix20260917_142535_995_079_N.mp4")],
        [(RDT_FILE_DATA, struct.pack("<II", 0, 4) + b"data")],
    ]

    size = SdCardClient(session).download_video(
        SdCardEvent(start_time=1_700_000_000, length=30, event_type=4, src_event=4, src_status=0),
        tmp_path / "clip.mp4",
    )

    assert size == 4
    assert (tmp_path / "clip.mp4").read_bytes() == b"data"