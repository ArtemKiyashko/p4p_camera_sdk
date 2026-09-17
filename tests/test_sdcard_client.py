import struct

from p4p_camera_sdk.sdcard import IOTYPE_GET_ADVANCE_SETTINGS_REQ, IOTYPE_LISTEVENT_REQ
from p4p_camera_sdk.sdcard_client import SdCardClient


class FakeSession:
    def __init__(self) -> None:
        self.sent: list[tuple[int, int, bytes]] = []
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

    def poll_ioctrl(self, timeout: float):
        yield from self.responses.pop(0)


def test_list_events_initializes_session_before_listing() -> None:
    session = FakeSession()
    events = SdCardClient(session).list_events(1, 2)

    assert [item[1] for item in session.sent] == [IOTYPE_GET_ADVANCE_SETTINGS_REQ, IOTYPE_LISTEVENT_REQ]
    assert events[0].start_time == 1_700_000_000
    assert events[0].length == 30