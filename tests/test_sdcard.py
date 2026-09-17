from p4p_camera_sdk import parse_event_record
from p4p_camera_sdk.credentials import encode_password
from p4p_camera_sdk.sdcard import EVENT_TYPE_NAMES, build_list_event


def test_event_record_names_and_fields() -> None:
    record = parse_event_record(bytes.fromhex("78563412b4000301"))

    assert record.start_time == 0x12345678
    assert record.length == 0x00B4
    assert record.event_type == 3
    assert record.src_event == 3
    assert record.src_status == 1
    assert EVENT_TYPE_NAMES[record.event_type] == "Network wakeup"


def test_activity_event_preserves_driving_bit() -> None:
    record = parse_event_record(bytes.fromhex("78563412b4008402"))

    assert record.event_type == 4
    assert record.src_event == 0x84
    assert record.driving_mode is True
    assert EVENT_TYPE_NAMES[record.event_type] == "Activity detected"


def test_list_event_request_layout() -> None:
    payload = build_list_event(0x11223344, 0x55667788)

    assert len(payload) == 20
    assert payload[5:7] == b"\x00<"
    assert payload[8:16] == bytes.fromhex("4433221188776655")


def test_password_encoding_uses_vendor_alphabet() -> None:
    assert encode_password("password") == "rgqoFHiJ6Aw9nYFzFVrPDHdIcrE,"
