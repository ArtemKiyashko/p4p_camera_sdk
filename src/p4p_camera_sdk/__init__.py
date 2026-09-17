"""Reusable P4P relay/KCP and Ucon SD-card protocol primitives."""

from .credentials import CredentialClient, DeviceCredentials, encode_password
from .sdcard import EventRecord, parse_event_record

__all__ = [
	"RDT_IOTYPE_BASE",
	"CredentialClient",
	"DeviceCredentials",
	"EventRecord",
	"RelaySession",
	"encode_password",
	"parse_event_record",
]


def __getattr__(name: str):
	if name in {"RDT_IOTYPE_BASE", "RelaySession"}:
		from .relay import RDT_IOTYPE_BASE, RelaySession

		return {"RDT_IOTYPE_BASE": RDT_IOTYPE_BASE, "RelaySession": RelaySession}[name]
	raise AttributeError(name)
