"""Ucon REST login and device-credential discovery."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from uuid import uuid4

HOST = "https://portal-uni-acc.ubiam.com"
USER_AGENT = "ucon/2.0.10"


def encode_password(plaintext: str) -> str:
    digest = hmac.new(b"", plaintext.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii").translate(str.maketrans("+/=", "-_,"))


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    device_uid: str
    device_password: str
    device_name: str


class CredentialClient:
    def __init__(self, account: str, password: str, host: str = HOST) -> None:
        self._account = account
        self._password = password
        self._host = host.rstrip("/")

    async def get_device(self, index: int = 0) -> DeviceCredentials:
        import httpx

        app_uuid = str(uuid4())
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
            "X-Ubiaapi-Callcontext": f"source=app&app=ucon&ver=2.0.10&uuid={app_uuid}&lang=en",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            login = await client.post(
                f"{self._host}/api/v3/login",
                headers=headers,
                json={
                    "account": self._account,
                    "password": encode_password(self._password),
                    "app": "ucon",
                    "app_version": "2.0.10",
                    "device_type": 1,
                    "lang": "en",
                    "brand": "Linux",
                },
            )
            login.raise_for_status()
            login_data = login.json()
            if login_data.get("code") != 0:
                raise RuntimeError("Ucon login rejected")
            data = login_data.get("data", {})
            token = data.get("Token") or data.get("token")
            if not token:
                raise RuntimeError("Ucon login response did not contain a token")
            authenticated_headers = {
                **headers,
                "X-Ubia-Auth-Usertoken": token,
                "X-Ubiaapi-Callcontext": (
                    f"source=app&app=ucon&ver=2.0.10&uuid={data.get('uuid', app_uuid)}&lang=en"
                ),
            }
            response = await client.post(
                f"{self._host}/api/v2/user/device_list",
                headers=authenticated_headers,
                json={},
            )
            response.raise_for_status()
            result = response.json()
            if result.get("code") != 0:
                raise RuntimeError("Ucon device list request rejected")
            devices = result.get("data", {}).get("infos", [])
            if not 0 <= index < len(devices):
                raise IndexError(f"device index {index} is out of range")
            device = devices[index]
            return DeviceCredentials(
                device_uid=device["device_uid"],
                device_password=device["device_pwd"],
                device_name=device.get("device_name", ""),
            )
