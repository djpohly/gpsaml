#!/usr/bin/env python3

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialDescriptor as PKCD
from fido2.webauthn import PublicKeyCredentialRequestOptions as PKCRO
from typing import Any


class Fido2Impl:
    def __init__(self, origin: str):
        dev = next(CtapHidDevice.list_devices(), None)
        assert(dev is not None)

        self.client = Fido2Client(dev, origin)

    @staticmethod
    def device_present() -> bool:
        dev = next(CtapHidDevice.list_devices(), None)
        return dev is not None

    def get_signature(self, appid: str, key: PKCD, clientData: dict[str, Any]) -> tuple[str, str, str]:
        result = self.client.get_assertion(PKCRO(
            challenge=websafe_decode(clientData["challenge"]),
            rp_id=appid,
            allow_credentials=[key],
            extensions=clientData["clientExtensions"],
        )).get_response(0)

        return (
            websafe_encode(result.authenticator_data),
            result.signature.hex(),
            websafe_encode(result.client_data),
        )

    def key_for_id(self, keyid_b64: str) -> PKCD:
        return PKCD(type="public-key", id=websafe_decode(keyid_b64))
