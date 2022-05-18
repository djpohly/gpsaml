#!/usr/bin/env python3

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialDescriptor as PKCD
from fido2.webauthn import PublicKeyCredentialRequestOptions as PKCRO


class Fido2Impl:
    def __init__(self, origin):
        dev = next(CtapHidDevice.list_devices(), None)
        assert(dev is not None)

        self.client = Fido2Client(dev, origin)

    def get_signature(self, appid, key: PKCD, clientData):
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

    def key_for_id(self, keyid_b64: str):
        return PKCD(type="public-key", id=websafe_decode(keyid_b64))
