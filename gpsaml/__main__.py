#!/usr/bin/env python3

# Based partly on information from Peter Williams [1], partly on manual tracing
# of Duo Web authentication flow with HTTP logging and Wireshark usbmon
# captures.
#
# [1]: https://github.com/pkgw/bibtools/blob/master/harvard-duo-auth-flow.md
#
# It is possible that there may be skippable steps here, but this works for
# both Duo Push and WebAuthn (tested with GoTrust Idem Key).

import base64
from bs4 import BeautifulSoup
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialDescriptor as PKCD
from fido2.webauthn import PublicKeyCredentialRequestOptions as PKCRO
import json
import requests
import sys
import urllib.parse
import xml.etree.ElementTree as ET


def main():
    # Provide username and VPN host as arguments and password on stdin (never
    # ever as a command line argument!)
    username = sys.argv[1]
    host = sys.argv[2]
    password = input()

    # Use a session to keep cookies
    http = requests.Session()

    # First retrieve SAML from VPN host
    url = f"https://{host}/ssl-vpn/prelogin.esp"
    # url = f"https://{host}/global-protect/prelogin.esp"
    r = http.get(url)
    if r.status_code != 200:
        print("Failed to make prelogin request", file=sys.stderr)
        exit(1)

    # Parse HTML page out of SAML request
    saml = ET.fromstring(r.text)
    req = base64.b64decode(saml.find("saml-request").text)
    soup = BeautifulSoup(req, "html.parser")

    # Find form and get pre-set inputs
    form = soup.find("form")
    inputs = {e["name"]: e["value"] for e in form("input")}

    # Submit form and parse response
    login_url = urllib.parse.urljoin(r.url, form["action"])
    login = http.post(login_url, data=inputs)
    if login.status_code != 200:
        print("Failed to request login page", file=sys.stderr)
        exit(1)
    soup = BeautifulSoup(login.text, "html.parser")

    # Fill in next form with username/password
    form = soup.find("form")
    inputs = {e["name"]: e.get("value") for e in form("input")}
    inputs["j_username"] = username
    inputs["j_password"] = password

    # Submit form and parse response
    auth_url = urllib.parse.urljoin(login.url, form["action"])
    auth = http.post(auth_url, data=inputs)
    if auth.status_code != 200:
        print("Failed to authenticate step 1", file=sys.stderr)
        exit(1)
    soup = BeautifulSoup(auth.text, "html.parser")

    # Pull information needed to construct API request from iframe tag
    iframe = soup.find("iframe", id="duo_iframe")
    duohost = iframe["data-host"]
    duo_sig, app_sig = iframe["data-sig-request"].split(":")
    post_act = urllib.parse.urljoin(auth.url, iframe["data-post-action"])

    # Send API request (yes, this is actually a POST with a query string) and
    # parse response
    urienc = urllib.parse.quote(auth_url)
    iframe_url = (
        f"https://{duohost}/frame/web/v1/auth?tx={duo_sig}&parent={urienc}&v=2.6"
    )

    iframe = http.post(iframe_url)
    if iframe.status_code != 200:
        print("Failed to load Duo frame", file=sys.stderr)
        exit(1)
    soup = BeautifulSoup(iframe.text, "html.parser")

    # Get SID from response
    form = soup.find("form")
    sid = form.find("input", {"name": "sid"}).get("value")

    # Default to push
    factor = "Duo Push"
    device = "phone1"

    # Check for hardware key and autoselect second factor
    keydev = next(CtapHidDevice.list_devices(), None)
    if keydev is not None:
        key_elt = form.find("option", {"name": "webauthn"})
        if key_elt:
            factor = "WebAuthn Credential"
            device = key_elt["value"]
        else:
            keydev = None

    # Submit second-factor form
    prompt_url = urllib.parse.urljoin(iframe.url, form["action"])
    prompt = http.post(
        prompt_url,
        data={
            "sid": sid,
            "factor": factor,
            "device": device,
        },
    )
    if prompt.status_code != 200:
        print("Failed to load prompt", file=sys.stderr)
        exit(1)
    txid = prompt.json()["response"]["txid"]

    # First POST to /frame/status issues the challenge/push
    status_url = urllib.parse.urljoin(prompt.url, "/frame/status")
    challenge_req = http.post(
        status_url,
        data={
            "sid": sid,
            "txid": txid,
        },
    )
    if challenge_req.status_code != 200:
        print(f"Failed to get status {challenge_req.status_code}", file=sys.stderr)
        exit(1)

    if keydev is not None:
        # Retrieve challenge from server reply
        challengedata = challenge_req.json()["response"]
        if challengedata["status_code"] != "webauthn_sent":
            print(
                f"Failed to get challenge {challengedata['status_code']}",
                file=sys.stderr,
            )
            exit(1)

        scheme, netloc, _, _, _, _ = urllib.parse.urlparse(prompt.url)
        origin = f"{scheme}://{netloc}"

        options = challengedata["webauthn_credential_request_options"]
        # TODO: would there ever be an index 1 or higher?
        cred = options["allowCredentials"][0]

        # Set up FIDO2 key
        hwkey = Fido2Client(keydev, origin)
        result = hwkey.get_assertion(
            PKCRO(
                challenge=websafe_decode(options["challenge"]),
                rp_id=options["rpId"],
                allow_credentials=[
                    PKCD(
                        type=cred["type"],
                        id=websafe_decode(cred["id"]),
                    )
                ],
                extensions=options["extensions"],
            )
        ).get_response(0)

        # Gather data from FIDO2 key
        response_data = {
            "sessionId": options["sessionId"],
            "id": cred["id"],
            "rawId": cred["id"],
            "type": cred["type"],
            "authenticatorData": websafe_encode(result.authenticator_data),
            "clientDataJSON": websafe_encode(result.client_data),
            "signature": result.signature.hex(),
            "extensionResults": {
                "appid": False,
            },
        }

        # Submit two-factor response
        auth = http.post(
            prompt_url,
            data={
                "sid": sid,
                "device": "webauthn_credential",
                "factor": "webauthn_finish",
                "response_data": json.dumps(response_data, separators=(",", ":")),
                "out_of_date": "False",
                "days_out_of_date": "0",
                "days_to_block": "None",
            },
        )
        if auth.status_code != 200:
            print("Failed to load auth", file=sys.stderr)
            exit(1)

        # New txid is issued for hardware key authentication
        txid = auth.json()["response"]["txid"]

    # Second POST to /frame/status gets the 2FA response
    result_req = http.post(
        status_url,
        data={
            "sid": sid,
            "txid": txid,
        },
    )
    if result_req.status_code != 200:
        print(f"Failed to get result {result_req.status_code}", file=sys.stderr)
        exit(1)

    # Duo cookie is provided in response JSON
    resultdata = result_req.json()["response"]
    if resultdata["result"] != "SUCCESS":
        print(f"Failed to get result {resultdata['result']}", file=sys.stderr)
        exit(1)

    finalurl = urllib.parse.urljoin(iframe.url, resultdata["result_url"])
    final_req = http.post(finalurl, data={"sid": sid})
    if final_req.status_code != 200:
        print(f"Failed to get final {final_req.status_code}", file=sys.stderr)
        exit(1)

    finaldata = final_req.json()["response"]
    signed_duo_response = f"{finaldata['cookie']}:{app_sig}"

    # POST Duo signature back to original form
    final = http.post(
        post_act,
        data={
            "_eventId": "proceed",
            "sig_response": signed_duo_response,
        },
    )
    if final.status_code != 200:
        print(f"Failed to get final {final.status_code}", file=sys.stderr)
        exit(1)

    soup = BeautifulSoup(final.text, "html.parser")
    form = soup.find("form")
    inputs = {e["name"]: e["value"] for e in form("input") if e.get("name") is not None}

    # POST again to get prelogin cookie for GlobalProtect
    veryfinal_url = urllib.parse.urljoin(final.url, form["action"])
    veryfinal = http.post(veryfinal_url, data=inputs)
    if veryfinal.status_code != 200:
        print(f"Failed to get veryfinal {veryfinal.status_code}", file=sys.stderr)
        exit(1)
    cookie = veryfinal.headers["prelogin-cookie"]

    # Print authorization cookie to stdout for use with
    #     openconnect --usergroup=gateway:prelogin-cookie --passwd-on-stdin
    print(cookie)


if __name__ == "__main__":
    main()
