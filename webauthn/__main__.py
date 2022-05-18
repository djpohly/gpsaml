#!/usr/bin/env python3

# Based partly on information from Peter Williams [1] and partly on manual
# tracing of Duo Web authentication flow.
#
# [1]: https://github.com/pkgw/bibtools/blob/master/harvard-duo-auth-flow.md
#
# It is possible that there may be skippable steps here, but this does work.

import base64
from bs4 import BeautifulSoup
import hashlib
import html
import json
import requests
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

from .impl import Fido2Impl


# Provide username and VPN host as arguments and password on stdin (never
# ever as a command line argument!)
username = sys.argv[1]
host = sys.argv[2]
password = input()

# Use a session to keep cookies
http = requests.Session()

# First retrieve SAML from VPN host
url = f"https://{host}/ssl-vpn/prelogin.esp"
#url = f"https://{host}/global-protect/prelogin.esp"
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

# Submit form and parse response (00-03)
login_url = urllib.parse.urljoin(r.url, form["action"])
login = http.post(login_url, data=inputs)
if login.status_code != 200:
    print("Failed to request login page", file=sys.stderr)
    exit(1)
soup = BeautifulSoup(login.text, "html.parser")

# Fill in next form with username/password
form = soup.find("form")
inputs = {e["name"]: e.get("value", None) for e in form("input")}
inputs["j_username"] = username
inputs["j_password"] = password

# Submit form and parse response (04-05)
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
# Currently doesn't appear to be used in our case
#post_arg = iframe.get("data-post-argument")

# Skip (06) which just leaks system info

# Send API request (yes, this is actually a POST with a query string) and
# parse response (07-08)
urienc = urllib.parse.quote(auth_url)
iframe_url = f"https://{duohost}/frame/web/v1/auth?tx={duo_sig}&parent={urienc}&v=2.6"

iframe = http.post(iframe_url)
if iframe.status_code != 200:
    print("Failed to load Duo frame", file=sys.stderr)
    exit(1)
soup = BeautifulSoup(iframe.text, "html.parser")

# Get the SID from the response (and the other inputs while we're here)
form = soup.find("form")
inputs = {e["name"]: e.get("value", None) for e in form("input")}
sid = inputs["sid"]
wkey = form.find("option", {"name": "webauthn"})["value"]

# Load the WebAuthn pop-up window (09)
popup_params = {
    "sid": sid,
    "wkey": wkey,
}
popup_url = urllib.parse.urljoin(iframe.url, "/frame/prompt/webauthn_auth_popup")

popup = http.get(popup_url, params=popup_params)
if popup.status_code != 200:
    print("Failed to load WebAuthn popup", file=sys.stderr)
    exit(1)
soup = BeautifulSoup(popup.text, "html.parser")

popsid = html.unescape(json.loads(soup.find("script", id="sid").string))

# Get server challenge (10)
prompt_url = urllib.parse.urljoin(popup.url, "/frame/prompt")
prompt = http.post(prompt_url, data={
    "sid": popsid,
    "device": wkey,
    "factor": "WebAuthn Credential",
})
if prompt.status_code != 200:
    print("Failed to load prompt", file=sys.stderr)
    exit(1)
txid = prompt.json()["response"]["txid"]

# First POST to /frame/status gets the challenge (11)
status_url = urllib.parse.urljoin(popup.url, "/frame/status")
challenge_req = http.post(status_url, data={
    "sid": popsid,
    "txid": txid,
})
if challenge_req.status_code != 200:
    print(f"Failed to get challenge {challenge_req.status_code}", file=sys.stderr)
    exit(1)

challengedata = challenge_req.json()["response"]
if challengedata["status_code"] != "webauthn_sent":
    print(f"Failed to get challenge {challengedata['status_code']}", file=sys.stderr)
    exit(1)

options = challengedata["webauthn_credential_request_options"]

scheme, netloc, _, _, _, _ = urllib.parse.urlparse(popup.url)
origin = f"{scheme}://{netloc}"
# TODO: would there ever be an index 1 or higher?
cred = options["allowCredentials"][0]
challenge = options["challenge"]
appid = options['rpId']

clientData = {
    "challenge": challenge,
    "clientExtensions": options["extensions"],
    "hashAlgorithm": "SHA-256",
    "origin": origin,
    "type": "webauthn.get",
}


# Set up key
impl = Fido2Impl(origin)
key = impl.key_for_id(cred["id"])
authenticatorData_b64, sig_hex, clientDataJSON_b64 = impl.get_signature(appid, key, clientData)

# Submit response from hardware token
response_data = {
    "sessionId": options["sessionId"],
    "id": cred["id"],
    "rawId": cred["id"],
    "type": cred["type"],
    "authenticatorData": authenticatorData_b64,
    "clientDataJSON": clientDataJSON_b64,
    "signature": sig_hex,
    "extensionResults": {
        "appid": False,
    },
}

# Provide assertion from U2F key (12)
auth = http.post(prompt_url, data={
    "sid": sid,
    "device": "webauthn_credential",
    "factor": "webauthn_finish",
    "response_data": json.dumps(response_data, separators=(',', ':')),
    "out_of_date": "False",
    "days_out_of_date": "0",
    "days_to_block": "None",
})
if auth.status_code != 200:
    print("Failed to load auth", file=sys.stderr)
    exit(1)
txid2 = auth.json()["response"]["txid"]

# Second POST to /frame/status gets the auth result (13)
result_req = http.post(status_url, data={
    "sid": sid,
    "txid": txid2,
})
if result_req.status_code != 200:
    print(f"Failed to get result {result_req.status_code}", file=sys.stderr)
    exit(1)

resultdata = result_req.json()["response"]
if resultdata["result"] != "SUCCESS":
    print(f"Failed to get result {resultdata['result']}", file=sys.stderr)
    exit(1)

# Final request to get the cookie
finalurl = urllib.parse.urljoin(iframe.url, resultdata["result_url"])
final_req = http.post(finalurl, data={"sid": sid})
if final_req.status_code != 200:
    print(f"Failed to get final {final_req.status_code}", file=sys.stderr)
    exit(1)

finaldata = final_req.json()["response"]
signed_duo_response = f"{finaldata['cookie']}:{app_sig}"

final = http.post(post_act, {"_eventId": "proceed", "sig_response": signed_duo_response})
if final.status_code != 200:
    print(f"Failed to get final {final.status_code}", file=sys.stderr)
    exit(1)

soup = BeautifulSoup(final.content, "html.parser")
form = soup.find("form")
inputs = {e["name"]: e.get("value", None) for e in form("input") if e.get("name") is not None}

# POST again to get prelogin cookie for GlobalProtect
veryfinal_url = urllib.parse.urljoin(final.url, form["action"])
veryfinal = http.post(veryfinal_url, data=inputs)
if veryfinal.status_code != 200:
    print(f"Failed to get veryfinal {veryfinal.status_code}", file=sys.stderr)
    exit(1)
cookie = veryfinal.headers['prelogin-cookie']

# Print authorization cookie to stdout for use with
#     openconnect --usergroup=gateway:prelogin-cookie --passwd-on-stdin
print(cookie)
