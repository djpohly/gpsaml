#!/usr/bin/env python3

# Based partly on information from Peter Williams [1] and partly on manual
# tracing of Duo Web authentication flow.
#
# [1]: https://github.com/pkgw/bibtools/blob/master/harvard-duo-auth-flow.md
#
# It is possible that there may be skippable steps here, but this does work.

import base64
from bs4 import BeautifulSoup
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
    #url = f"https://{host}/global-protect/prelogin.esp"
    r = http.get(url)
    if r.status_code != 200:
        print("Failed to make prelogin request", file=sys.stderr)
        exit(1)

    # Parse HTML page out of SAML request
    saml = ET.fromstring(r.content)
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
    soup = BeautifulSoup(login.content, "html.parser")

    # Fill in next form with username/password
    form = soup.find("form")
    inputs = {e["name"]: e.get("value", None) for e in form("input")}
    inputs["j_username"] = username
    inputs["j_password"] = password

    # Submit form and parse response
    auth_url = urllib.parse.urljoin(login.url, form["action"])
    auth = http.post(auth_url, data=inputs)
    if auth.status_code != 200:
        print("Failed to authenticate step 1", file=sys.stderr)
        exit(1)
    soup = BeautifulSoup(auth.content, "html.parser")

    # Pull information needed to construct API request from iframe tag
    iframe = soup.find("iframe", id="duo_iframe")
    host = iframe["data-host"]
    duo_sig, app_sig = iframe["data-sig-request"].split(":")
    post_act = urllib.parse.urljoin(auth.url, iframe["data-post-action"])
    # Currently doesn't appear to be used in our case
    #post_arg = iframe.get("data-post-argument")

    # Send API request (yes, this is actually a POST with a query string) and
    # parse response
    urienc = urllib.parse.quote(auth_url)
    iframe_url = f"https://{host}/frame/web/v1/auth?tx={duo_sig}&parent={urienc}&v=2.6"
    iframe = http.post(iframe_url)
    if iframe.status_code != 200:
        print("Failed to load Duo frame", file=sys.stderr)
        exit(1)
    soup = BeautifulSoup(iframe.content, "html.parser")

    # Select second factor
    form = soup.find("form")
    print(form, file=sys.stderr)
    inputs = {e["name"]: e.get("value", None) for e in form("input")}
    # Hard-coded since scraping select/option elements is not as easy
    if False:
        inputs["factor"] = "WebAuthn Credential"
        inputs["auth_device_label"] = "Security Key"
        # GET https://api-445a7321.duosecurity.com/frame/prompt/webauthn_auth_popup
        #    ?sid=MTczZThkZmZmMThiNGQ0NmE2ZGViMGFiNWIxNGRjMDA%3D%7C209.147.96.13%7C1642631457%7C63bd486294666027428369627e14ea5b0f66ca0c
        #    &wkey=WAGZIZX4J1NUZRVYIMYN
        # <script ... id="page_data">{"wkey": "WAGZIZX4J1NUZRVYIMYN"}</script>
        # <script ... id="sid">"MTczZThkZmZmMThiNGQ0NmE2ZGViMGFiNWIxNGRjMDA=|209.147.96.13|1642631463|6fcebc102a5dcc0388308cab5262fd0463f0d5ac"</script>
        # POST /frame/prompt
        #    sid=MTczZThkZmZmMThiNGQ0NmE2ZGViMGFiNWIxNGRjMDA=|209.147.96.13|1642631463|6fcebc102a5dcc0388308cab5262fd0463f0d5ac
        #    device=WAGZIZX4J1NUZRVYIMYN
        #    factor=WebAuthn+Credential
        # POST /frame/status
        #    sid=MTczZThkZmZmMThiNGQ0NmE2ZGViMGFiNWIxNGRjMDA=|209.147.96.13|1642631463|6fcebc102a5dcc0388308cab5262fd0463f0d5ac
        #    txid=0ade83f3-e5fe-4267-853a-2a9bef9dc194
    else:
        inputs["factor"] = "Duo Push"
        inputs["device"] = "phone1"
    sid = inputs["sid"]

    # Submit second-factor form
    prompt_url = urllib.parse.urljoin(iframe.url, form["action"])
    prompt = http.post(prompt_url, data=inputs)
    if prompt.status_code != 200:
        print("Failed to load prompt", file=sys.stderr)
        exit(1)
    txid = prompt.json()["response"]["txid"]

    # First POST to /frame/status initiates the push
    status_url = urllib.parse.urljoin(prompt.url, "/frame/status")
    status = http.post(status_url, {"sid": sid, "txid": txid})
    if status.status_code != 200:
        print(f"Failed to get status {status.status_code}", file=sys.stderr)
        exit(1)
    # Second, identical POST to /frame/status waits for response
    status = http.post(status_url, {"sid": sid, "txid": txid})
    if status.status_code != 200:
        print(f"Failed to get status2 {status.status_code}", file=sys.stderr)
        exit(1)

    # Duo cookie is provided in response JSON
    result_url = urllib.parse.urljoin(prompt.url, status.json()["response"]["result_url"])
    result = http.post(result_url, {"sid": sid, "txid": txid})
    if result.status_code != 200:
        print(f"Failed to get result {result.status_code}", file=sys.stderr)
        exit(1)
    js = result.json()["response"]
    signed_duo_response = f"{js['cookie']}:{app_sig}"

    # POST Duo signature back to original form
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


if __name__ == "__main__":
    main()
