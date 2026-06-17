#!/usr/bin/env python3
"""carrier.py, load per-carrier "bundles" that isolate operator-specific IMS
quirks (the "badtelephony" config) from the otherwise generic SIP/IMS stack.

A bundle is a JSON file named by the leading digits of the IMSI, e.g. ``badtelephony-bundles/311480.json`` for Verizon
(MCC 311, MNC 480). At startup we read the IMSI off the SIM (see sim_aka.py), then pick the bundle whose filename is the
*longest* digit-prefix of that IMSI. That sidesteps the MCC/MNC-length
ambiguity (2- vs 3-digit MNC): the file is simply named with however many
leading digits identify the operator.

If no bundle matches we synthesise a generic one from the 3GPP discovery naming
convention (``ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`` for the home domain,
``epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org`` for the ePDG) so the stack
still works for any operator, it just won't carry that operator's bespoke
header/codec conventions.

Everything operator-specific lives in the bundle; everything device-specific
(IMEI, and thus the +sip.instance URN) stays on the CLI/CONFIG; everything
subscriber-specific (IMSI, MSISDN) comes from the SIM or the CLI.
"""
from __future__ import annotations

import glob
import json
import os

BUNDLE_DIR_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "badtelephony-bundles")

# Device identity (IMEI) is NOT carrier-specific and is deliberately kept out of
# source: supply it with --imei or in this gitignored file. See the shipped
# device_config.example.json template.
DEVICE_CONFIG_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "device_config.json")

# Generic 3GPP-standard defaults; a bundle overrides only what the operator
# does differently. These are deliberately minimal and standards-compliant.
GENERIC_DEFAULTS = {
    "name": "Generic (3GPP)",
    "transport": "tcp",
    "user_agent": "BadTelephony/1.0",
    "p_access_network_info": "IEEE-802.11;i-wlan-node-id=000000000000",
    # Feature tags appended to the Contact header. "{imei_urn}" is substituted
    # with the device's urn:gsma:imei:... at build time.
    "contact_features": [
        '+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"',
        '+sip.instance="<{imei_urn}>"',
        "audio",
    ],
    # MO offer codec set, most-preferred first. Names map to SDP in build_sdp.
    "mo_codecs": ["amr-wb", "evs"],
    "notes": "",
}


class Bundle:
    """An operator profile: the parsed bundle plus the generic fallbacks."""

    def __init__(self, data, source):
        self.source = source                      # where it came from (for logs)
        d = dict(GENERIC_DEFAULTS)
        d.update({k: v for k, v in (data or {}).items() if v is not None})
        self.name = d["name"]
        self.mccmnc = d.get("mccmnc")
        self.domain = d["domain"]                 # IMS home domain / realm
        self.transport = d["transport"]           # Gm transport: tcp/udp
        self.user_agent = d["user_agent"]
        self.pani = d["p_access_network_info"]
        self.contact_features = list(d["contact_features"])
        self.mo_codecs = list(d["mo_codecs"])
        self.epdg = d.get("epdg")
        self.notes = d.get("notes", "")

    def contact_features_str(self, imei_urn=""):
        """Render the Contact feature tags as ';tag;tag...' for appending."""
        out = []
        for f in self.contact_features:
            out.append(f.replace("{imei_urn}", imei_urn))
        return "".join(";" + f for f in out)

    def describe(self):
        return (f"{self.name} [{self.source}] domain={self.domain} "
                f"transport={self.transport} codecs={','.join(self.mo_codecs)}")


def split_mcc_mnc(imsi, mnc_len=None):
    """Split an IMSI into (mcc, mnc). If mnc_len is unknown, guess: North
    American MCCs (3xx) use 3-digit MNCs, most others 2 a heuristic only used
    for the discovery fallback, but like also its generally true. 
    Eventually I should probably just hardcode the list for https://www.itu.int/dms_pub/itu-t/opb/sp/T-SP-E.212B-2018-PDF-E.pdf 
    but also hopefully someone will just make the bundles for the other 3-digit MNCs. """
    mcc = imsi[:3]
    if mnc_len not in (2, 3):
        mnc_len = 3 if mcc.startswith("3") else 2
    return mcc, imsi[3:3 + mnc_len]


def discovery_names(imsi, mnc_len=None):
    """3GPP TS 23.003 home-network / ePDG FQDNs for an IMSI. Used when we don't have a carrier bundle"""
    mcc, mnc = split_mcc_mnc(imsi, mnc_len)
    mcc3, mnc3 = mcc.zfill(3), mnc.zfill(3)
    home = f"ims.mnc{mnc3}.mcc{mcc3}.3gppnetwork.org"
    epdg = f"epdg.epc.mnc{mnc3}.mcc{mcc3}.pub.3gppnetwork.org"
    return home, epdg, mcc, mnc


def find_bundle_file(imsi, bundles_dir):
    """The bundle file whose digit-name is the longest prefix of the IMSI."""
    best, best_len = None, -1
    for path in glob.glob(os.path.join(bundles_dir, "*.json")):
        stem = os.path.splitext(os.path.basename(path))[0]
        digits = "".join(ch for ch in stem if ch.isdigit())
        if digits and imsi.startswith(digits) and len(digits) > best_len:
            best, best_len = path, len(digits)
    return best


def load(imsi, bundles_dir=None, mnc_len=None):
    """Resolve the operator bundle for an IMSI, falling back to 3GPP discovery."""
    bundles_dir = bundles_dir or BUNDLE_DIR_DEFAULT
    path = find_bundle_file(imsi, bundles_dir)
    if path:
        with open(path) as f:
            data = json.load(f)
        data.setdefault("mccmnc", os.path.splitext(os.path.basename(path))[0])
        return Bundle(data, source=os.path.basename(path))
    home, epdg, mcc, mnc = discovery_names(imsi, mnc_len)
    data = {
        "name": f"Generic MCC{mcc}/MNC{mnc} (3GPP discovery)",
        "mccmnc": mcc + mnc,
        "domain": home,
        "epdg": epdg,
        "notes": "No bundle matched this IMSI; using 3GPP discovery FQDNs. "
                 "Drop a badtelephony-bundles/<mccmnc>.json to customise.",
    }
    return Bundle(data, source="3gpp-discovery")


def resolve_imsi(cli_imsi=None, reader=0):
    """Return (imsi, mnc_len). Use the CLI value if given, else read the SIM."""
    if cli_imsi:
        return cli_imsi, None
    import sim_aka
    info = sim_aka.read_subscriber(reader_index=reader)
    return info["imsi"], info.get("mnc_len")


def resolve_imei(cli_imei=None, path=None):
    """Device IMEI from --imei, else device_config.json. Never hard-coded so the
    source can be released without leaking a real device identity."""
    if cli_imei:
        return cli_imei
    path = path or DEVICE_CONFIG_DEFAULT
    if os.path.exists(path):
        with open(path) as f:
            imei = (json.load(f) or {}).get("imei")
        if imei:
            return str(imei)
    raise SystemExit(
        f"No IMEI configured. Pass --imei <15 digits>, or create {path} "
        '(see device_config.example.json): {"imei": "..."}')
