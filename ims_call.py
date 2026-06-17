#!/usr/bin/env python3
"""
ims_call.py, register to IMS over an existing ePDG tunnel,
then place an MO call (INVITE) to an MSISDN so the far end RINGS.

SIGNALLING ONLY, this is NOT a real client. It can just place phone calls. the goal is a ring + a readable answer SDP so we
can confirm the codec (AMR-WB vs EVS). An answered call won't have audio.

    sudo ip netns exec ims python3 ims_call.py \
        --pcscf <THIS session's P-CSCF> \
        --msisdn +1YOURNUMBER --to +1NUMBERYOURECALLiNG

The IMSI is read from the SIM (PC/SC) and selects the operator bundle in
badtelephony-bundles/ (named by MCC+MNC), which supplies the home domain,
User-Agent, codecs and Contact feature tags. Pass --imsi to override.
"""
from __future__ import annotations

import argparse
import re
import secrets
import socket
import sys
import time

import sim_aka
import carrier

# 3GPP-standard constants (not operator-specific, I think...).
MMTEL_ICSI = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
ALLOW = ("Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,"
         "REFER,UPDATE")

CONFIG = {"imei": None, "impu": ""}

# The active operator profile (User-Agent, PANI, Contact feature tags, domain,
# codecs, ...). Set from carrier.load() in main(); ims_proxy sets ims.BUNDLE too.
# Everything operator-specific is read through this so nothing is hard-coded.
BUNDLE = carrier.Bundle({"domain": ""}, source="unset")


# text/SIP helpers
def vh(ip):
    return f"[{ip}]" if ":" in ip else ip


def br():
    return "z9hG4bK" + secrets.token_hex(8)


def parse_headers(raw: str):
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = lines[0]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    return status, headers, body


def auth_param(value: str, name: str):
    m = re.search(name + r'\s*=\s*"?([^",]+)"?', value, re.I)
    return m.group(1) if m else None


def status_code(status: str) -> int:
    m = re.search(r"\s(\d{3})\s", " " + status + " ")
    return int(m.group(1)) if m else 0


def get_uri(header_value: str) -> str:
    m = re.search(r"<([^>]+)>", header_value)
    return m.group(1) if m else header_value.split(";")[0].strip()


def get_tag(header_value: str):
    m = re.search(r";tag=([^;>\s]+)", header_value)
    return m.group(1) if m else None


def record_route_set(headers: dict) -> list:
    rrs = []
    for hv in headers.get("record-route", []):
        for part in hv.split(","):
            part = part.strip()
            if part:
                rrs.append(get_uri(part))
    return rrs


# IMS-AKA digest now lives in sim_aka (decode_aka_nonce / aka_challenge /
# aka_password / digest_response) so all three SIP clients share one copy.


def imei_urn(imei):
    d = "".join(c for c in imei if c.isdigit())
    if len(d) == 15:
        return f"urn:gsma:imei:{d[:8]}-{d[8:14]}-{d[14:]}"
    return f"urn:gsma:imei:{d}"


# transport (TCP framed / UDP)
class Transport:
    """One connection to the P-CSCF. TCP frames by Content-Length; UDP is 1:1."""

    def __init__(self, fam, local, src_port, pcscf, port, proto, timeout):
        self.proto, self.pcscf, self.port = proto, pcscf, port
        kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        self.sock = socket.socket(fam, kind)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)
        if proto == "tcp":
            if local:
                self.sock.bind((local, 0))
            self.sock.connect((pcscf, port))
        else:
            self.sock.bind((local, src_port))
        self.local = self.sock.getsockname()[0]
        self.local_port = self.sock.getsockname()[1]
        self.buf = b""

    def send(self, msg):
        data = msg.encode()
        if self.proto == "tcp":
            self.sock.sendall(data)
        else:
            self.sock.sendto(data, (self.pcscf, self.port))

    def _extract(self):
        if b"\r\n\r\n" not in self.buf:
            return None
        head, sep, rest = self.buf.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    clen = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
        if len(rest) < clen:
            return None
        msg = head + sep + rest[:clen]
        self.buf = rest[clen:]
        return msg.decode(errors="replace")

    def recv(self, timeout):
        self.sock.settimeout(timeout)
        if self.proto == "udp":
            data, _ = self.sock.recvfrom(65535)
            return data.decode(errors="replace")
        while True:
            msg = self._extract()
            if msg is not None:
                return msg
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("P-CSCF closed the TCP connection")
            self.buf += chunk


def detect_local(pcscf, port, fam):
    p = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        p.connect((pcscf, port))
        return p.getsockname()[0]
    finally:
        p.close()


# contact
def contact_hdr(impu_user, local, port, proto):
    tp = ";transport=tcp" if proto == "tcp" else ""
    feats = BUNDLE.contact_features_str(imei_urn(CONFIG["imei"]))
    return f"Contact: <sip:{impu_user}@{vh(local)}:{port}{tp}>{feats}"


# REGISTER (proven flow, TCP)
def register(args, T, local, src_port):
    home = args.domain
    impu = f"sip:{args.msisdn}@{home}"
    impi = f"{args.imsi}@{home}"
    call_id = secrets.token_hex(12)
    ftag = secrets.token_hex(6)
    tp = args.transport.upper()

    def reg_msg(cseq, auth=None):
        lines = [
            f"REGISTER sip:{home} SIP/2.0",
            f"Via: SIP/2.0/{tp} {vh(local)}:{src_port};branch={br()};rport",
            "Max-Forwards: 70",
            f"From: <{impu}>;tag={ftag}",
            f"To: <{impu}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            contact_hdr(args.msisdn, local, src_port, args.transport),
        ]
        lines.append(auth or
                     f'Authorization: Digest nonce="",uri="sip:{home}",'
                     f'realm="{home}",username="{impi}",response=""')
        lines += [ALLOW, f"User-Agent: {BUNDLE.user_agent}",
                  "Supported: 100rel,path,replaces",
                  f"P-Access-Network-Info: {BUNDLE.pani}",
                  "Expires: 600000", "Content-Length: 0", "", ""]
        return "\r\n".join(lines)

    T.send(reg_msg(1))
    status, headers, _ = parse_headers(T.recv(args.timeout))
    if status_code(status) != 401:
        sys.exit(f"REGISTER: expected 401, got {status.strip()}")

    wmark = headers.get("www-authenticate", [""])[0]
    nonce = auth_param(wmark, "nonce")
    realm = auth_param(wmark, "realm") or home
    qop = auth_param(wmark, "qop")
    algo = auth_param(wmark, "algorithm") or "AKAv1-MD5"
    q = sim_aka.aka_challenge(nonce, reader_index=args.reader)
    passwd = sim_aka.aka_password(q["res"], q["ik"], q["ck"], algo)

    nc, cnonce = "00000001", secrets.token_hex(8)
    uri = f"sip:{home}"
    rsp = sim_aka.digest_response(impi, realm, passwd, "REGISTER", uri, nonce,
                                  qop=qop, cnonce=cnonce, nc=nc)
    auth = (f'Authorization: Digest username="{impi}",realm="{realm}",'
            f'nonce="{nonce}",uri="{uri}",response="{rsp}",algorithm={algo}')
    if qop:
        auth += f',qop={qop},nc={nc},cnonce="{cnonce}"'
    T.send(reg_msg(2, auth))
    status2, headers2, _ = parse_headers(T.recv(args.timeout))
    if status_code(status2) != 200:
        sys.exit(f"REGISTER: expected 200, got {status2.strip()}")

    svc = []
    for hv in headers2.get("service-route", []):
        for part in hv.split(","):
            if part.strip():
                svc.append(get_uri(part.strip()))
    print(f"*** REGISTERED ({tp}) ***  service-route:",
          svc if svc else "(none: we're routing via P-CSCF)")
    return {"home": home, "impu": impu, "impi": impi, "service_route": svc}


# SDP stufs
def build_sdp(local, rtp_port, codecs):
    """codecs: ordered list drawn from the bundle, e.g. ['amr-wb','evs']."""
    pts, lines = [], []
    if "evs" in codecs:
        pts.append("97")
        lines += ["a=rtpmap:97 EVS/16000/1",
                  "a=fmtp:97 br=5.9-24.4;bw=nb-swb;ch-aw-recv=-1;mode-switch=0"]
    if "amr-wb" in codecs:
        pts.append("104")
        lines += ["a=rtpmap:104 AMR-WB/16000/1",
                  "a=fmtp:104 mode-change-capability=2;max-red=0"]
    if "amr-nb" in codecs:
        pts.append("96")
        lines += ["a=rtpmap:96 AMR/8000", "a=fmtp:96 mode-set=7;max-red=0"]
    if "pcmu" in codecs:
        pts.append("0")
        lines += ["a=rtpmap:0 PCMU/8000"]
    pts.append("100")
    lines += ["a=rtpmap:100 telephone-event/16000", "a=fmtp:100 0-15"]
    sid = secrets.randbelow(2**31)
    sdp = ["v=0", f"o=- {sid} {sid} IN IP6 {local}", "s=-",
           f"c=IN IP6 {local}", "b=AS:49", "b=RS:625", "b=RR:1875", "t=0 0",
           f"m=audio {rtp_port} RTP/AVP {' '.join(pts)}"] + lines + \
          ["a=ptime:20", "a=maxptime:240", "a=sendrecv", f"a=rtcp:{rtp_port + 1}"]
    return "\r\n".join(sdp) + "\r\n"


# INVITE + in-dialog
def via(local, src_port, proto):
    return (f"Via: SIP/2.0/{proto.upper()} {vh(local)}:{src_port}"
            f";branch={br()};rport")


def build_invite(args, st, local, src_port, rtp_port, call_id, ftag, branch):
    target = f"tel:{args.to}"
    sdp = build_sdp(local, rtp_port, args.codecs)
    lines = [
        f"INVITE {target} SIP/2.0",
        f"Via: SIP/2.0/{args.transport.upper()} {vh(local)}:{src_port}"
        f";branch={branch};rport",
        "Max-Forwards: 70",
    ]
    for rr in st["service_route"]:
        lines.append(f"Route: <{rr}>")
    lines += [
        f"From: <{st['impu']}>;tag={ftag}",
        f"To: <{target}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        contact_hdr(args.msisdn, local, src_port, args.transport),
        f"P-Preferred-Identity: <{st['impu']}>",
        f"P-Access-Network-Info: {BUNDLE.pani}",
        f'Accept-Contact: *;+g.3gpp.icsi-ref="{MMTEL_ICSI}"',
        "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel",
        ALLOW, "Supported: 100rel,timer,replaces",
        "Session-Expires: 1800", "Min-SE: 90",
        f"User-Agent: {BUNDLE.user_agent}",
        "Content-Type: application/sdp",
        f"Content-Length: {len(sdp.encode())}",
        "", sdp,
    ]
    return "\r\n".join(lines)


def in_dialog(method, args, st, local, src_port, call_id, ftag, rtag,
              route, target, cseq, extra=None):
    lines = [f"{method} {target} SIP/2.0",
             via(local, src_port, args.transport), "Max-Forwards: 70"]
    for r in route:
        lines.append(f"Route: <{r}>")
    lines += [
        f"From: <{st['impu']}>;tag={ftag}",
        f"To: <tel:{args.to}>" + (f";tag={rtag}" if rtag else ""),
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
    ]
    if extra:
        lines += extra
    lines += ["Content-Length: 0", "", ""]
    return "\r\n".join(lines)


def summarize_sdp(body: str):
    for ln in body.split("\n"):
        ln = ln.strip()
        if ln.startswith("m=") or ln.startswith("a=rtpmap"):
            print("    SDP>", ln)


# call flow
def run_call(args):
    fam = socket.AF_INET6 if ":" in args.pcscf else socket.AF_INET
    if args.transport == "udp" and not args.local:
        args.local = detect_local(args.pcscf, args.port, fam)
    T = Transport(fam, args.local, args.src_port, args.pcscf, args.port,
                  args.transport, args.timeout)
    local, src_port = T.local, T.local_port
    print(f"local: {local}:{src_port} ({args.transport})", file=sys.stderr)

    st = register(args, T, local, src_port)
    CONFIG["impu"] = st["impu"]

    try:
        rtp = socket.socket(fam, socket.SOCK_DGRAM)
        rtp.bind((local, args.rtp_port))
        rtp_port = rtp.getsockname()[1]
    except OSError:
        rtp_port = args.rtp_port

    call_id = secrets.token_hex(12)
    ftag = secrets.token_hex(6)
    branch = br()
    target = f"tel:{args.to}"

    inv = build_invite(args, st, local, src_port, rtp_port,
                       call_id, ftag, branch)
    print(f"\n--- INVITE -> {args.to} ({args.transport}, "
          f"codecs {','.join(args.codecs)}) --->")
    print(inv)
    T.send(inv)

    route = list(st["service_route"])
    rtag, remote_target = None, target
    pracked, next_cseq, invite_cseq = set(), 2, 1
    final, ringing = None, False
    deadline = time.time() + args.ring_time

    try:
        while time.time() < deadline:
            try:
                resp = T.recv(max(0.5, deadline - time.time()))
            except socket.timeout:
                break
            status, headers, body = parse_headers(resp)
            code = status_code(status)
            cseqh = headers.get("cseq", [""])[0]
            if "INVITE" not in cseqh and code:          # PRACK/UPDATE responses
                print(f"<--- {status.strip()}  ({cseqh})")
                continue
            print(f"\n<--- {status.strip()}")

            if get_tag(headers.get("to", [""])[0]):
                rtag = get_tag(headers["to"][0])
            rr = record_route_set(headers)
            if rr:
                route = list(reversed(rr))
            if headers.get("contact"):
                remote_target = get_uri(headers["contact"][0])

            if 100 <= code < 200:
                if code == 180:
                    ringing = True
                    print("    *** 180 RINGING: your phone should be ringing (or we got blackholed by Verizon. This happens sometimes just like wait 24 hours) ***")
                elif code == 183:
                    print("    183 Session Progress (early media / preconditions)")
                if body.strip():
                    summarize_sdp(body)
                rseq = headers.get("rseq", [None])[0]
                req = " ".join(headers.get("require", [])).lower()
                if rseq and "100rel" in req and rseq not in pracked:
                    pracked.add(rseq)
                    print(f"    -> PRACK rseq={rseq}")
                    T.send(in_dialog("PRACK", args, st, local, src_port,
                                     call_id, ftag, rtag, route, remote_target,
                                     next_cseq,
                                     extra=[f"RAck: {rseq} {invite_cseq} INVITE"]))
                    next_cseq += 1
                continue

            final = code
            if 200 <= code < 300:
                print("    *** 200 OK: CALL ANSWERED!! ***")
                if body.strip():
                    summarize_sdp(body)
                T.send(in_dialog("ACK", args, st, local, src_port, call_id,
                                 ftag, rtag, route, remote_target, invite_cseq))
                print("    (no RTP wired: hanging up in 2s)")
                time.sleep(2)
                T.send(in_dialog("BYE", args, st, local, src_port, call_id,
                                 ftag, rtag, route, remote_target, next_cseq))
            else:
                print(f"    call failed: {status.strip()}")
                for r in headers.get("reason", []):
                    print("    Reason:", r)
            break

        if final is None:
            print("\n(no final response: cancelling)")
            T.send("\r\n".join([
                f"CANCEL {target} SIP/2.0",
                f"Via: SIP/2.0/{args.transport.upper()} {vh(local)}:{src_port}"
                f";branch={branch};rport",
                "Max-Forwards: 70",
                f"From: <{st['impu']}>;tag={ftag}",
                f"To: <{target}>",
                f"Call-ID: {call_id}",
                "CSeq: 1 CANCEL", "Content-Length: 0", "", ""]))
    except (KeyboardInterrupt, ConnectionError) as e:
        print(f"\n{type(e).__name__}: {e}")

    if ringing and final is None:
        print("\nResult: reached RINGING: MO signalling works through alerting. "
              "Next: media (RTP) so an answer has audio.")


def main():
    global BUNDLE
    ap = argparse.ArgumentParser(description="Place an IMS MO call over the ePDG tunnel.")
    ap.add_argument("--pcscf", required=True)
    ap.add_argument("--local", default=None)
    ap.add_argument("--imsi", default=None,
                    help="default: read from the SIM via PC/SC")
    ap.add_argument("--msisdn", required=True)
    ap.add_argument("--to", required=True, help="callee E.164, e.g. +15406552415")
    ap.add_argument("--domain", default=None,
                    help="IMS home domain (default: from the operator bundle)")
    ap.add_argument("--imei", default=None,
                    help="device IMEI (default: from device_config.json)")
    ap.add_argument("--device-config", default=carrier.DEVICE_CONFIG_DEFAULT)
    ap.add_argument("--codec", choices=["bundle", "both", "amr-wb", "amr-nb",
                                        "evs", "pcmu"], default="bundle",
                    help="MO offer codecs (default: from the operator bundle)")
    ap.add_argument("--transport", choices=["bundle", "tcp", "udp"],
                    default="bundle",
                    help="Gm transport (default: checks bundle)")
    ap.add_argument("--bundles-dir", default=carrier.BUNDLE_DIR_DEFAULT)
    ap.add_argument("--port", type=int, default=5060)
    ap.add_argument("--src-port", type=int, default=5060)
    ap.add_argument("--rtp-port", type=int, default=50004)
    ap.add_argument("--reader", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--ring-time", type=float, default=45.0)
    args = ap.parse_args()

    CONFIG["imei"] = carrier.resolve_imei(args.imei, args.device_config)
    imsi, mnc_len = carrier.resolve_imsi(args.imsi, args.reader)
    args.imsi = imsi
    BUNDLE = carrier.load(imsi, args.bundles_dir, mnc_len)
    print(f"IMSI {imsi} -> bundle: {BUNDLE.describe()}", file=sys.stderr)
    args.domain = args.domain or BUNDLE.domain
    if args.transport == "bundle":
        args.transport = BUNDLE.transport
    if args.codec == "bundle":
        args.codecs = list(BUNDLE.mo_codecs)
    elif args.codec == "both":
        args.codecs = ["amr-wb", "evs"]
    else:
        args.codecs = [args.codec]
    run_call(args)


if __name__ == "__main__":
    main()
