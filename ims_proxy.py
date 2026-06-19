#!/usr/bin/env python3
"""
ims_proxy.py, SIP <-> IMS wrapper (a back-to-back user agent / B2BUA).

It lets an ordinary SIP softphone such as baresip place and receive calls
through a real IMS network (e.g. Verizon's vzims.com) over your existing ePDG
tunnel, WITHOUT the softphone knowing anything about IMS-AKA, the P-CSCF, the
tunnel, or the carrier's header conventions.

Two faces:

  NETWORK side (towards the P-CSCF, inside the `ims` netns)
      A single persistent TCP connection that does the full IMS-AKA digest
      REGISTER (the same proven flow as ims_call.py) and keeps it alive with a
      periodic re-REGISTER. Verizon reuses this one connection for terminating
      (incoming) requests, so MT calls arrive here too.

  ACCESS side (towards baresip, on 127.0.0.1 by default)
      A plain SIP UDP registrar + UA. baresip REGISTERs here (any password, we
      are the registrar) and the proxy answers 200 OK because the *real*
      registration is already held upstream. baresip's INVITEs become IMS
      INVITEs; IMS INVITEs become INVITEs to baresip.

  MEDIA
      For every call the proxy allocates an RTP/RTCP relay: one socket pair on
      the tunnel (network) side, one on the access side. SDP is rewritten so
      each leg points at the proxy, and packets are forwarded both ways with
      symmetric-RTP latching. You can kinda think of this like an "SIP Reverse Proxy".
      Codecs are passed through UNCHANGED (no transcoding) so for working audio the
      softphone must offer a codec the IMS core accepts (AMR-WB; build baresip with 
      the `amr` module). With a G.711/Opus-only softphone you still get full 
      signalling + ringing, and IMS will answer 488 on the offer if no codec 
      is common, which the proxy relays back so you can see it.

Run it inside the tunnel namespace:

    sudo ip netns exec ims python3 ims_proxy.py \
        --pcscf IPV6:ADDRESS:TO:PCSCF --msisdn +1YOURNUMBER

Then point baresip at it (also inside the netns so it can reach 127.0.0.1):

    sudo ip netns exec ims baresip -f /tmp/baresip
    # ~/.baresip/accounts:
    #   <sip:+MSISDNREPLACEMEEEEE@127.0.0.1>;auth_pass=x;outbound="sip:127.0.0.1:5060;transport=udp";medianat=
"""
from __future__ import annotations

import argparse
import queue
import re
import secrets
import select
import socket
import subprocess
import sys
import threading
import time

import sim_aka
import carrier
import sms_3gpp2
import ims_call as ims

from ims_call import (
    parse_headers, auth_param, status_code, get_uri, get_tag,
    record_route_set, contact_hdr, vh, br,
    ALLOW, MMTEL_ICSI,
)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def ensure_lo_up():
    # Pretty self explanatory but the IMS namespace made by swuikev2 doesn't have lo up
    try:
        # /sys/.../flags is the IFF_* bitmask; IFF_UP = 0x1. (operstate reads
        # "unknown" for loopback even when up, so it can't be used here.)
        if int(open("/sys/class/net/lo/flags").read().strip(), 16) & 0x1:
            return
    except (OSError, ValueError):
        pass
    try:
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True,
                       capture_output=True)
        log("brought loopback up (lo was down in this netns)")
    except (OSError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", b"")
        detail = detail.decode(errors="replace").strip() if detail else e
        log(f"WARNING: could not bring lo up ({detail}). If baresip times out "
            "reaching the proxy, run: ip netns exec ims ip link set lo up")


def local_v6_addrs():
    """All IPv6 addresses currently assigned in this netns, by interface.

    Read straight from /proc/net/if_inet6 so we can show, at startup, exactly
    which addresses are live, baresip MUST register to one of these, and the
    ePDG keeps handing out new prefixes per session.
    """
    out = []
    try:
        for line in open("/proc/net/if_inet6"):
            p = line.split()
            if len(p) >= 6:
                addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(p[0]))
                out.append((p[5], addr))
    except OSError:
        pass
    return out


# SDP
def sdp_media_endpoint(body: str):
    """Pull the (address, rtp_port) the far end wants media on from an SDP."""
    addr, port = None, None
    for ln in body.splitlines():
        ln = ln.strip()
        if ln.startswith("c=") and addr is None:
            p = ln[2:].split()
            if len(p) >= 3:
                addr = p[2]
        elif ln.startswith("m=audio"):
            p = ln.split()
            if len(p) >= 2:
                try:
                    port = int(p[1])
                except ValueError:
                    port = None
    return addr, port


def rewrite_sdp(body: str, addr: str, rtp_port: int, rtcp_port: int) -> str:
    """Rewrite connection/media lines so this SDP points at our relay.

    Only the transport coordinates change, the codec/payload-type list is left
    exactly as the originator wrote it, so the relay can forward RTP verbatim
    (no transcoding) and the payload types stay consistent on each leg.
    """
    fam = "IP6" if ":" in addr else "IP4"
    out = []
    for ln in body.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith("c="):
            out.append(f"c=IN {fam} {addr}")
        elif s.startswith("o="):
            p = s.split()
            if len(p) >= 6:
                p[4], p[5] = fam, addr
                out.append(" ".join(p))
            else:
                out.append(s)
        elif s.startswith("m=audio"):
            p = s.split()
            p[1] = str(rtp_port)
            out.append(" ".join(p))
        elif s.startswith("a=rtcp:"):
            out.append(f"a=rtcp:{rtcp_port}")
        else:
            out.append(s)
    return "\r\n".join(out) + "\r\n"


#  media relay
class MediaRelay:
    """One RTP+RTCP relay session bridging the access leg and the network leg.

    Sockets are latched symmetric-RTP style: the destination on each side is
    seeded from the offered/answered SDP but then updated to wherever packets
    actually arrive from, which copes with the softphone advertising a port it
    does not actually send from (common) and with NAT-ish behaviour.
    """

    def __init__(self, net_local: str, acc_local: str):
        self.netfam = socket.AF_INET6 if ":" in net_local else socket.AF_INET
        self.accfam = socket.AF_INET6 if ":" in acc_local else socket.AF_INET
        self.net_rtp, self.net_rtp_port = self._pair(self.netfam, net_local)
        self.net_rtcp, self.net_rtcp_port = self._pair(
            self.netfam, net_local, prefer=self.net_rtp_port + 1)
        self.acc_rtp, self.acc_rtp_port = self._pair(self.accfam, acc_local)
        self.acc_rtcp, self.acc_rtcp_port = self._pair(
            self.accfam, acc_local, prefer=self.acc_rtp_port + 1)
        self.net_dest = None   # where IMS wants media   (set from answer SDP)
        self.acc_dest = None   # where baresip wants media (set from offer SDP)
        self.running = False
        self._t = None
        # observability: per-leg RTP packet counts + first-packet flags
        self.a2n = 0    # baresip -> IMS
        self.n2a = 0    # IMS -> baresip
        self._seen_a = False
        self._seen_n = False

    @staticmethod
    def _pair(fam, addr, prefer=None):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if prefer is not None:
            try:
                s.bind((addr, prefer))
                return s, prefer
            except OSError:
                pass
        s.bind((addr, 0))
        return s, s.getsockname()[1]

    def start(self):
        self.running = True
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        socks = [self.net_rtp, self.net_rtcp, self.acc_rtp, self.acc_rtcp]
        while self.running:
            try:
                r, _, _ = select.select(socks, [], [], 0.5)
            except (OSError, ValueError):
                break
            for s in r:
                try:
                    data, src = s.recvfrom(4096)
                except OSError:
                    continue
                if s is self.net_rtp:
                    self.net_dest = src
                    self.n2a += 1
                    if not self._seen_n:
                        self._seen_n = True
                        log(f"[RTP] first packet IMS->proxy from {src[0]}:{src[1]} "
                            f"({len(data)}B) -> baresip "
                            f"{'(have baresip dest)' if self.acc_dest else '(NO baresip dest yet!)'}")
                    if self.acc_dest:
                        self.acc_rtp.sendto(data, self.acc_dest)
                elif s is self.net_rtcp:
                    if self.acc_dest:
                        self.acc_rtcp.sendto(
                            data, (self.acc_dest[0], self.acc_rtcp_port_of(self.acc_dest)))
                elif s is self.acc_rtp:
                    self.acc_dest = src
                    self.a2n += 1
                    if not self._seen_a:
                        self._seen_a = True
                        log(f"[RTP] first packet baresip->proxy from {src[0]}:{src[1]} "
                            f"({len(data)}B) -> IMS "
                            f"{'(have IMS dest)' if self.net_dest else '(NO IMS dest yet!)'}")
                    if self.net_dest:
                        self.net_rtp.sendto(data, self.net_dest)
                elif s is self.acc_rtcp:
                    if self.net_dest:
                        self.net_rtcp.sendto(
                            data, (self.net_dest[0], self.net_rtcp_port_of(self.net_dest)))

    # RTCP usually rides RTP-port+1; fall back to that if we never saw RTCP.
    def acc_rtcp_port_of(self, dest):
        return dest[1] + 1

    def net_rtcp_port_of(self, dest):
        return dest[1] + 1

    def stop(self):
        self.running = False
        log(f"[RTP] relay closing, baresip->IMS {self.a2n} pkts, "
            f"IMS->baresip {self.n2a} pkts")
        for s in (self.net_rtp, self.net_rtcp, self.acc_rtp, self.acc_rtcp):
            try:
                s.close()
            except OSError:
                pass


class Call:
    """A bridged call: one access-side dialog + one network-side dialog."""

    def __init__(self, direction):
        self.direction = direction          # 'MO' or 'MT'
        self.state = "init"                  # init/inviting/ringing/up/ended
        self.media = None
        # access (baresip) dialog 
        self.a_callid = None
        self.a_from = None    # full From header value (their AoR + their tag)
        self.a_to = None      # full To header value
        self.a_contact = None # their Contact URI (in-dialog target)
        self.a_via = []       # their Via stack (echoed in responses)
        self.a_cseq_invite = None
        self.a_our_tag = secrets.token_hex(6)   # tag WE own on the access side
        self.a_remote_tag = None
        # network (IMS) dialog 
        self.n_callid = secrets.token_hex(12)
        self.n_ftag = secrets.token_hex(6)
        self.n_branch = br()
        self.n_invite_cseq = 1
        self.n_cseq = 2
        self.n_rtag = None
        self.n_route = []
        self.n_target = None
        self.n_pracked = set()
        self.ims_answer = None        # SDP answer body from IMS (often in 183)
        self.acc_answer_sent = False  # have we given baresip the answer SDP yet?
        # Transient TCP leg for the MO INVITE transaction. Needed for bigger messages like INVITE which break the UDP MTU and seem to get dropped.
        self.n_tcp = None             # ims.Transport (TCP) or None
        self.n_tcp_port = None        # its local port, advertised in the TCP Via


class Proxy:
    def __init__(self, args):
        self.args = args
        self.home = args.domain
        self.impu = f"sip:{args.msisdn}@{self.home}"
        self.impi = f"{args.imsi}@{self.home}"
        self.msisdn = args.msisdn
        self.service_route = []
        self.send_lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.reg_q = queue.Queue()
        self.calls_by_n = {}   # network Call-ID  -> Call
        self.calls_by_a = {}   # access  Call-ID  -> Call
        self.acc_contact = None  # baresip's registered Contact URI (for MT)
        self.acc_peer = None     # (addr, port) baresip's SIP source
        self.running = True
        ims.CONFIG["imei"] = args.imei
        self.transport = ims.BUNDLE.transport   # Gm transport from the bundle
        self.fam = socket.AF_INET6 if ":" in args.pcscf else socket.AF_INET
        self.T = None
        self.net_port = None
        self.net_local = args.local or ims.detect_local(args.pcscf, args.port,
                                                         self.fam)
        # Access transport: a plain UDP socket the softphone talks to. baresip
        # discards loopback addresses (127/8, ::1), so we bind a non-loopback
        # tunnel address. Prefer a stable ULA (fd00::1) added to tun1 if present
        # the SLAAC globals rotate per ePDG session, the ULA does not.
        listen = args.listen or self.net_local
        self.afam = socket.AF_INET6 if ":" in listen else socket.AF_INET
        self.acc = socket.socket(self.afam, socket.SOCK_DGRAM)
        self.acc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the WILDCARD, not the one address we happened to detect: tun1
        # carries several SLAAC globals that rotate, and baresip may send to a
        # sibling of the one we advertise. Receiving on :: catches them all;
        # replies go back to the packet's source (acc_peer), and the concrete
        # `self.listen` is still what we put in Via/Contact/SDP. Pass --listen
        # to pin a specific address instead.
        bind_addr = args.listen or ("::" if self.afam == socket.AF_INET6 else "0.0.0.0")
        self.acc.bind((bind_addr, args.listen_port))
        self.listen = listen
        self.listen_port = self.acc.getsockname()[1]
        self.registered = False

    # ---- wire tracing -----------------------------------------------------
    def trace(self, dirn, where, msg, peer=None):
        """Dump a SIP message at a transport chokepoint. Full body unless --quiet."""
        first = msg.split("\r\n", 1)[0]
        loc = f" {vh(peer[0])}:{peer[1]}" if peer else ""
        tag = f"{where} {dirn}"
        if self.args.quiet:
            log(f"[{tag}]{loc}  {first}")
            return
        sep = "=" * 64
        sys.stderr.write(f"\n{sep}\n[{tag}]{loc}\n{'-'*64}\n{msg.rstrip()}\n{sep}\n")
        sys.stderr.flush()

    def net_send(self, msg):
        self.trace("TX", "NET", msg, (self.args.pcscf, self.args.port))
        with self.send_lock:
            if self.T is None:
                return
            self.T.send(msg)

    def acc_send(self, msg, dest=None):
        dest = dest or self.acc_peer
        if not dest:
            log(f"[ACC TX DROPPED: no destination known]  "
                f"{msg.split(chr(13)+chr(10),1)[0]}")
            return
        self.trace("TX", "ACC", msg, dest)
        self.acc.sendto(msg.encode(), dest)

    def reg_msg(self, call_id, ftag, cseq, auth=None):
        lines = [
            f"REGISTER sip:{self.home} SIP/2.0",
            f"Via: SIP/2.0/{self.transport.upper()} {vh(self.net_local)}:{self.net_port}"
            f";branch={br()};rport",
            "Max-Forwards: 70",
            f"From: <{self.impu}>;tag={ftag}",
            f"To: <{self.impu}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            contact_hdr(self.msisdn, self.net_local, self.net_port, self.transport),
            auth or (f'Authorization: Digest nonce="",uri="sip:{self.home}",'
                     f'realm="{self.home}",username="{self.impi}",response=""'),
            ALLOW, f"User-Agent: {ims.BUNDLE.user_agent}",
            "Supported: 100rel,path,replaces",
            f"P-Access-Network-Info: {ims.BUNDLE.pani}",
            f"Expires: {self.args.expires}", "Content-Length: 0", "", "",
        ]
        return "\r\n".join(lines)

    def do_register(self):
        """Full two-leg IMS-AKA REGISTER, driven through the rx thread's queue."""
        call_id = secrets.token_hex(12)
        ftag = secrets.token_hex(6)
        # drain any stale entries
        while not self.reg_q.empty():
            self.reg_q.get_nowait()
        self.net_send(self.reg_msg(call_id, ftag, 1))
        try:
            code, headers, _ = self.reg_q.get(timeout=self.args.timeout)
        except queue.Empty:
            log("REGISTER: no challenge"); return False
        if code != 401:
            log(f"REGISTER: expected 401, got {code}"); return False

        wmark = headers.get("www-authenticate", [""])[0]
        nonce = auth_param(wmark, "nonce")
        realm = auth_param(wmark, "realm") or self.home
        qop = auth_param(wmark, "qop")
        algo = auth_param(wmark, "algorithm") or "AKAv1-MD5"
        try:
            q = sim_aka.aka_challenge(nonce, reader_index=self.args.reader)
        except Exception as e:
            log(f"AKA failed: {e}"); return False
        passwd = sim_aka.aka_password(q["res"], q["ik"], q["ck"], algo)

        nc, cnonce = "00000001", secrets.token_hex(8)
        uri = f"sip:{self.home}"
        rsp = sim_aka.digest_response(self.impi, realm, passwd, "REGISTER", uri,
                                      nonce, qop=qop, cnonce=cnonce, nc=nc)
        auth = (f'Authorization: Digest username="{self.impi}",realm="{realm}",'
                f'nonce="{nonce}",uri="{uri}",response="{rsp}",algorithm={algo}')
        if qop:
            auth += f',qop={qop},nc={nc},cnonce="{cnonce}"'
        self.net_send(self.reg_msg(call_id, ftag, 2, auth))
        try:
            code, headers, _ = self.reg_q.get(timeout=self.args.timeout)
        except queue.Empty:
            log("REGISTER: no 200"); return False
        if code != 200:
            log(f"REGISTER: expected 200, got {code}"); return False

        svc = []
        for hv in headers.get("service-route", []):
            for part in hv.split(","):
                if part.strip():
                    svc.append(get_uri(part.strip()))
        with self.state_lock:
            self.service_route = svc
            self.registered = True
        # Work out when to refresh: the granted Contact expires, else Expires.
        granted = self._granted_expires(headers)
        log(f"*** IMS REGISTERED ***  expires={granted}s  service-route:",
            svc if svc else "(none)")
        refresh_in = max(60, int(granted * 0.5))
        t = threading.Timer(refresh_in, self._refresh)
        t.daemon = True
        t.start()
        return True

    def _granted_expires(self, headers):
        for c in headers.get("contact", []):
            m = re.search(r"expires=(\d+)", c, re.I)
            if m:
                return int(m.group(1))
        for e in headers.get("expires", []):
            try:
                return int(e)
            except ValueError:
                pass
        return min(self.args.expires, 3600)

    def _refresh(self):
        if not self.running:
            return
        log("re-REGISTER (refresh) ...")
        if not self.do_register():
            log("refresh failed; retrying in 60s")
            t = threading.Timer(60, self._refresh)
            t.daemon = True
            t.start()

    # ---- upstream bring-up (P-CSCF connect + register), retried -----------
    def connect_network(self):
        """Open the P-CSCF transport and start its reader.

        Separate from __init__ so a stale/unreachable --pcscf only delays the
        upstream side; the access side is already serving baresip.
        """
        proto = self.transport
        bind_local = self.net_local if proto == "udp" else self.args.local
        try:
            self.T = ims.Transport(self.fam, bind_local, self.args.src_port,
                                   self.args.pcscf, self.args.port, proto,
                                   self.args.timeout)
        except OSError as e:
            log(f"P-CSCF {proto.upper()} setup to {self.args.pcscf}:{self.args.port} "
                f"FAILED: {e} (stale P-CSCF for this session?)")
            self.T = None
            return False
        self.net_local = self.T.local
        self.net_port = self.T.local_port
        log(f"P-CSCF {proto.upper()} {self.net_local}:{self.net_port} -> "
            f"{self.args.pcscf}:{self.args.port}"
            + ("  UDP " if proto == "udp" else " TCP "))
        threading.Thread(target=self.net_rx_loop, daemon=True).start()
        return True

    def _bringup(self):
        if self.T is None and not self.connect_network():
            return False
        return self.do_register()

    def _schedule_retry(self, delay=10):
        t = threading.Timer(delay, self._retry)
        t.daemon = True
        t.start()

    def _retry(self):
        if not self.running or self.registered:
            return
        if self._bringup():
            log("proxy ready IMS came up on retry")
        else:
            self._schedule_retry()

    def open_invite_tcp(self, call: Call):
        """Open a short-lived TCP connection for one MO INVITE transaction and
        start a reader for its responses. On failure the caller
        falls back to sending the INVITE over the persistent UDP socket."""
        try:
            t = ims.Transport(self.fam, self.net_local, 0, self.args.pcscf,
                              self.args.port, "tcp", self.args.timeout)
        except OSError as e:
            log(f"INVITE TCP leg connect FAILED: {e}; INVITE will go over UDP "
                "(may fragment if >MTU)")
            return False
        call.n_tcp = t
        call.n_tcp_port = t.local_port
        threading.Thread(target=self.net_tcp_rx_loop, args=(call,),
                         daemon=True).start()
        log(f"INVITE TCP leg up: {vh(t.local)}:{t.local_port} -> "
            f"{self.args.pcscf}:{self.args.port} (n={call.n_callid[:8]})")
        return True

    def net_tcp_rx_loop(self, call: Call):
        """Read INVITE responses off this call's transient TCP leg and dispatch
        them through the same on_network path as the UDP socket."""
        t = call.n_tcp
        while self.running and call.n_tcp is t:
            try:
                raw = t.recv(1.0)
            except socket.timeout:
                continue
            except (ConnectionError, OSError):
                return
            self.trace("RX", "NET", raw, (self.args.pcscf, self.args.port))
            try:
                self.on_network(raw)
            except Exception as e:
                log("network handler error (tcp leg):", e)

    def close_invite_tcp(self, call: Call):
        t = call.n_tcp
        call.n_tcp = None          # signals net_tcp_rx_loop to exit
        if t is not None:
            t.close()

    def net_send_invite_leg(self, call: Call, msg):
        """Send an INVITE-transaction message (INVITE/ACK/CANCEL) on the call's
        TCP leg; fall back to the persistent socket when there is none."""
        if call.n_tcp is None:
            return self.net_send(msg)
        self.trace("TX", "NET", msg, (self.args.pcscf, self.args.port))
        with self.send_lock:
            t = call.n_tcp
            if t is None:
                return
            try:
                t.send(msg)
            except OSError as e:
                log(f"INVITE-leg TCP send failed: {e}")

    # ---- network-side message builders -----------------------------------
    def n_via(self, branch):
        return (f"Via: SIP/2.0/{self.transport.upper()} {vh(self.net_local)}:{self.net_port}"
                f";branch={branch};rport")

    def n_via_call(self, call: Call, branch):
        """Via for a request on this call's INVITE transaction: TCP (the leg's
        port) if it has a transient TCP leg, else the persistent transport."""
        if call.n_tcp is not None:
            return (f"Via: SIP/2.0/TCP {vh(self.net_local)}:{call.n_tcp_port}"
                    f";branch={branch};rport")
        return self.n_via(branch)

    def build_net_invite(self, call: Call, sdp: str):
        lines = [
            f"INVITE {call.n_target} SIP/2.0",
            self.n_via_call(call, call.n_branch),
            "Max-Forwards: 70",
        ]
        for r in self.service_route:
            lines.append(f"Route: <{r}>")
        lines += [
            f"From: <{self.impu}>;tag={call.n_ftag}",
            f"To: <{call.n_target}>",
            f"Call-ID: {call.n_callid}",
            "CSeq: 1 INVITE",
            contact_hdr(self.msisdn, self.net_local, self.net_port, self.transport),
            f"P-Preferred-Identity: <{self.impu}>",
            f"P-Access-Network-Info: {ims.BUNDLE.pani}",
            f'Accept-Contact: *;+g.3gpp.icsi-ref="{MMTEL_ICSI}"',
            "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel",
            ALLOW, "Supported: 100rel,timer,replaces",
            "Session-Expires: 1800", "Min-SE: 90",
            f"User-Agent: {ims.BUNDLE.user_agent}",
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp.encode())}",
            "", sdp,
        ]
        return "\r\n".join(lines)

    def net_indialog(self, method, call: Call, cseq, extra=None, body=None,
                     leg=False):
        route = call.n_route or self.service_route
        via = self.n_via_call(call, br()) if leg else self.n_via(br())
        lines = [f"{method} {call.n_target} SIP/2.0", via,
                 "Max-Forwards: 70"]
        for r in route:
            lines.append(f"Route: <{r}>")
        lines += [
            f"From: <{self.impu}>;tag={call.n_ftag}",
            f"To: <{call.n_target}>" + (f";tag={call.n_rtag}" if call.n_rtag else ""),
            f"Call-ID: {call.n_callid}",
            f"CSeq: {cseq} {method}",
        ]
        if extra:
            lines += extra
        b = body or ""
        lines += [f"Content-Length: {len(b.encode())}", "", b]
        return "\r\n".join(lines)

    def net_cancel(self, call: Call):
        lines = [
            f"CANCEL {call.n_target} SIP/2.0",
            self.n_via_call(call, call.n_branch),  # must match the INVITE's Via
            "Max-Forwards: 70",
        ]
        for r in self.service_route:
            lines.append(f"Route: <{r}>")
        lines += [
            f"From: <{self.impu}>;tag={call.n_ftag}",
            f"To: <{call.n_target}>",
            f"Call-ID: {call.n_callid}",
            "CSeq: 1 CANCEL", "Content-Length: 0", "", "",
        ]
        return "\r\n".join(lines)

    def net_response(self, headers, code, reason, extra=None, body=None,
                     totag=None, contact=False):
        """Build a response to an inbound IMS request (we are the UAS)."""
        lines = [f"SIP/2.0 {code} {reason}"]
        for v in headers.get("via", []):
            lines.append(f"Via: {v}")
        for rr in headers.get("record-route", []):
            lines.append(f"Record-Route: {rr}")
        frm = headers.get("from", [""])[0]
        to = headers.get("to", [""])[0]
        if totag and "tag=" not in to:
            to = f"{to};tag={totag}"
        lines += [f"From: {frm}", f"To: {to}",
                  f"Call-ID: {headers.get('call-id', [''])[0]}",
                  f"CSeq: {headers.get('cseq', [''])[0]}"]
        if contact:
            # A 2xx answer to INVITE MUST carry Contact or the peer can't ACK
            # it (IMS otherwise gives up and CANCELs). Our network-side contact.
            lines.append(contact_hdr(self.msisdn, self.net_local, self.net_port,
                                     self.transport))
        if extra:
            lines += extra
        b = body or ""
        if b:
            lines.append("Content-Type: application/sdp")
        lines += [f"Content-Length: {len(b.encode())}", "", b]
        return "\r\n".join(lines)

    # ---- access-side message builders -------------------------------------
    def a_response(self, call_or_headers, code, reason, extra=None, body=None,
                   totag=None, contact=False):
        """Response to a baresip request (we are the UAS on the access side)."""
        headers = call_or_headers
        lines = [f"SIP/2.0 {code} {reason}"]
        for v in headers.get("via", []):
            lines.append(f"Via: {v}")
        frm = headers.get("from", [""])[0]
        to = headers.get("to", [""])[0]
        if totag and "tag=" not in to:
            to = f"{to};tag={totag}"
        lines += [f"From: {frm}", f"To: {to}",
                  f"Call-ID: {headers.get('call-id', [''])[0]}",
                  f"CSeq: {headers.get('cseq', [''])[0]}"]
        if contact:
            lines.append(f"Contact: <sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}>")
        if extra:
            lines += extra
        b = body or ""
        if b:
            lines.append("Content-Type: application/sdp")
        lines += [f"Content-Length: {len(b.encode())}", "", b]
        return "\r\n".join(lines)

    def a_request(self, method, call: Call, cseq, extra=None, body=None):
        """In-dialog request towards baresip (we are the UAC on access side)."""
        target = get_uri(call.a_contact) if call.a_contact else get_uri(call.a_from)
        # From(us) = the To of their INVITE + our tag; To(them) = their From.
        our = get_uri(call.a_to)
        their = get_uri(call.a_from)
        lines = [
            f"{method} {target} SIP/2.0",
            f"Via: SIP/2.0/UDP {vh(self.listen)}:{self.listen_port}"
            f";branch={br()};rport",
            "Max-Forwards: 70",
            f"From: <{our}>;tag={call.a_our_tag}",
            f"To: <{their}>" + (f";tag={call.a_remote_tag}" if call.a_remote_tag else ""),
            f"Call-ID: {call.a_callid}",
            f"CSeq: {cseq} {method}",
            f"Contact: <sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}>",
        ]
        if extra:
            lines += extra
        b = body or ""
        if b:
            lines.append("Content-Type: application/sdp")
        lines += [f"Content-Length: {len(b.encode())}", "", b]
        return "\r\n".join(lines)

    # ---- teardown ---------------------------------------------------------
    def drop_call(self, call: Call):
        with self.state_lock:
            self.calls_by_n.pop(call.n_callid, None)
            self.calls_by_a.pop(call.a_callid, None)
        if call.media:
            call.media.stop()
        self.close_invite_tcp(call)   # FIN the transient INVITE TCP leg, if any
        call.state = "ended"

    # ====================================================================== #
    #  ACCESS SIDE  (requests from baresip)                                  #
    # ====================================================================== #
    def acc_rx_loop(self):
        while self.running:
            try:
                data, peer = self.acc.recvfrom(65535)
            except OSError:
                break
            self.acc_peer = peer
            raw = data.decode(errors="replace")
            self.trace("RX", "ACC", raw, peer)
            try:
                self.on_access(raw, peer)
            except Exception as e:
                log("access handler error:", e)

    def on_access(self, raw, peer):
        first = raw.split("\r\n", 1)[0]
        if first.startswith("SIP/2.0"):
            return self.on_access_response(raw)
        method = first.split(" ", 1)[0].upper()
        log(f"access <- {method} from {peer[0]}:{peer[1]}")
        _, headers, body = parse_headers(raw)
        if method == "REGISTER":
            self.handle_acc_register(headers)
        elif method == "INVITE":
            self.handle_acc_invite(headers, body)
        elif method == "ACK":
            pass  # ACK of our 2xx dialog already up, nothing to relay
        elif method == "CANCEL":
            self.handle_acc_cancel(headers)
        elif method == "BYE":
            self.handle_acc_bye(headers)
        elif method == "OPTIONS":
            self.acc_send(self.a_response(headers, 200, "OK", extra=[ALLOW]), peer)
        else:
            self.acc_send(self.a_response(headers, 200, "OK"), peer)

    def handle_acc_register(self, headers):
        # We are already registered upstream; just confirm to the softphone and
        # remember where to deliver incoming (MT) calls.
        if headers.get("contact"):
            self.acc_contact = get_uri(headers["contact"][0])
        exp = headers.get("expires", ["3600"])[0]
        contact_echo = headers.get("contact", [f"<sip:{self.msisdn}@{vh(self.listen)}>"])[0]
        extra = [f"Contact: {contact_echo};expires={exp}",
                 f'Service-Route: <sip:{self.home};lr>']
        self.acc_send(self.a_response(headers, 200, "OK", extra=extra,
                                      totag=secrets.token_hex(6)))
        log(f"access REGISTER ok (contact={self.acc_contact})")

    def handle_acc_invite(self, headers, body):
        callid = headers.get("call-id", [""])[0]
        with self.state_lock:
            if callid in self.calls_by_a:
                return  # retransmission
        if not self.registered:
            self.acc_send(self.a_response(headers, 503, "Service Unavailable",
                                          extra=["Retry-After: 5"]))
            log("MO INVITE rejected 503, not yet registered to IMS")
            return
        call = Call("MO")
        call.a_callid = callid
        call.a_from = headers.get("from", [""])[0]
        call.a_to = headers.get("to", [""])[0]
        call.a_via = headers.get("via", [])
        call.a_cseq_invite = headers.get("cseq", [""])[0]
        call.a_remote_tag = get_tag(call.a_from)
        if headers.get("contact"):
            call.a_contact = get_uri(headers["contact"][0])
        call.n_target = f"tel:{self.extract_number(call.a_to)}"

        # Media relay: seed baresip's media endpoint from its offer.
        relay = MediaRelay(self.net_local, self.listen)
        acc_addr, acc_port = sdp_media_endpoint(body)
        if acc_addr and acc_port:
            relay.acc_dest = (acc_addr, acc_port)
        call.media = relay
        net_sdp = rewrite_sdp(body, self.net_local, relay.net_rtp_port,
                              relay.net_rtcp_port)

        with self.state_lock:
            self.calls_by_a[call.a_callid] = call
            self.calls_by_n[call.n_callid] = call
        call.state = "inviting"

        # 100 Trying to baresip, INVITE to IMS.
        self.acc_send(self.a_response(headers, 100, "Trying"))
        relay.start()
        if self.transport == "udp":
            self.open_invite_tcp(call)
        self.net_send_invite_leg(call, self.build_net_invite(call, net_sdp))
        log(f"MO call -> {call.n_target}  (a={call.a_callid[:8]} n={call.n_callid[:8]})")

    def handle_acc_cancel(self, headers):
        callid = headers.get("call-id", [""])[0]
        call = self.calls_by_a.get(callid)
        # 200 to the CANCEL itself; the INVITE will get a 487 we relay from IMS.
        self.acc_send(self.a_response(headers, 200, "OK"))
        if call and call.state in ("inviting", "ringing"):
            self.net_send_invite_leg(call, self.net_cancel(call))
            log("MO CANCEL relayed to IMS")

    def handle_acc_bye(self, headers):
        callid = headers.get("call-id", [""])[0]
        call = self.calls_by_a.get(callid)
        self.acc_send(self.a_response(headers, 200, "OK"))
        if call:
            self.net_send(self.net_indialog("BYE", call, call.n_cseq))
            call.n_cseq += 1
            log("BYE from baresip -> IMS")
            self.drop_call(call)

    def on_access_response(self, raw):
        # Responses from baresip to OUR requests (MT INVITE, or BYE we sent).
        _, headers, body = parse_headers(raw)
        code = status_code(raw.split("\r\n", 1)[0])
        cseq = headers.get("cseq", [""])[0]
        callid = headers.get("call-id", [""])[0]
        call = self.calls_by_a.get(callid)
        if not call:
            return
        if "INVITE" in cseq and call.direction == "MT":
            self.mt_on_access_response(call, code, headers, body)

    # ====================================================================== #
    #  NETWORK SIDE  (messages from the IMS / P-CSCF)                        #
    # ====================================================================== #
    def net_rx_loop(self):
        while self.running and self.T is not None:
            try:
                raw = self.T.recv(1.0)
            except socket.timeout:
                continue
            except (ConnectionError, OSError) as e:
                if self.transport == "udp":
                    log(f"network recv error (udp, ignored): {e}")
                    continue
                log(f"P-CSCF connection lost: {e} access side stays up, "
                    "reconnecting in 5s")
                self.T = None
                self.registered = False
                self._schedule_retry(5)
                return
            self.trace("RX", "NET", raw, (self.args.pcscf, self.args.port))
            try:
                self.on_network(raw)
            except Exception as e:
                log("network handler error:", e)

    def on_network(self, raw):
        first = raw.split("\r\n", 1)[0]
        _, headers, body = parse_headers(raw)
        cseq = headers.get("cseq", [""])[0]
        if first.startswith("SIP/2.0"):
            code = status_code(first)
            if "REGISTER" in cseq:
                self.reg_q.put((code, headers, raw))
                return
            self.on_net_response(code, headers, body, cseq)
        else:
            self.on_net_request(first, headers, body)

    # ---- responses to our network transactions ---------------------------
    def on_net_response(self, code, headers, body, cseq):
        callid = headers.get("call-id", [""])[0]
        call = self.calls_by_n.get(callid)
        if not call:
            return
        if "INVITE" not in cseq:
            return  # responses to our PRACK/BYE/UPDATE, nothing to forward
        # learn the dialog as it forms
        if get_tag(headers.get("to", [""])[0]):
            call.n_rtag = get_tag(headers["to"][0])
        rr = record_route_set(headers)
        if rr:
            call.n_route = list(reversed(rr))
        if headers.get("contact"):
            call.n_target = get_uri(headers["contact"][0])

        # Verizon (Ericsson MTAS) puts the SDP ANSWER in the reliable 183, not
        # the 200 OK (which comes back with no body). Capture the answer from
        # whatever response carries it, wire the relay, and make sure baresip
        # gets it otherwise baresip has no remote addr/codec and can't send
        # (the "downlink only" bug).
        if body.strip() and call.media:
            ims_addr, ims_port = sdp_media_endpoint(body)
            if ims_addr and ims_port:
                call.media.net_dest = (ims_addr, ims_port)
                call.ims_answer = body

        if 100 <= code < 200:
            if body.strip() and call.media and not call.acc_answer_sent:
                # Bridge the answer to baresip as a 183 w/ SDP -> baresip sets up
                # media and starts sending RTP (early media).
                acc_sdp = rewrite_sdp(body, self.listen, call.media.acc_rtp_port,
                                      call.media.acc_rtcp_port)
                self.acc_send(self.a_response(
                    self._invite_headers(call), 183, "Session Progress",
                    body=acc_sdp, totag=call.a_our_tag, contact=True))
                call.acc_answer_sent = True
                log("answer SDP from 183 bridged to baresip (early media)")
            elif code == 180:
                call.state = "ringing"
                self.acc_send(self.a_response(
                    self._invite_headers(call), 180, "Ringing",
                    totag=call.a_our_tag, contact=True))
            # PRACK if the provisional demands it (mirror ims_call.py).
            rseq = headers.get("rseq", [None])[0]
            require = " ".join(headers.get("require", [])).lower()
            if rseq and "100rel" in require and rseq not in call.n_pracked:
                call.n_pracked.add(rseq)
                self.net_send(self.net_indialog(
                    "PRACK", call, call.n_cseq,
                    extra=[f"RAck: {rseq} {call.n_invite_cseq} INVITE"]))
                call.n_cseq += 1
            return

        if 200 <= code < 300:
            # ACK the IMS 200 (we are the UAC) on the INVITE's leg (TCP).
            self.net_send_invite_leg(
                call, self.net_indialog("ACK", call, call.n_invite_cseq, leg=True))
            # If baresip hasn't been given the answer yet (no 183 carried it),
            # include it now; otherwise the 200 needs no body (already answered).
            acc_sdp = ""
            if not call.acc_answer_sent and call.media:
                ans = body if body.strip() else (call.ims_answer or "")
                if ans:
                    acc_sdp = rewrite_sdp(ans, self.listen,
                                          call.media.acc_rtp_port,
                                          call.media.acc_rtcp_port)
                    call.acc_answer_sent = True
            self.acc_send(self.a_response(
                self._invite_headers(call), 200, "OK", body=acc_sdp,
                totag=call.a_our_tag, contact=True))
            call.state = "up"
            log(f"MO call answered (n={call.n_callid[:8]}) media bridged "
                f"(answer {'in 2xx' if acc_sdp else 'already sent via 183'})")
            return

        # failure: relay the status to baresip and tear down
        reason = first_reason(code)
        self.acc_send(self.a_response(self._invite_headers(call), code, reason,
                                      totag=call.a_our_tag))
        log(f"MO call failed: {code} {reason}")
        self.drop_call(call)

    def _invite_headers(self, call: Call):
        """Reconstruct the access-side request headers needed to answer baresip."""
        return {
            "via": call.a_via,
            "from": [call.a_from],
            "to": [call.a_to],
            "call-id": [call.a_callid],
            "cseq": [call.a_cseq_invite],
        }

    # ---- inbound IMS requests --------------------------------------------
    def on_net_request(self, first, headers, body):
        method = first.split(" ", 1)[0].upper()
        callid = headers.get("call-id", [""])[0]
        call = self.calls_by_n.get(callid)
        if method == "INVITE" and not call:
            return self.handle_mt_invite(headers, body)
        if method == "BYE":
            self.net_send(self.net_response(headers, 200, "OK"))
            if call:
                if call.a_callid in self.calls_by_a and call.state == "up":
                    self.acc_send(self.a_request("BYE", call, call.n_cseq))
                log("IMS BYE -> baresip")
                self.drop_call(call)
            return
        if method == "CANCEL":
            self.net_send(self.net_response(headers, 200, "OK"))
            if call and call.state != "up":
                # caller gave up while ringing. For MT, CANCEL baresip's INVITE;
                # for MO we are baresip's UAS, so 487 the pending INVITE.
                if call.direction == "MT":
                    self.acc_send(self.build_mt_cancel(call))
                else:
                    self.acc_send(self.a_response(self._invite_headers(call), 487,
                                                  "Request Terminated",
                                                  totag=call.a_our_tag))
                self.drop_call(call)
            return
        if method in ("UPDATE", "INVITE"):  # session-timer refresh / re-INVITE
            self.net_send(self.net_response(headers, 200, "OK", body=body or None,
                                            totag=call.n_rtag if call else None))
            return
        if method == "OPTIONS":
            self.net_send(self.net_response(headers, 200, "OK", extra=[ALLOW]))
            return
        if method == "MESSAGE":
            self.handle_net_message(headers)
            return
        if method in ("NOTIFY", "INFO", "PRACK"):
            self.net_send(self.net_response(headers, 200, "OK"))
            return

    # inbound SMS over IMS (X.S0048)
    def handle_net_message(self, headers):
        """An MT short message: a SIP MESSAGE carrying a binary 3GPP2 SMS.

        Per X.S0048 7.3.2.3 we 200 OK it (RFC 3428) so the network stops
        retransmitting, decode the C.S0015 body, and hand the text to the
        softphone as an ordinary text/plain MESSAGE. Sending SMS (MO) is not
        implemented yet.
        """
        self.net_send(self.net_response(headers, 200, "OK"))
        ctype = headers.get("content-type", [""])[0].lower()
        if "application/vnd.3gpp2.sms" not in ctype:
            log(f"IMS MESSAGE ({ctype or 'no content-type'}); not 3GPP2 SMS, ignored. Feel free to PR in reg 3GPP SMS")
            return
        raw = self.T.last_raw if self.T else b""
        sms_bytes = raw.partition(b"\r\n\r\n")[2]
        try:
            clen = int(headers.get("content-length", ["0"])[0])
        except ValueError:
            clen = 0
        if clen and len(sms_bytes) >= clen:
            sms_bytes = sms_bytes[:clen]
        try:
            sms = sms_3gpp2.decode(sms_bytes)
        except Exception as e:
            log(f"3GPP2 SMS decode failed: {e}  raw={sms_bytes.hex()}")
            return
        sender = sms.get("orig_addr") or \
            self.extract_number(headers.get("from", [""])[0]) or "unknown"
        sender = self._fmt_msisdn(sender)
        text = sms.get("text", "")
        stamp = f"  (sent {sms['timestamp']})" if sms.get("timestamp") else ""
        log(f"*** SMS from {sender}: {text!r}{stamp}")
        # Only a Deliver carries user content for the softphone; acks/reports
        # (delivery-ack, user-ack, read-ack) are logged but not forwarded.
        mtype = sms.get("message_type")
        if mtype not in (None, "deliver"):
            log(f"    (SMS transport message type {mtype}; not forwarded to client)")
            return
        self.deliver_sms_to_access(sender, text)

    @staticmethod
    def _fmt_msisdn(number: str) -> str:
        d = re.sub(r"[^\d+]", "", number)
        if not d or d.startswith("+"):
            return d or number
        if len(d) == 10:
            return "+1" + d
        if len(d) == 11 and d.startswith("1"):
            return "+" + d
        return d

    def deliver_sms_to_access(self, sender, text):
        if not self.acc_contact or not self.acc_peer:
            log("SMS received but no softphone registered; not delivered "
                "(register baresip to pick it up)")
            return
        self.acc_send(self.build_acc_message(sender, text))
        log(f"SMS delivered to softphone as text/plain (from {sender})")

    def build_acc_message(self, sender, text):
        """Out-of-dialog SIP MESSAGE towards baresip (RFC 3428, text/plain)."""
        target = get_uri(self.acc_contact)
        blen = len(text.encode())
        lines = [
            f"MESSAGE {target} SIP/2.0",
            f"Via: SIP/2.0/UDP {vh(self.listen)}:{self.listen_port}"
            f";branch={br()};rport",
            "Max-Forwards: 70",
            f'From: "{sender}" <sip:{sender}@{self.home}>;tag={secrets.token_hex(6)}',
            f"To: <{target}>",
            f"Call-ID: {secrets.token_hex(12)}",
            "CSeq: 1 MESSAGE",
            f"Contact: <sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}>",
            "Content-Type: text/plain;charset=UTF-8",
            f"Content-Length: {blen}",
            "", text,
        ]
        return "\r\n".join(lines)

    # ---- MT (incoming) call ----------------------------------------------
    def handle_mt_invite(self, headers, body):
        if not self.acc_contact:
            # No softphone registered to take the call.
            self.net_send(self.net_response(headers, 480, "Temporarily Unavailable"))
            log("MT INVITE but no access UA registered 480")
            return
        call = Call("MT")
        call.n_callid = headers.get("call-id", [""])[0]
        call.n_rtag = call.a_our_tag  # our tag in the IMS dialog
        call.n_ftag = get_tag(headers.get("from", [""])[0])
        call.n_target = get_uri(headers.get("contact", [""])[0]) or \
            get_uri(headers.get("from", [""])[0])
        call.n_route = list(reversed(record_route_set(headers)))
        call.n_invite_headers = headers
        caller = self.extract_number(headers.get("from", [""])[0]) or "unknown"

        relay = MediaRelay(self.net_local, self.listen)
        ims_addr, ims_port = sdp_media_endpoint(body)
        if ims_addr and ims_port:
            relay.net_dest = (ims_addr, ims_port)
        call.media = relay
        acc_sdp = rewrite_sdp(body, self.listen, relay.acc_rtp_port,
                              relay.acc_rtcp_port) if body.strip() else ""

        call.a_callid = secrets.token_hex(12)
        with self.state_lock:
            self.calls_by_n[call.n_callid] = call
            self.calls_by_a[call.a_callid] = call

        self.net_send(self.net_response(headers, 100, "Trying"))
        relay.start()
        self.acc_send(self.build_mt_invite(call, caller, acc_sdp))
        log(f"MT call from {caller} -> baresip (n={call.n_callid[:8]})")

    def build_mt_invite(self, call: Call, caller, sdp):
        call.a_branch = br()
        call.a_to = f"<{self.impu}>"
        call.a_from = f'"{caller}" <sip:{caller}@{self.home}>;tag={call.a_our_tag}'
        lines = [
            f"INVITE {get_uri(self.acc_contact)} SIP/2.0",
            f"Via: SIP/2.0/UDP {vh(self.listen)}:{self.listen_port}"
            f";branch={call.a_branch};rport",
            "Max-Forwards: 70",
            f"From: {call.a_from}",
            f"To: <{self.impu}>",
            f"Call-ID: {call.a_callid}",
            "CSeq: 1 INVITE",
            f"Contact: <sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}>",
            ALLOW, f"User-Agent: {ims.BUNDLE.user_agent}",
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp.encode())}",
            "", sdp,
        ]
        call.a_cseq_invite = "1 INVITE"
        return "\r\n".join(lines)

    def build_mt_cancel(self, call: Call):
        """CANCEL baresip's INVITE (MT call abandoned before answer)."""
        return "\r\n".join([
            f"CANCEL {get_uri(self.acc_contact)} SIP/2.0",
            f"Via: SIP/2.0/UDP {vh(self.listen)}:{self.listen_port}"
            f";branch={call.a_branch};rport",
            "Max-Forwards: 70",
            f"From: {call.a_from}",
            f"To: <{self.impu}>",
            f"Call-ID: {call.a_callid}",
            "CSeq: 1 CANCEL", "Content-Length: 0", "", "",
        ])

    def build_mt_ack(self, call: Call):
        """ACK baresip's 2xx we are the UAC toward baresip on an MT call."""
        target = get_uri(call.a_contact) if call.a_contact else get_uri(self.acc_contact)
        return "\r\n".join([
            f"ACK {target} SIP/2.0",
            f"Via: SIP/2.0/UDP {vh(self.listen)}:{self.listen_port}"
            f";branch={br()};rport",
            "Max-Forwards: 70",
            f"From: {call.a_from}",
            f"To: <{self.impu}>" + (f";tag={call.a_remote_tag}" if call.a_remote_tag else ""),
            f"Call-ID: {call.a_callid}",
            "CSeq: 1 ACK",
            f"Contact: <sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}>",
            "Content-Length: 0", "", "",
        ])

    def mt_on_access_response(self, call: Call, code, headers, body):
        if get_tag(headers.get("to", [""])[0]):
            call.a_remote_tag = get_tag(headers["to"][0])
        if headers.get("contact"):
            call.a_contact = get_uri(headers["contact"][0])
        if 100 <= code < 200:
            if code in (180, 183):
                self.net_send(self.net_response(call.n_invite_headers, 180,
                                                "Ringing", totag=call.n_rtag))
            return
        if 200 <= code < 300:
            # We are the UAC toward baresip: ACK its 200 (else baresip keeps
            # retransmitting it). ACK every retransmit; forward to IMS only once.
            self.acc_send(self.build_mt_ack(call))
            if call.state == "up":
                return
            acc_addr, acc_port = sdp_media_endpoint(body)
            if acc_addr and acc_port and call.media:
                call.media.acc_dest = (acc_addr, acc_port)
            net_sdp = rewrite_sdp(body, self.net_local, call.media.net_rtp_port,
                                  call.media.net_rtcp_port) if body.strip() else ""
            # 2xx answer to IMS MUST carry Contact (contact=True) or IMS can't
            # ACK it and CANCELs the call.
            self.net_send(self.net_response(call.n_invite_headers, 200, "OK",
                                            body=net_sdp, totag=call.n_rtag,
                                            contact=True))
            call.state = "up"
            log("MT call answered: media bridged")
            return
        # baresip rejected the call
        self.net_send(self.net_response(call.n_invite_headers, code,
                                        first_reason(code), totag=call.n_rtag))
        self.drop_call(call)

    # ---- misc -------------------------------------------------------------
    def extract_number(self, header_value):
        uri = get_uri(header_value).split(";")[0]
        if uri.startswith("tel:"):
            user = uri[4:]
        elif uri.startswith("sip:") or uri.startswith("sips:"):
            user = uri.split(":", 1)[1].split("@")[0]
        else:
            user = uri
        digits = re.sub(r"[^\d+]", "", user)
        if not digits:
            return ""
        if not digits.startswith("+"):
            if len(digits) == 10:
                digits = "+1" + digits
            elif len(digits) == 11 and digits.startswith("1"):
                digits = "+" + digits
            else:
                digits = "+" + digits
        return digits

    def _write_account(self, acct):
        """Rewrite the single active <sip:...> line in baresip's accounts file
        so it always points at THIS session's tunnel address (which rotates)."""
        path = self.args.baresip_accounts
        try:
            lines = open(path).read().splitlines()
        except OSError as e:
            log(f"--write-account: cannot read {path}: {e}")
            return
        res, done = [], False
        for ln in lines:
            s = ln.strip()
            if s.startswith("<sip:") and not s.startswith("#"):
                if not done:
                    res.append(acct); done = True
            else:
                res.append(ln)
        if not done:
            res.append(acct)
        try:
            open(path, "w").write("\n".join(res) + "\n")
            log(f"--write-account: updated {path}")
        except OSError as e:
            log(f"--write-account: cannot write {path}: {e}")

    # ---- run --------------------------------------------------------------
    def run(self):
        ensure_lo_up()
        log(f"network: {self.transport.upper()} {self.net_local} -> "
            f"{self.args.pcscf}:{self.args.port} (connecting in run)")
        log(f"access : UDP [::]:{self.listen_port} (wildcard) "
            f"advertising {vh(self.listen)}")
        log("live local IPv6 addresses (baresip MUST target one of these):")
        for ifn, addr in local_v6_addrs():
            mark = "  <- advertised" if addr == self.listen else ""
            log(f"    {ifn:6} {addr}{mark}")
        aor = f"sip:{self.msisdn}@{vh(self.listen)}:{self.listen_port}"
        acct = (f"<{aor}>;auth_pass=x;medianat=;mediaenc=;regint=600;"
                "answermode=manual")
        print("\n" + "=" * 70, file=sys.stderr)
        print("POINT BARESIP HERE (this session's tunnel address):", file=sys.stderr)
        print("  /root/.baresip/config   ->  net_interface\ttun1", file=sys.stderr)
        print("                          ->  sip_listen\t[::]:5070", file=sys.stderr)
        print(f"  /root/.baresip/accounts ->  {acct}", file=sys.stderr)
        if self.args.write_account:
            self._write_account(acct)
        print("=" * 70 + "\n", file=sys.stderr)
        # Serve the access side FIRST and unconditionally. baresip must always
        # get an answer regardless of the P-CSCF / IMS state; the upstream
        # connection is brought up separately and retried, never blocking this.
        threading.Thread(target=self.acc_rx_loop, daemon=True).start()
        log(f"access side serving on [::]:{self.listen_port}: bringing up IMS ...")
        if self._bringup():
            log("proxy ready: baresip can register and place/receive calls")
        else:
            log("IMS not up yet: access side still serving (baresip can "
                "register; MO calls answered 503 until IMS is up). retry in 10s")
            self._schedule_retry()
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            log("shutting down")
        finally:
            self.running = False
            for call in list(self.calls_by_n.values()):
                self.drop_call(call)


def first_reason(code):
    return {
        400: "Bad Request", 403: "Forbidden", 404: "Not Found",
        408: "Request Timeout", 480: "Temporarily Unavailable",
        486: "Busy Here", 487: "Request Terminated", 488: "Not Acceptable Here",
        500: "Server Internal Error", 503: "Service Unavailable",
        603: "Decline",
    }.get(code, "Error")


def main():
    ap = argparse.ArgumentParser(
        description="SIP<->IMS B2BUA: bridge a normal SIP softphone to an IMS core.")
    ap.add_argument("--pcscf", required=True, help="THIS session's P-CSCF address")
    ap.add_argument("--imsi", default=None,
                    help="default: read from the SIM via PC/SC")
    ap.add_argument("--msisdn", required=True, help="your E.164 number")
    ap.add_argument("--domain", default=None,
                    help="IMS home domain (default: from the operator bundle)")
    ap.add_argument("--imei", default=None,
                    help="device IMEI (default: from device_config.json)")
    ap.add_argument("--device-config", default=carrier.DEVICE_CONFIG_DEFAULT)
    ap.add_argument("--bundles-dir", default=carrier.BUNDLE_DIR_DEFAULT,
                    help="directory of badtelephony operator bundles")
    ap.add_argument("--local", default=None,
                    help="network-side source address (default: kernel picks the tunnel addr)")
    ap.add_argument("--port", type=int, default=5060, help="P-CSCF SIP port")
    ap.add_argument("--src-port", type=int, default=0,
                    help="network-side TCP source port (0 = kernel chooses; avoids TIME_WAIT)")
    ap.add_argument("--listen", default=None,
                    help="access-side address baresip connects to "
                         "(default: the auto-detected tunnel IPv6 baresip "
                         "refuses loopback, and the tunnel addr is the only "
                         "non-loopback address in the netns)")
    ap.add_argument("--listen-port", type=int, default=5060)
    ap.add_argument("--reader", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--expires", type=int, default=600000,
                    help="REGISTER Expires we request (carrier may shorten it)")
    ap.add_argument("--write-account", action="store_true",
                    help="rewrite baresip's active account line to this session's "
                         "tunnel address on startup (proxy runs as root in the netns)")
    ap.add_argument("--baresip-accounts", default="/root/.baresip/accounts",
                    help="path to baresip accounts file for --write-account")
    ap.add_argument("--quiet", action="store_true",
                    help="trace one line per SIP message instead of the full body")
    args = ap.parse_args()

    # Resolve the subscriber + operator profile before building the proxy:
    # read the IMSI off the SIM (unless given), pick the bundle whose name is
    # the longest prefix of the IMSI, else fall back to 3GPP discovery.
    # Resolve into args.imei so Proxy.__init__ (which sets ims.CONFIG["imei"] =
    # args.imei) sees the resolved value rather than re-clobbering it with None.
    args.imei = carrier.resolve_imei(args.imei, args.device_config)
    imsi, mnc_len = carrier.resolve_imsi(args.imsi, args.reader)
    args.imsi = imsi
    ims.BUNDLE = carrier.load(imsi, args.bundles_dir, mnc_len)
    log(f"IMSI {imsi} -> bundle: {ims.BUNDLE.describe()}")
    if ims.BUNDLE.notes:
        log(f"bundle notes: {ims.BUNDLE.notes}")
    args.domain = args.domain or ims.BUNDLE.domain
    Proxy(args).run()


if __name__ == "__main__":
    main()
