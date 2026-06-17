#!/usr/bin/env python3
"""
sim_aka.py, run 3G/UMTS AKA on a USIM via PC/SC and return the quintuplet
components (RES, CK, IK) plus AUTS on resync.

This is the same card operation SWu-IKEv2 does for EAP-AKA, factored out so the
IMS registration client can reuse it for the *separate* IMS-AKA challenge.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

USIM_AID_PREFIX = bytes.fromhex("A0000000871002")


class AKAError(Exception):
    pass


class AKASyncFailure(Exception):
    """Card reported AUTN sequence-number out of range; .auts must be sent back."""
    def __init__(self, auts: bytes):
        super().__init__("AKA synchronisation failure (AUTS returned)")
        self.auts = auts


def _xmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    if sw1 == 0x61:  # response bytes available -> GET RESPONSE
        data, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
    return bytes(data), sw1, sw2


def _select_by_aid(conn, aid: bytes):
    apdu = bytes([0x00, 0xA4, 0x04, 0x04, len(aid)]) + aid + b"\x00"
    return _xmit(conn, apdu)


def _select_usim(conn):
    """Walk EF.DIR records, find the USIM application, SELECT it."""
    # SELECT EF.DIR (2F00) under MF
    _xmit(conn, bytes([0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0x00]))
    for rec in range(1, 16):
        data, sw1, _ = conn.transmit([0x00, 0xB2, rec, 0x04, 0x26])
        if sw1 != 0x90:
            break
        b = bytes(data)
        # Application template 0x61 -> AID in tag 0x4F
        i = b.find(0x4F)
        if i < 0 or i + 1 >= len(b):
            continue
        aid_len = b[i + 1]
        aid = b[i + 2:i + 2 + aid_len]
        if aid.startswith(USIM_AID_PREFIX):
            _, sw1, _ = _select_by_aid(conn, aid)
            if sw1 in (0x90, 0x61):
                return aid
            raise AKAError("found USIM AID but SELECT failed")
    raise AKAError("no USIM application found in EF.DIR")


def _open(reader_index: int):
    from smartcard.System import readers
    rlist = readers()
    if not rlist:
        raise AKAError("no PC/SC readers")
    conn = rlist[reader_index].createConnection()
    conn.connect()
    return conn


def _select_fid(conn, fid: bytes):
    """SELECT an EF by file-ID under the currently-selected application."""
    apdu = bytes([0x00, 0xA4, 0x00, 0x04, len(fid)]) + fid + b"\x00"
    return _xmit(conn, apdu)


def _read_binary(conn, length: int, offset: int = 0):
    p1, p2 = (offset >> 8) & 0x7F, offset & 0xFF
    data, sw1, sw2 = _xmit(conn, bytes([0x00, 0xB0, p1, p2, length]))
    if sw1 not in (0x90, 0x61):
        raise AKAError(f"READ BINARY failed: SW={sw1:02X}{sw2:02X}")
    return bytes(data)


def _decode_imsi(raw: bytes) -> str:
    """Decode EF.IMSI (3GPP TS 31.102 4.2.2): length byte + nibble-swapped BCD,
    the first nibble being a parity/type digit that is dropped."""
    if not raw:
        raise AKAError("empty EF.IMSI")
    n = raw[0]
    nibbles = ""
    for b in raw[1:1 + n]:
        nibbles += f"{b & 0x0F}{(b >> 4) & 0x0F}"
    digits = nibbles[1:].rstrip("f")          # drop parity nibble, strip padding
    if not (14 <= len(digits) <= 15) or not digits.isdigit():
        raise AKAError(f"implausible IMSI decoded: {digits!r}")
    return digits


def read_subscriber(reader_index: int = 0):
    """Read the IMSI (and, if available, the MNC length) straight from the
    USIM so it need not be supplied on the CLI. Returns {imsi, mnc_len}."""
    conn = _open(reader_index)
    _select_usim(conn)
    _select_fid(conn, b"\x6F\x07")            # EF.IMSI
    imsi = _decode_imsi(_read_binary(conn, 9))
    mnc_len = None
    try:
        _select_fid(conn, b"\x6F\xAD")        # EF.AD (administrative data)
        ad = _read_binary(conn, 4)
        if len(ad) >= 4 and ad[3] in (2, 3):  # byte 4 = number of MNC digits
            mnc_len = ad[3]
    except AKAError:
        pass
    return {"imsi": imsi, "mnc_len": mnc_len}


def run_aka(rand: bytes, autn: bytes, reader_index: int = 0):
    """
    Run UMTS AKA for (rand, autn). Returns dict {res, ck, ik}.
    Raises AKASyncFailure(auts) if the card requests resync.
    """
    if len(rand) != 16 or len(autn) != 16:
        raise AKAError("RAND and AUTN must be 16 bytes each")

    conn = _open(reader_index)

    _select_usim(conn)

    # AUTHENTICATE in UMTS security context (P2=0x81), data = Lr||RAND||Lr||AUTN
    body = bytes([len(rand)]) + rand + bytes([len(autn)]) + autn
    apdu = bytes([0x00, 0x88, 0x00, 0x81, len(body)]) + body + b"\x00"
    data, sw1, sw2 = _xmit(conn, apdu)
    if sw1 not in (0x90, 0x61):
        raise AKAError(f"AUTHENTICATE failed: SW={sw1:02X}{sw2:02X}")

    # Response tag: 0xDB = success (RES, CK, IK[, Kc]); 0xDC = sync failure (AUTS)
    tag = data[0]
    p = 1
    if tag == 0xDC:
        l = data[p]; p += 1
        return _sync(data[p:p + l])
    if tag != 0xDB:
        raise AKAError(f"unexpected AUTHENTICATE response tag {tag:02X}")

    res_len = data[p]; p += 1
    res = data[p:p + res_len]; p += res_len
    ck_len = data[p]; p += 1
    ck = data[p:p + ck_len]; p += ck_len
    ik_len = data[p]; p += 1
    ik = data[p:p + ik_len]; p += ik_len
    return {"res": res, "ck": ck, "ik": ik}


def _sync(auts: bytes):
    raise AKASyncFailure(auts)


# IMS-AKA digest (RFC 3310 / RFC 4169)
def decode_aka_nonce(nonce_b64: str):
    """Split an IMS-AKA WWW-Authenticate nonce into (RAND, AUTN).

    The nonce is base64(RAND[16] || AUTN[16] || optional server data) per
    RFC 3310; the trailing '===' tolerates missing base64 padding.
    """
    raw = base64.b64decode(nonce_b64 + "===")
    if len(raw) < 32:
        raise AKAError(f"AKA nonce too short ({len(raw)} bytes; need >= 32)")
    return raw[:16], raw[16:32]


def aka_challenge(nonce_b64: str, reader_index: int = 0):
    """Decode an IMS-AKA nonce and run AKA on the card in one step.

    Returns the quintuplet dict {res, ck, ik}; raises AKASyncFailure(auts) if
    the card requests resync (caller handles the AUTS resend).
    """
    rand, autn = decode_aka_nonce(nonce_b64)
    return run_aka(rand, autn, reader_index=reader_index)


def aka_password(res: bytes, ik: bytes, ck: bytes, algorithm: str) -> bytes:
    """The SIP-digest 'password' for IMS-AKA.

    RFC 3310 (AKAv1-MD5) uses RES directly; RFC 4169 (AKAv2-MD5) uses
    base64(HMAC-MD5(RES||IK||CK, "http-digest-akav2-password")).
    """
    if algorithm and algorithm.upper().startswith("AKAV2"):
        prf = hmac.new(res + ik + ck, b"http-digest-akav2-password",
                       hashlib.md5).digest()
        return base64.b64encode(prf)
    return res


def digest_response(username, realm, password_bytes, method, uri, nonce,
                    qop=None, cnonce=None, nc=None):
    """RFC 2617 MD5 digest with the AKA RES / AKAv2 PRF as the password."""
    ha1 = hashlib.md5(username.encode() + b":" + realm.encode()
                      + b":" + password_bytes).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop in ("auth", "auth-int"):
        return hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
