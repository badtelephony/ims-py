#!/usr/bin/env python3
"""
sms_3gpp2.py, decode a binary 3GPP2 SMS (the body of a SIP MESSAGE with
Content-Type application/vnd.3gpp2.sms).

Only decoding is implemented, X.S0048 MO (sending) is a separate problem and is
not something I'm in the mood to deal with rn. (it's called badtelephony not goodphone)
"""
from __future__ import annotations


class SmsDecodeError(Exception):
    pass


class _Bits:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0                 # absolute bit offset
        self.nbits = len(data) * 8

    def read(self, n: int) -> int:
        if self.pos + n > self.nbits:
            raise SmsDecodeError(
                f"ran off end of field (wanted {n} bits at {self.pos}/{self.nbits})")
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            bit = (byte >> (7 - (self.pos & 7))) & 1
            v = (v << 1) | bit
            self.pos += 1
        return v

    def left(self) -> int:
        return self.nbits - self.pos


P_TELESERVICE_ID = 0x00
P_SERVICE_CATEGORY = 0x01
P_ORIG_ADDRESS = 0x02
P_DEST_ADDRESS = 0x04
P_BEARER_REPLY = 0x06
P_BEARER_DATA = 0x08

S_MESSAGE_ID = 0x00
S_USER_DATA = 0x01
S_MC_TIMESTAMP = 0x03
S_CALLBACK_NUMBER = 0x0E

TRANSPORT_MSG_TYPES = {0x00: "point-to-point", 0x01: "broadcast", 0x02: "acknowledge"}
BEARER_MSG_TYPES = {
    1: "deliver", 2: "submit", 3: "cancellation",
    4: "delivery-ack", 5: "user-ack", 6: "read-ack",
}

# MSG_ENCODING values (C.S0015-B table 4.5.2-1)
ENC_OCTET = 0x00
ENC_IS91 = 0x01
ENC_ASCII7 = 0x02
ENC_IA5 = 0x03
ENC_UNICODE = 0x04
ENC_SHIFT_JIS = 0x05
ENC_KOREAN = 0x06
ENC_LATIN_HEBREW = 0x07
ENC_LATIN = 0x08
ENC_GSM7 = 0x09
ENCODING_NAMES = {
    ENC_OCTET: "octet", ENC_IS91: "is91", ENC_ASCII7: "ascii7", ENC_IA5: "ia5",
    ENC_UNICODE: "unicode", ENC_SHIFT_JIS: "shift-jis", ENC_KOREAN: "korean",
    ENC_LATIN_HEBREW: "latin/hebrew", ENC_LATIN: "latin", ENC_GSM7: "gsm7",
}

# 4-bit DTMF digit codes used when an address is in DIGIT_MODE 0 (C.S0005).
_DTMF = {0x1: "1", 0x2: "2", 0x3: "3", 0x4: "4", 0x5: "5", 0x6: "6",
         0x7: "7", 0x8: "8", 0x9: "9", 0xA: "0", 0xB: "*", 0xC: "#"}

# GSM 7-bit default alphabet (3GPP TS 23.038) basic table, index 0..127.
_GSM_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ"
    " !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
_GSM_EXT = {0x0A: "\f", 0x14: "^", 0x28: "{", 0x29: "}", 0x2F: "\\",
            0x3C: "[", 0x3D: "~", 0x3E: "]", 0x40: "|", 0x65: "€"}


def _decode_chars(b: _Bits, encoding: int, num_fields: int) -> str:
    if encoding in (ENC_ASCII7, ENC_IA5):
        return "".join(chr(b.read(7)) for _ in range(num_fields))
    if encoding == ENC_UNICODE:
        raw = bytearray()
        for _ in range(num_fields):
            raw += b.read(16).to_bytes(2, "big")
        return raw.decode("utf-16-be", errors="replace")
    if encoding in (ENC_OCTET, ENC_LATIN):
        return bytes(b.read(8) for _ in range(num_fields)).decode("latin-1")
    if encoding == ENC_LATIN_HEBREW:
        return bytes(b.read(8) for _ in range(num_fields)).decode(
            "iso-8859-8", errors="replace")
    if encoding == ENC_GSM7:
        out, esc = [], False
        for _ in range(num_fields):
            c = b.read(7)
            if esc:
                out.append(_GSM_EXT.get(c, " "))
                esc = False
            elif c == 0x1B:
                esc = True
            else:
                out.append(_GSM_BASIC[c])
        return "".join(out)
    # shift-jis / korean / is91 and anything unknown: best-effort octet dump.
    n = b.left() // 8
    return "<" + ENCODING_NAMES.get(encoding, f"enc{encoding}") + ":" + \
           bytes(b.read(8) for _ in range(n)).hex() + ">"


def _decode_address(data: bytes) -> str:
    """Originating / Destination Address parameter (C.S0015-B 3.4.3.3)."""
    b = _Bits(data)
    digit_mode = b.read(1)
    number_mode = b.read(1)
    if digit_mode:
        b.read(3)                    # NUMBER_TYPE
        if number_mode == 0:
            b.read(4)                # NUMBER_PLAN
    num = b.read(8)
    if digit_mode == 0:
        return "".join(_DTMF.get(b.read(4), "?") for _ in range(num))
    return "".join(chr(b.read(8)) for _ in range(num))


def _decode_callback(data: bytes) -> str:
    """Call-Back Number subparameter (C.S0015-B 4.5.15): like an address but
    with no NUMBER_MODE bit."""
    b = _Bits(data)
    digit_mode = b.read(1)
    if digit_mode:
        b.read(3)                    # NUMBER_TYPE
        b.read(4)                    # NUMBER_PLAN
    num = b.read(8)
    if digit_mode == 0:
        return "".join(_DTMF.get(b.read(4), "?") for _ in range(num))
    return "".join(chr(b.read(8)) for _ in range(num))


def _bcd(byte: int) -> int:
    return (byte >> 4) * 10 + (byte & 0x0F)


def _decode_timestamp(data: bytes) -> str:
    """Message Center Time Stamp (C.S0015-B 4.5.4): 6 BCD octets
    YY MM DD HH MM SS. Years 96-99 are 19xx, otherwise 20xx."""
    if len(data) < 6:
        raise SmsDecodeError("short MC timestamp")
    yy = _bcd(data[0])
    year = 1900 + yy if yy >= 96 else 2000 + yy
    return (f"{year:04d}-{_bcd(data[1]):02d}-{_bcd(data[2]):02d} "
            f"{_bcd(data[3]):02d}:{_bcd(data[4]):02d}:{_bcd(data[5]):02d}")


def _decode_user_data(data: bytes) -> dict:
    """User Data subparameter (C.S0015-B 4.5.2)."""
    b = _Bits(data)
    encoding = b.read(5)
    if encoding == ENC_IS91:
        b.read(8)                    # MESSAGE_TYPE, only present for IS-91
    num = b.read(8)
    text = _decode_chars(b, encoding, num)
    return {"encoding": ENCODING_NAMES.get(encoding, encoding),
            "num_fields": num, "text": text}


def _iter_tlv(data: bytes):
    """Yield (id, value_bytes) for octet-aligned TLV (ID, LEN, value)."""
    p = 0
    while p + 2 <= len(data):
        pid, plen = data[p], data[p + 1]
        p += 2
        yield pid, data[p:p + plen]
        p += plen


def _decode_bearer_data(data: bytes, out: dict) -> None:
    for sid, val in _iter_tlv(data):
        if sid == S_MESSAGE_ID:
            b = _Bits(val)
            out["message_type"] = BEARER_MSG_TYPES.get(b.read(4), "reserved")
            out["message_id"] = b.read(16)
        elif sid == S_USER_DATA:
            out.update(_decode_user_data(val))
        elif sid == S_MC_TIMESTAMP:
            out["timestamp"] = _decode_timestamp(val)
        elif sid == S_CALLBACK_NUMBER:
            out["callback"] = _decode_callback(val)


def decode(body: bytes) -> dict:
    """Decode an application/vnd.3gpp2.sms body.

    Returns a dict that may contain: transport_msg_type, teleservice,
    orig_addr, dest_addr, message_type, message_id, encoding, num_fields,
    text, timestamp, callback. Raises SmsDecodeError on a malformed body.
    """
    if not body:
        raise SmsDecodeError("empty body")
    out = {"transport_msg_type": TRANSPORT_MSG_TYPES.get(body[0], body[0])}
    for pid, val in _iter_tlv(body[1:]):
        if pid == P_TELESERVICE_ID:
            out["teleservice"] = int.from_bytes(val, "big")
        elif pid == P_ORIG_ADDRESS:
            out["orig_addr"] = _decode_address(val)
        elif pid == P_DEST_ADDRESS:
            out["dest_addr"] = _decode_address(val)
        elif pid == P_BEARER_DATA:
            _decode_bearer_data(val, out)
    return out
