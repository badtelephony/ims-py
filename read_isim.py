#!/usr/bin/env python3
"""
read_isim.py -- dump the IMS identities from the card's ISIM application.

If the SIM has an ISIM (ADF.ISIM, AID prefix A000000087 1004), it carries the
AUTHORITATIVE IMS identities the real device registers with -- these override
any IMSI-derived guess:

  EF_IMPI   (6F02)  private identity  -> Authorization username
  EF_IMPU   (6F04)  public identity   -> From / To / Contact AoR  (record-based,
                                          may hold several; the 1st is the default)
  EF_DOMAIN (6F03)  home domain       -> Request-URI / realm
  EF_IST    (6F07)  ISIM service table (which services are present)
  EF_PCSCF  (6F09)  provisioned P-CSCF (if any; VoWiFi normally uses the ePDG
                                        CFG_REPLY instead, but worth seeing)

Feed the results straight into ims_register.py:
    --impi <EF_IMPI>  --impu <EF_IMPU[0]>  --domain <EF_DOMAIN>

Requires pyscard:  pip install pyscard
Usage:  python3 read_isim.py [--reader N] [--pin 1234] [--list]
"""

import argparse
import sys

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
except ImportError:
    sys.exit("pyscard required:  pip install pyscard")

ISIM_AID = toBytes("A000000087")  # match A000000087 **1004** (ISIM) below
ISIM_APP = 0x1004                 # application code distinguishing ISIM from USIM (1002)


def send(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    while sw1 == 0x61:
        d, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        data += d
    if sw1 == 0x6C:
        data, sw1, sw2 = conn.transmit(list(apdu[:4]) + [sw2])
        while sw1 == 0x61:
            d, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            data += d
    return data, sw1, sw2


def ok(sw1, sw2):
    return sw1 == 0x90 and sw2 == 0x00


def selected(sw1, sw2):
    return ok(sw1, sw2) or sw1 == 0x61


def select(conn, p1, p2, body):
    return send(conn, [0x00, 0xA4, p1, p2, len(body)] + list(body) + [0x00])


def parse_dir_aids(conn):
    """Read EF.DIR (2F00) and return every application AID it lists."""
    select(conn, 0x00, 0x04, toBytes("3F00"))
    _, sw1, sw2 = select(conn, 0x00, 0x04, toBytes("2F00"))
    aids = []
    if not selected(sw1, sw2):
        return aids
    for rec in range(1, 16):
        data, sw1, sw2 = send(conn, [0x00, 0xB2, rec, 0x04, 0x00])
        if not ok(sw1, sw2) or not data or data[0] != 0x61:
            if sw1 != 0x90:
                break
            continue
        i = 2
        while i + 1 < len(data):
            tag, ln = data[i], data[i + 1]
            if tag == 0x4F:
                aids.append(data[i + 2:i + 2 + ln])
            i += 2 + ln
    return aids


def find_isim_aid(conn):
    """Locate the ISIM AID: prefix A000000087, application bytes 1004."""
    for aid in parse_dir_aids(conn):
        if (len(aid) >= 7 and aid[:5] == ISIM_AID
                and aid[5] == 0x10 and aid[6] == 0x04):
            return aid
    return None


def select_isim(conn):
    aid = find_isim_aid(conn)
    if aid is None:
        # last resort: try a bare partial-AID select for the ISIM app
        cand = toBytes("A0000000871004")
        _, sw1, sw2 = select(conn, 0x04, 0x04, cand)
        return (cand, (sw1, sw2)) if selected(sw1, sw2) else (None, (sw1, sw2))
    _, sw1, sw2 = select(conn, 0x04, 0x04, aid)
    return (aid, (sw1, sw2)) if selected(sw1, sw2) else (None, (sw1, sw2))


def read_transparent(conn, fid):
    _, sw1, sw2 = select(conn, 0x00, 0x04, toBytes(fid))
    if not selected(sw1, sw2):
        return None, (sw1, sw2)
    data, sw1, sw2 = send(conn, [0x00, 0xB0, 0x00, 0x00, 0x00])
    return (data, (sw1, sw2)) if ok(sw1, sw2) else (None, (sw1, sw2))


def read_all_records(conn, fid, maxrec=8):
    _, sw1, sw2 = select(conn, 0x00, 0x04, toBytes(fid))
    if not selected(sw1, sw2):
        return None, (sw1, sw2)
    out = []
    for rec in range(1, maxrec + 1):
        data, sw1, sw2 = send(conn, [0x00, 0xB2, rec, 0x04, 0x00])
        if not ok(sw1, sw2):
            break
        out.append(data)
    return out, (0x90, 0x00)


def tlv80_str(data):
    """EF_IMPI/IMPU/DOMAIN store the identity as a tag-'80' TLV of UTF-8 text."""
    if not data:
        return ""
    b = data
    if b[0] == 0x80 and len(b) >= 2:
        b = b[2:2 + b[1]]
    b = bytes(x for x in b if x not in (0xFF,))           # strip padding
    try:
        return b.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return toHexString(list(b))


def verify_pin(conn, pin):
    body = list(pin.encode("ascii")) + [0xFF] * (8 - len(pin))
    _, sw1, sw2 = send(conn, [0x00, 0x20, 0x00, 0x01, 0x08] + body)
    return ok(sw1, sw2)


def main():
    ap = argparse.ArgumentParser(description="Dump IMS identities from the card's ISIM.")
    ap.add_argument("--reader", type=int, default=0)
    ap.add_argument("--pin")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    rl = readers()
    if not rl:
        sys.exit("no PC/SC readers found")
    if args.list:
        for i, r in enumerate(rl):
            print(f"{i}: {r}")
        return

    conn = rl[args.reader].createConnection()
    conn.connect()
    print(f"reader: {rl[args.reader]}\n")

    if args.pin and not verify_pin(conn, args.pin):
        print("warning: PIN verify failed\n")

    aid, (sw1, sw2) = select_isim(conn)
    if aid is None:
        print(f"No ISIM application present (last SW={sw1:02X}{sw2:02X}).")
        print("=> IMS identities are USIM-derived. Per 3GPP TS 23.003 13.x the")
        print("   IMPI/temporary-IMPU realm is ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org,")
        print("   NOT the vanity domain. Try:")
        print("     --impi <IMSI>@ims.mnc480.mcc311.3gppnetwork.org")
        print("     --impu sip:<IMSI>@ims.mnc480.mcc311.3gppnetwork.org")
        return

    print(f"ISIM selected (AID {toHexString(aid)})\n")

    impi, _ = read_transparent(conn, "6F02")
    dom,  _ = read_transparent(conn, "6F03")
    ist,  _ = read_transparent(conn, "6F07")
    impus, _ = read_all_records(conn, "6F04")
    pcscf, _ = read_transparent(conn, "6F09")

    print(f"EF_IMPI   (6F02): {tlv80_str(impi) if impi else '--'}")
    print(f"EF_DOMAIN (6F03): {tlv80_str(dom) if dom else '--'}")
    if impus:
        for n, rec in enumerate(impus):
            s = tlv80_str(rec)
            if s:
                print(f"EF_IMPU #{n+1} (6F04): {s}")
    else:
        print("EF_IMPU   (6F04): --")
    if ist:
        print(f"EF_IST    (6F07): {toHexString(ist)}")
    if pcscf:
        print(f"EF_PCSCF  (6F09): {tlv80_str(pcscf)}")

    print("\nFeed ims_register.py:")
    impi_s = tlv80_str(impi) if impi else "<IMSI>@vzims.com"
    impu_s = tlv80_str(impus[0]) if impus else "sip:<MSISDN>@vzims.com"
    dom_s = tlv80_str(dom) if dom else "vzims.com"
    print(f"   --impi '{impi_s}'  --impu '{impu_s}'  --domain '{dom_s}'")


if __name__ == "__main__":
    main()
