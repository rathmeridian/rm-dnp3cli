#!/usr/bin/env python3
"""
dnp3_outstation.py - a minimal DNP3 (over TCP) outstation simulator.

Listens for DNP3/TCP master connections (default port 20000), decodes incoming
requests, keeps a small in-memory point database, and sends back well-formed
DNP3 responses. It is meant as a bench peer for a DNP3 master such as the
companion `dnp3cli` tool, and for protocol testing/learning -- not as a
production outstation (no DNP3 Secure Authentication, no TLS, single fragment).

Run:
    python3 dnp3_outstation.py                 # listen on 0.0.0.0:20000, addr 10
    python3 dnp3_outstation.py -a 4 -p 20000   # outstation address 4
    python3 dnp3_outstation.py --bi 8 --ai 4   # 8 binary + 4 analog inputs

Supported requests:
    Read (class 0 / 1 / 2 / 3)        -> Response with current BI/AI/BO/AO data
    Direct Operate CROB  (group 12)   -> updates binary outputs, echoes status
    Direct Operate Analog Out (gp 41) -> updates analog outputs, echoes status
    Cold / Warm Restart               -> Response with a time-delay object
    Enable / Disable Unsolicited      -> Response (acknowledged, IIN only)
    Delay Measurement                 -> Response with a time-delay object
Anything else gets a Response with IIN2.0 (NO_FUNC_CODE_SUPPORT) set.
"""

import argparse
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------
# DNP3 CRC (polynomial 0x3D65, reflected 0xA6BC, result complemented)
# --------------------------------------------------------------------------
def dnp3_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFF


def crc_bytes(block: bytes) -> bytes:
    return struct.pack("<H", dnp3_crc(block))


# --------------------------------------------------------------------------
# Function codes / names
# --------------------------------------------------------------------------
FC_CONFIRM        = 0x00
FC_READ           = 0x01
FC_WRITE          = 0x02
FC_SELECT         = 0x03
FC_OPERATE        = 0x04
FC_DIRECT_OPERATE = 0x05
FC_COLD_RESTART   = 0x0D
FC_WARM_RESTART   = 0x0E
FC_ENABLE_UNSOL   = 0x14
FC_DISABLE_UNSOL  = 0x15
FC_DELAY_MEASURE  = 0x17
FC_RESPONSE       = 0x81

FC_NAMES = {
    0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE", 0x03: "SELECT",
    0x04: "OPERATE", 0x05: "DIRECT_OPERATE", 0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART", 0x14: "ENABLE_UNSOLICITED",
    0x15: "DISABLE_UNSOLICITED", 0x17: "DELAY_MEASUREMENT",
}

CROB_CODES = {
    0x01: "PULSE_ON", 0x02: "PULSE_OFF", 0x03: "LATCH_ON", 0x04: "LATCH_OFF",
    0x41: "CLOSE/PULSE_ON", 0x81: "TRIP/PULSE_ON",
}


# --------------------------------------------------------------------------
# Point database
# --------------------------------------------------------------------------
class Database:
    def __init__(self, n_bi, n_ai, n_bo, n_ao):
        self.bi = [False] * n_bi            # binary inputs
        self.ai = [i * 100 for i in range(n_ai)]  # analog inputs (16-bit)
        self.bo = [False] * n_bo            # binary output status
        self.ao = [0] * n_ao                # analog output status


# --------------------------------------------------------------------------
# Link-layer frame read / build
# --------------------------------------------------------------------------
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(sock):
    """Read one DNP3 link frame, return (dest, src, user_data) or None."""
    header = recv_exact(sock, 10)             # 0x05 0x64 + 8 more
    if not header or header[0] != 0x05 or header[1] != 0x64:
        return None
    if crc_bytes(header[0:8]) != header[8:10]:
        print("  ! bad link header CRC")
        return None

    length = header[2]
    ctrl   = header[3]
    dest   = struct.unpack("<H", header[4:6])[0]
    src    = struct.unpack("<H", header[6:8])[0]
    user_len = length - 5                     # bytes of transport+app payload

    # Payload travels in 16-byte data blocks, each followed by a 2-byte CRC.
    user = b""
    remaining = user_len
    while remaining > 0:
        chunk_len = min(16, remaining)
        block = recv_exact(sock, chunk_len + 2)
        if not block:
            return None
        data, blk_crc = block[:chunk_len], block[chunk_len:]
        if crc_bytes(data) != blk_crc:
            print("  ! bad data block CRC")
            return None
        user += data
        remaining -= chunk_len

    print(f"  link: ctrl=0x{ctrl:02X} dest={dest} src={src} len={length}")
    return dest, src, user


def build_frame(dest, src, user: bytes) -> bytes:
    """Wrap transport+application payload in an outstation link frame."""
    header = bytes([0x05, 0x64, 5 + len(user), 0x44]) + \
             struct.pack("<H", dest) + struct.pack("<H", src)
    frame = header + crc_bytes(header)
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        frame += block + crc_bytes(block)
    return frame


# --------------------------------------------------------------------------
# Object encoders for responses
# --------------------------------------------------------------------------
def obj_binary_inputs(values):
    """Group 1 var 2 (binary input with flags), range 0..N-1."""
    if not values:
        return b""
    body = bytearray([0x01, 0x02, 0x00, 0x00, len(values) - 1])  # grp,var,q=0x00,start,stop
    for v in values:
        body.append(0x81 if v else 0x01)      # online(0x01) | state(0x80)
    return bytes(body)


def obj_analog_inputs(values):
    """Group 30 var 2 (16-bit analog input with flag), range 0..N-1."""
    if not values:
        return b""
    body = bytearray([0x1E, 0x02, 0x00, 0x00, len(values) - 1])
    for v in values:
        body.append(0x01)                      # flag: online
        body += struct.pack("<h", _clamp16(v))
    return bytes(body)


def obj_binary_out_status(values):
    """Group 10 var 2 (binary output status), range 0..N-1."""
    if not values:
        return b""
    body = bytearray([0x0A, 0x02, 0x00, 0x00, len(values) - 1])
    for v in values:
        body.append(0x81 if v else 0x01)
    return bytes(body)


def obj_analog_out_status(values):
    """Group 40 var 2 (16-bit analog output status), range 0..N-1."""
    if not values:
        return b""
    body = bytearray([0x28, 0x02, 0x00, 0x00, len(values) - 1])
    for v in values:
        body.append(0x01)
        body += struct.pack("<h", _clamp16(v))
    return bytes(body)


def obj_time_delay_fine(ms=0):
    """Group 52 var 2 (time delay fine), count 1."""
    return bytes([0x34, 0x02, 0x07, 0x01]) + struct.pack("<H", ms & 0xFFFF)


def _clamp16(v):
    return max(-32768, min(32767, int(v)))


# --------------------------------------------------------------------------
# Request handling
# --------------------------------------------------------------------------
def decode_read_classes(objs):
    classes = []
    i = 0
    while i + 2 < len(objs):
        g, v, q = objs[i], objs[i + 1], objs[i + 2]
        if g == 0x3C:  # group 60
            classes.append({1: "Class0", 2: "Class1", 3: "Class2",
                            4: "Class3"}.get(v, f"var{v}"))
        i += 3
        if q == 0x06:  # all objects, no range field
            continue
        break
    return classes


def handle_request(db, app: bytes):
    """Given an application fragment, return (app_response_payload)."""
    if len(app) < 2:
        return None
    app_ctrl = app[0]
    func     = app[1]
    objs     = app[2:]
    seq      = app_ctrl & 0x0F
    name     = FC_NAMES.get(func, f"0x{func:02X}")
    print(f"  app:  ctrl=0x{app_ctrl:02X} seq={seq} func={name}")

    iin = 0x0000
    resp_objs = b""

    if func == FC_READ:
        classes = decode_read_classes(objs)
        print(f"        read classes: {', '.join(classes) or '(none decoded)'}")
        # Return everything we have (acts as an integrity/class-0 reply).
        resp_objs = (obj_binary_inputs(db.bi) + obj_analog_inputs(db.ai) +
                     obj_binary_out_status(db.bo) + obj_analog_out_status(db.ao))

    elif func == FC_DIRECT_OPERATE:
        resp_objs = apply_operate(db, objs)

    elif func in (FC_COLD_RESTART, FC_WARM_RESTART):
        print(f"        {name} requested")
        resp_objs = obj_time_delay_fine(0)

    elif func == FC_DELAY_MEASURE:
        resp_objs = obj_time_delay_fine(0)

    elif func in (FC_ENABLE_UNSOL, FC_DISABLE_UNSOL):
        print(f"        {name} acknowledged")
        # Just acknowledge with IIN; no data objects.

    else:
        print(f"        unsupported function {name}")
        iin |= 0x0001  # IIN2.0 FUNC_NOT_SUPPORTED (low byte of IIN2)

    # Response app control echoes the request sequence, FIR=FIN=1.
    resp = bytes([0xC0 | seq, FC_RESPONSE]) + struct.pack("<H", iin) + resp_objs
    return resp


def apply_operate(db, objs):
    """Light parse of a direct-operate object header; update DB; echo status."""
    if len(objs) < 3:
        return objs
    group, var, qual = objs[0], objs[1], objs[2]

    if group == 0x0C and var == 0x01:          # CROB (binary output)
        # qualifier 0x17: 1-byte count, 1-byte index prefix per item
        idx = 0
        count = objs[3] if len(objs) > 3 else 1
        p = 4
        for _ in range(count):
            if p + 12 > len(objs):
                break
            index = objs[p]
            code  = objs[p + 1]
            p += 12                            # index(1)+code(1)+count(1)+on(4)+off(4)+status(1)
            cname = CROB_CODES.get(code, f"0x{code:02X}")
            if index < len(db.bo):
                if code in (0x03, 0x41):       # latch on / close
                    db.bo[index] = True
                elif code in (0x04, 0x81):     # latch off / trip
                    db.bo[index] = False
            idx = index
            print(f"        CROB point {index}: {cname} -> "
                  f"BO[{index}]={db.bo[index] if index < len(db.bo) else '?'}")
        # Echo the request objects back (status bytes already 0x00 = success).
        return objs

    if group == 0x29:                          # analog output (group 41)
        count = objs[3] if len(objs) > 3 else 1
        p = 4
        size = {0x01: 4, 0x02: 2, 0x03: 4, 0x04: 8}.get(var, 2)
        for _ in range(count):
            if p + 1 + size + 1 > len(objs):
                break
            index = objs[p]
            raw = objs[p + 1:p + 1 + size]
            if size == 2:
                value = struct.unpack("<h", raw)[0]
            elif size == 4:
                value = struct.unpack("<i", raw)[0]
            else:
                value = struct.unpack("<q", raw)[0]
            p += 1 + size + 1
            if index < len(db.ao):
                db.ao[index] = value
            print(f"        Analog out point {index}: value={value}")
        return objs

    print(f"        operate on group {group} var {var} (echoed, no state change)")
    return objs


# --------------------------------------------------------------------------
# Server loop
# --------------------------------------------------------------------------
def serve(host, port, my_addr, db):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f"DNP3 outstation (addr={my_addr}) listening on {host}:{port}")
    print(f"  points: {len(db.bi)} BI, {len(db.ai)} AI, "
          f"{len(db.bo)} BO, {len(db.ao)} AO")
    try:
        while True:
            conn, peer = srv.accept()
            print(f"\n[{time.strftime('%H:%M:%S')}] connection from "
                  f"{peer[0]}:{peer[1]}")
            try:
                handle_client(conn, my_addr, db)
            except (ConnectionError, OSError) as e:
                print(f"  connection error: {e}")
            finally:
                conn.close()
                print("  connection closed")
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        srv.close()


def handle_client(conn, my_addr, db):
    while True:
        frame = read_frame(conn)
        if frame is None:
            return
        dest, src, user = frame
        if dest != my_addr:
            print(f"  (frame addressed to {dest}, not us ({my_addr}) -- ignoring)")
            continue
        if not user:
            continue

        # Transport header is the first user byte; app fragment follows.
        app = user[1:]
        resp_app = handle_request(db, app)
        if resp_app is None:
            continue

        # Single-fragment transport header (FIR=FIN=1, seq 0).
        payload = bytes([0xC0]) + resp_app
        out = build_frame(src, my_addr, payload)   # reply: dest=master, src=us
        print(f"  -> response {len(out)} bytes")
        conn.sendall(out)


def main():
    ap = argparse.ArgumentParser(description="Minimal DNP3/TCP outstation simulator")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("-p", "--port", type=int, default=20000, help="TCP port (default 20000)")
    ap.add_argument("-a", "--addr", type=int, default=10, help="outstation DNP3 address (default 10)")
    ap.add_argument("--bi", type=int, default=8, help="number of binary inputs")
    ap.add_argument("--ai", type=int, default=4, help="number of analog inputs")
    ap.add_argument("--bo", type=int, default=8, help="number of binary outputs")
    ap.add_argument("--ao", type=int, default=4, help="number of analog outputs")
    args = ap.parse_args()

    db = Database(args.bi, args.ai, args.bo, args.ao)
    # A couple of inputs set so a read returns something interesting.
    if args.bi >= 2:
        db.bi[0] = True
    serve(args.host, args.port, args.addr, db)


if __name__ == "__main__":
    sys.exit(main())
