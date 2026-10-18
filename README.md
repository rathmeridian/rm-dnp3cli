# dnp3cli

A small interactive DNP3-over-TCP master/client for Linux. It presents a menu
of common DNP3 application commands and sends the selected one to a target
outstation, then hex-dumps the response.

> Intended for commissioning, protocol testing, and **authorized** security
> assessment of DNP3 outstations you own or are permitted to test. Sending
> control commands (operate, restart) to live industrial equipment can affect
> physical processes — only point it at devices you are allowed to operate.

## Build

```bash
make
# or:  cc -O2 -Wall -Wextra -o dnp3cli dnp3cli.c
```

## Usage

```bash
./dnp3cli [-p port] [-s master_addr] [-d outstation_addr] <target_ip>
```

| Flag | Meaning                     | Default |
|------|-----------------------------|---------|
| `-p` | TCP port                    | 20000   |
| `-s` | DNP3 source (master) address| 1       |
| `-d` | DNP3 destination (outstation) address | 10 |

Example:

```bash
./dnp3cli -d 4 192.0.2.50
```

## Menu

| # | Command | DNP3 details |
|---|---------|--------------|
| 1 | Read Class 0 | FC 0x01, obj 60v1 |
| 2 | Full integrity poll | FC 0x01, obj 60v2/v3/v4/v1 |
| 3–6 | Direct Operate CROB | FC 0x05, obj 12v1 (latch on/off, pulse trip/close) |
| 7 | Direct Operate Analog Output (16-bit) | FC 0x05, obj 41v2 |
| 8 | Cold Restart | FC 0x0D |
| 9 | Warm Restart | FC 0x0E |
| 10 | Enable Unsolicited | FC 0x14 |
| 11 | Disable Unsolicited | FC 0x15 |
| 12 | Delay Measurement | FC 0x17 |

## Notes / scope

- Implements the Data Link layer (0x0564 header, per-block DNP3 CRC with
  polynomial 0x3D65), a single-fragment Transport header, and a minimal
  Application layer.
- Requests are sent as **Unconfirmed User Data**; multi-fragment responses and
  link-layer confirmations are not reassembled — the raw reply is hex-dumped so
  you can inspect the IIN bits and objects.
- No TLS/DNP3-SA (Secure Authentication). Add as needed.

---

# dnp3_outstation.py — simulator

A minimal DNP3/TCP **outstation** (slave) simulator, written in Python 3 with
only the standard library. It's a bench peer for `dnp3cli`: it accepts a master
connection, validates and decodes incoming frames, keeps a small in-memory point
database, and sends back well-formed responses. Handy for testing a master or
learning the protocol without live equipment.

## Requirements

Python 3.7+ — no third-party packages.

## Run

```bash
python3 dnp3_outstation.py                 # 0.0.0.0:20000, outstation addr 10
python3 dnp3_outstation.py -a 4 -p 20000   # outstation address 4
python3 dnp3_outstation.py --bi 16 --ai 8  # size the point database
```

| Flag            | Meaning                              | Default   |
|-----------------|--------------------------------------|-----------|
| `--host`        | Bind address                         | `0.0.0.0` |
| `-p`, `--port`  | TCP port                             | `20000`   |
| `-a`, `--addr`  | Outstation (this device's) DNP3 addr | `10`      |
| `--bi`          | Number of binary inputs              | `8`       |
| `--ai`          | Number of analog inputs              | `4`       |
| `--bo`          | Number of binary outputs             | `8`       |
| `--ao`          | Number of analog outputs             | `4`       |

It logs each decoded request (link addresses, function code, decoded classes /
control codes) and the response size, so you can watch the exchange.

## What it answers

| Request (from master) | Response |
|-----------------------|----------|
| Read (class 0/1/2/3) | current BI (grp 1v2), AI (grp 30v2), BO status (grp 10v2), AO status (grp 40v2) |
| Direct Operate CROB (grp 12) | updates binary outputs (latch/close = on, trip = off), echoes status = success |
| Direct Operate Analog Out (grp 41) | updates analog output value, echoes status |
| Cold / Warm Restart | Response with a time-delay object (grp 52v2) |
| Enable / Disable Unsolicited | Response, acknowledged (IIN only) |
| Delay Measurement | Response with a time-delay object |
| anything else | Response with IIN2.0 (function not supported) |

## End-to-end test (two terminals)

Terminal 1 — start the outstation:

```bash
python3 dnp3_outstation.py -a 10
```

Terminal 2 — drive it with the master:

```bash
./dnp3cli -d 10 127.0.0.1
```

Then in the master menu, try: `1` (read class 0), `3` → point index `2`
(latch on), `1` again (read — binary output 2 now reads ON). The outstation
window logs every decoded request.

## Scope / limitations

- Single-fragment application messages; no multi-fragment reassembly, no
  link-layer or application confirmations, no unsolicited reporting.
- Not DNP3 Secure Authentication or TLS; one client handled at a time.
- Intended for lab/test use, not as a production outstation.
