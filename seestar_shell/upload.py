"""
Upload a firmware .bz file to a Seestar scope.

Protocol (ports 4350/4361, no auth required):
  1. Connect data socket to 4361.
  2. Connect command socket to 4350 — scope sends a greeting JSON line.
  3. Send begin_recv JSON (file_len, file_name, md5, run_update=true).
  4. Read ACK.
  5. Stream file bytes on data socket.
  6. Optionally poll until scope reboots and comes back online.
"""

import hashlib
import json
import socket
import sys
import time
from pathlib import Path

CMD_PORT       = 4350
DATA_PORT      = 4361
CHUNK_SIZE     = 4096
WAIT_TIMEOUT_S = 300


def recv_line(sock: socket.socket) -> str:
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            break
        buf.extend(b)
        if b == b'\n':
            break
    return buf.decode('utf-8', errors='replace').strip()


def upload(host: str, bz_path: str, remote_name: str, wait: bool) -> None:
    data = Path(bz_path).read_bytes()
    file_len = len(data)
    fmd5 = hashlib.md5(data).hexdigest()

    print(f"file:   {bz_path}")
    print(f"size:   {file_len:,} bytes")
    print(f"md5:    {fmd5}")
    print(f"target: {host}  name: {remote_name}")
    print()

    # Data socket must be connected before command socket.
    print(f"Connecting data  → {host}:{DATA_PORT}")
    s_data = socket.create_connection((host, DATA_PORT), timeout=10)

    print(f"Connecting cmd   → {host}:{CMD_PORT}")
    s_cmd = socket.create_connection((host, CMD_PORT), timeout=10)
    s_cmd.settimeout(10)

    greeting = recv_line(s_cmd)
    try:
        name = json.loads(greeting).get('name', 'updater')
    except Exception:
        name = 'updater'
    print(f"Greeting: {greeting[:80]}")
    print(f"Updater:  {name}")
    print()

    cmd = json.dumps({
        "id": 1,
        "method": "begin_recv",
        "params": [{
            "file_len": file_len,
            "file_name": remote_name,
            "run_update": True,
            "md5": fmd5,
        }]
    }) + "\r\n"
    s_cmd.sendall(cmd.encode())

    ack_raw = recv_line(s_cmd)
    print(f"ACK: {ack_raw}")
    try:
        ack = json.loads(ack_raw)
        if ack.get('error') is not None:
            sys.exit(f"ERROR: scope rejected upload: {ack['error']}")
        if ack.get('code', 0) != 0:
            sys.exit(f"ERROR: scope rejected upload (code {ack.get('code')}): {ack_raw}")
    except json.JSONDecodeError:
        sys.exit(f"ERROR: invalid ACK: {ack_raw}")
    print()

    print("Uploading...")
    t0 = time.time()
    sent = 0
    for i in range(0, file_len, CHUNK_SIZE):
        s_data.sendall(data[i:i + CHUNK_SIZE])
        sent += min(CHUNK_SIZE, file_len - i)
        elapsed = time.time() - t0 or 0.001
        rate_mb = sent / elapsed / 1_048_576
        pct = sent * 100 // file_len
        print(f"\r  {sent:>12,} / {file_len:,}  {pct:3d}%  {rate_mb:.1f} MB/s", end='', flush=True)

    s_data.close()
    s_cmd.close()
    elapsed = time.time() - t0
    print(f"\n\nUpload done in {elapsed:.1f}s  ({file_len / elapsed / 1_048_576:.1f} MB/s avg)")

    if not wait:
        print("Skipping post-install wait (--no-wait).")
        return

    print("\nScope is installing — DO NOT power off...")
    deadline = time.time() + WAIT_TIMEOUT_S
    t_install = time.time()
    went_offline = False
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, CMD_PORT), timeout=1)
            s.close()
            secs = int(time.time() - t_install)
            print(f"\r  installing... {secs}s", end='', flush=True)
            time.sleep(0.5)
        except OSError:
            print(f"\n  Scope offline — rebooting.")
            went_offline = True
            break

    if not went_offline:
        print("\nWARNING: scope never went offline — may have already rebooted.", file=sys.stderr)

    print("Waiting for scope to come back online...")
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, CMD_PORT), timeout=1)
            s.settimeout(1)
            line = recv_line(s)
            s.close()
            if line:
                total = time.time() - t0
                print(f"Scope is back online. Total time: {total:.0f}s")
                return
        except OSError:
            pass
        time.sleep(0.5)

    print(f"WARNING: timed out after {WAIT_TIMEOUT_S}s waiting for scope.", file=sys.stderr)


# ── Subcommand wiring ──────────────────────────────────────────────────────────

def add_subparser(sub):
    p = sub.add_parser(
        "upload",
        help="Upload a firmware .bz file to a Seestar scope",
    )
    p.add_argument("host",        help="Scope IP address or hostname")
    p.add_argument("file",        help="Firmware .bz file to upload")
    p.add_argument("remote_name", nargs="?", default="iscope_64",
                   help="Filename sent to scope (default: iscope_64). "
                        "Use 'iscope' for S50/S30, 'iscope_64' for S30 Pro / S50 Pro.")
    p.add_argument("--no-wait",   action="store_true",
                   help="Exit after upload without waiting for reboot")
    p.set_defaults(func=run)


def run(args):
    upload(args.host, args.file, args.remote_name, wait=not args.no_wait)
