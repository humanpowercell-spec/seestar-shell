"""
Pack a directory into a signed Seestar firmware .bz file.

Output format: bzip2(tar) || RSA-1024-PKCS1v15-SHA1-signature
"""

import bz2
import io
import os
import tarfile
import warnings
from pathlib import Path

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

_OWNER_NAME = "xiongxiaofeng"
_OWNER_ID   = 1013

_EMBEDDED_KEY_PEM = b"""\
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO0S7LqhYnfQP2vn
s7sZE8s4fV/QJTv1uasQ/0vxgubBdCB9E9N56B+aZSxUf3M8kU7F0Y+pmCNv9T9z
BzC7fu44SJYMgA2IgJOrGe6axLyTrxmYUXpsgC6HK6lfHCULFKOLrHX0WS+IKgm+
14vHnA7+3Ic3LIzK/OryGktpgvXhAgMBAAECgYEAwwzu+B4PhcQwafcYSLc5Mdoo
TMxT1iE1wSka4sCxkmlXweMmjLef42CEHRToR0dtxgG7iRdftMhIXwukvtOEeaUE
qCyjzLfvSYqd1xTE6LCVCwp1vKLZUIc7BeY7Ae7kVkrmKknQtlCGmO8MxZ8tFPgS
YVoUEzGBq1HztIDPTgECQQD95yTxHoBaEei9N/lkw5e3voiTomvlj8OA4n/BY0U1
8s7LHCfxklHW1BLBcLuJZc+ChWnRbqD7PlyIcPud2ckFAkEA7wgybiAaCiPpZqGI
MI3Xk8jIK7nPXCSW7eweq9jkfs6MqmYer2RDeqf2IJ87mZWQSY+p31XJcvgAHT7u
T9IgLQJAX/2oWMRoUCUfMZJc5jyQOnZ9Wht44VRF3I9FL47hVrESf3WIoGrqJ+cL
pDiDnkFwf28C/5vsnrAH+cmFRztUJQJAIgSpoLCi5BSOUBPnHPni11541nhAQZ3X
eQ7kopJgmodsz4dvEIkVbWxgA+6FfesiOMXgaC9+VwVihscBBY0jFQJAGU+fIYC7
ehg/GNbyD+UNL8xKqx9Pe69Q58B3kRnfDBce5KReMO5nNr8o3Pa/yWNu7ZjKWs3N
wzGGrKR8OsYqzw==
-----END PRIVATE KEY-----"""


def _owner_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
    tarinfo.uid   = _OWNER_ID
    tarinfo.gid   = _OWNER_ID
    tarinfo.uname = _OWNER_NAME
    tarinfo.gname = _OWNER_NAME
    return tarinfo


def pack(firmware_dir: Path, output_path: Path, key_pem: bytes) -> None:
    print(f"=== Packing {firmware_dir} → {output_path} ===")

    # Build GNU tar in memory — matches: tar --format=gnu --owner=... --no-recursion
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:", format=tarfile.GNU_FORMAT) as tf:
        for dirpath, dirnames, filenames in os.walk(firmware_dir):
            dirnames.sort()
            dp = Path(dirpath)
            if dp != firmware_dir:
                arcname = "./" + str(dp.relative_to(firmware_dir))
                tf.add(str(dp), arcname=arcname, recursive=False, filter=_owner_filter)
            for fname in sorted(filenames):
                fpath = dp / fname
                arcname = "./" + str(fpath.relative_to(firmware_dir))
                tf.add(str(fpath), arcname=arcname, recursive=False, filter=_owner_filter)

    tar_data = buf.getvalue()
    entry_count = tar_data.count(b"ustar")
    print(f"  tar: ~{entry_count} entries, {len(tar_data)} bytes")

    bz2_data = bz2.compress(tar_data, compresslevel=9)
    print(f"  bz2: {len(bz2_data)} bytes")

    privkey = serialization.load_pem_private_key(key_pem, password=None)
    sig = privkey.sign(bz2_data, padding.PKCS1v15(), hashes.SHA1())

    import hashlib
    print(f"  sha1: {hashlib.sha1(bz2_data).hexdigest()}")
    print(f"  sig:  {sig.hex()}")

    output_path.write_bytes(bz2_data + sig)
    print(f"  out:  {output_path} ({len(bz2_data) + len(sig)} bytes)")


# ── Subcommand wiring ──────────────────────────────────────────────────────────

def add_subparser(sub):
    p = sub.add_parser(
        "pack",
        help="Pack a directory into a signed firmware .bz file",
    )
    p.add_argument("firmware_dir",
                   help="Directory whose contents to pack")
    p.add_argument("output", nargs="?", default="iscope_64.packed.bz",
                   help="Output .bz file (default: iscope_64.packed.bz)")
    p.add_argument("--key", default=None, metavar="KEY.pem",
                   help="Path to PEM private key file (default: use embedded key)")
    p.set_defaults(func=run)


def run(args):
    firmware_dir = Path(args.firmware_dir).resolve()
    output_path  = Path(args.output).resolve()
    key_pem      = Path(args.key).read_bytes() if args.key else _EMBEDDED_KEY_PEM
    pack(firmware_dir, output_path, key_pem)
