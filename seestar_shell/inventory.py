"""
Incrementally downloads every Seestar APK version from APKPure and
extracts PEM private keys from libopenssllib.so.  Produces:

  • pem_inventory.json              — master inventory (one record per version)
  • ./report.md                    — narrative Markdown with per-version tables
  • ./certificates/pems/           — individual .pem files (version + fingerprint)
  • ./certificates/metadata/       — per-version JSON files
"""

import hashlib
import io
import json
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

PACKAGE  = "com.zwo.seestar"
API_URL  = f"https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name={PACKAGE}"

ANDROID_HEADERS = {
    "x-cv":           "3172501",
    "x-sv":           "29",
    "x-abis":         "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64",
    "x-gp":           "1",
    "Accept":         "application/json, text/plain, */*",
    "Accept-Language":"en-US,en;q=0.9",
    "User-Agent":     "APKPure/3.17.25 (Linux; U; Android 10; Pixel 3 Build/QQ3A.200805.001)",
}

SO_PATHS = [
    "lib/arm64-v8a/libopenssllib.so",
    "lib/armeabi-v7a/libopenssllib.so",
]

CHUNK_SIZE = 65536


# ── Version list ───────────────────────────────────────────────────────────────

def fetch_versions() -> list[dict]:
    """Hit the APKPure mobile API and return [{version, download_url}, ...]."""
    print("Querying APKPure API...")
    resp = requests.get(API_URL, headers=ANDROID_HEADERS, timeout=15)
    resp.raise_for_status()
    return _parse_versions(resp.content)


def _parse_versions(data: bytes) -> list[dict]:
    # Response is protobuf binary.  Decode as latin-1 so every byte is a
    # valid character, then use positional regex matching — same approach
    # as the Rust parse_protobuf_response().
    text = data.decode("latin-1")

    ver_re = re.compile(r"\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b")
    url_re = re.compile(
        r"XAPKJ.{2}(https://download\.pureapk\.com/b/XAPK/[A-Za-z0-9_.\-/?=&%:+]+)"
    )

    ver_positions = [(m.start(), m.group(1)) for m in ver_re.finditer(text)]

    seen     = set()
    versions = []
    for cap in url_re.finditer(text):
        url_pos = cap.start(1)
        url     = cap.group(1)
        version = next(
            (v for pos, v in reversed(ver_positions) if pos < url_pos),
            None,
        )
        if version and version not in seen:
            seen.add(version)
            versions.append({"version": version, "download_url": url})

    return versions


# ── Download ───────────────────────────────────────────────────────────────────

def download_xapk(version: str, url: str, dest_dir: Path) -> Path:
    """Download with HTTP Range resume.  Returns path to the local file."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"Seestar_{version}_APKPure.xapk"

    if dest.exists():
        try:
            zipfile.ZipFile(dest).close()
            size = dest.stat().st_size
            print(f"  {dest.name} already complete ({size:,} bytes)")
            return dest
        except zipfile.BadZipFile:
            pass

    resume_from = dest.stat().st_size if dest.exists() else 0
    headers = dict(ANDROID_HEADERS)
    if resume_from:
        headers["Range"] = f"bytes={resume_from}-"
        print(f"  Resuming {dest.name} from {resume_from:,} bytes")
    else:
        print(f"  Downloading {dest.name}")

    resp = requests.get(url, headers=headers, stream=True, timeout=60)
    resp.raise_for_status()

    total    = int(resp.headers.get("content-length", 0)) + resume_from
    received   = resume_from
    t0         = time.time()
    last_print = t0

    with open(dest, "ab" if resume_from else "wb") as f:
        for chunk in resp.iter_content(CHUNK_SIZE):
            f.write(chunk)
            received += len(chunk)
            now = time.time()
            if now - last_print >= 1.0:
                elapsed  = now - t0 or 0.001
                rate_mb  = (received - resume_from) / elapsed / 1_048_576
                pct      = received * 100 // total if total else 0
                print(
                    f"\r    {received:>12,} / {total:>12,}  {pct:3d}%  {rate_mb:.1f} MB/s",
                    end="", flush=True,
                )
                last_print = now

    elapsed = time.time() - t0
    print(f"\n  Done in {elapsed:.1f}s")
    return dest


# ── PEM extraction ─────────────────────────────────────────────────────────────

def _extract_strings(data: bytes) -> str:
    """strings(1) equivalent: printable ASCII runs of ≥4 chars."""
    out = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= 4:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= 4:
        out.append(cur.decode("ascii"))
    return "\n".join(out)


_PEM_RE = re.compile(
    r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"
)


def extract_pems(xapk_path: Path) -> tuple[list[str], list[str]]:
    """
    Search all split APKs inside an XAPK (or a plain APK) for
    libopenssllib.so and pull out any embedded PEM private key blocks.

    Returns (sorted_unique_pem_list, so_paths_found).
    """
    all_keys = set()
    sos_found = []

    with zipfile.ZipFile(xapk_path) as outer:
        names    = outer.namelist()
        is_xapk  = "manifest.json" in names and any(n.endswith(".apk") for n in names)
        apk_list = (
            [n for n in names if n.endswith(".apk") and "/" not in n]
            if is_xapk else [None]
        )

        for apk_entry in apk_list:
            if apk_entry is None:
                inner = outer
            else:
                inner = zipfile.ZipFile(io.BytesIO(outer.read(apk_entry)))

            try:
                inner_names = inner.namelist()
                for so_path in SO_PATHS:
                    if so_path not in inner_names:
                        continue
                    sos_found.append(so_path)
                    strings = _extract_strings(inner.read(so_path))
                    for m in _PEM_RE.finditer(strings):
                        all_keys.add(m.group(0))
            finally:
                if apk_entry is not None:
                    inner.close()

    return sorted(all_keys), sos_found


def pem_fingerprint(pem: str) -> str:
    """Short SHA-256 fingerprint of the PEM text for display / deduplication."""
    return hashlib.sha256(pem.strip().encode()).hexdigest()[:16]


# ── Inventory I/O ──────────────────────────────────────────────────────────────

def load_inventory(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def save_inventory(inventory: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(inventory, f, indent=2)
    print(f"  Inventory saved → {path}")


# ── Structured output writers ──────────────────────────────────────────────────


def write_metadata_json(version: str, entry: dict, metadata_dir: Path) -> Path:
    """Write per-version metadata as a standalone JSON file."""
    metadata_dir.mkdir(parents=True, exist_ok=True)
    path = metadata_dir / f"{version}.json"
    with open(path, "w") as f:
        json.dump(entry, f, indent=2)
    return path


def _ver_sort_key(v: str) -> list[int]:
    try:
        return [int(x) for x in v.split(".")]
    except ValueError:
        return [0]


def write_markdown_report(inventory: dict, report_path: Path) -> None:
    """Write a narrative Markdown report of the full inventory."""
    now = datetime.now(timezone.utc).isoformat()
    sorted_versions = sorted(inventory, key=_ver_sort_key)

    lines = [
        "# Seestar APK PEM Key Inventory",
        "",
        f"_Generated: {now}_",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Version | Keys | SO Found | SHA-256 Fingerprint(s) | Status |",
        "|---------|-----:|:--------:|------------------------|--------|",
    ]

    for ver in sorted_versions:
        entry  = inventory[ver]
        n      = entry.get("pem_count", "?")
        sos    = "yes" if entry.get("so_files_found") else "no"
        fps    = " · ".join(f"`{fp}`" for fp in (entry.get("pem_fingerprints") or []))
        if "download_error" in entry:
            status = "download error"
        elif "scan_error" in entry:
            status = "scan error"
        elif not entry.get("scanned"):
            status = "not scanned"
        else:
            status = "ok"
        lines.append(f"| {ver} | {n} | {sos} | {fps or '—'} | {status} |")

    lines += [
        "",
        "---",
        "",
        "## Version Details",
        "",
    ]

    for ver in sorted_versions:
        entry = inventory[ver]
        pems  = entry.get("pem_keys") or []
        fps   = entry.get("pem_fingerprints") or []

        lines.append(f"### {ver}")
        lines.append("")

        if url := entry.get("download_url"):
            lines.append(f"- **Source URL**: {url}")
        if size := entry.get("xapk_size"):
            lines.append(f"- **XAPK size**: {size:,} bytes")
        if sos := entry.get("so_files_found"):
            lines.append(f"- **SO files**: {', '.join(sos)}")
        if ts := entry.get("scanned_at"):
            lines.append(f"- **Scanned**: {ts}")
        if err := entry.get("download_error"):
            lines.append(f"- **Download error**: {err}")
        if err := entry.get("scan_error"):
            lines.append(f"- **Scan error**: {err}")

        lines.append(f"- **PEM keys found**: {len(pems)}")
        lines.append("")

        if pems:
            for i, (pem, fp) in enumerate(zip(pems, fps)):
                lines.append(f"#### Key {i + 1}  —  fingerprint `{fp}`")
                lines.append("")
                lines.append("```")
                lines.append(pem.strip())
                lines.append("```")
                lines.append("")
        else:
            lines.append("_No PEM keys found in this version._")
            lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n")
    print(f"  Report written → {report_path}")


def write_outputs(inventory: dict, output_dir: Path) -> None:
    """Write PEM files, per-version metadata JSONs, and the Markdown report."""
    pems_dir     = output_dir / "certificates" / "pems"
    metadata_dir = output_dir / "certificates" / "metadata"

    for ver, entry in inventory.items():
        pems = entry.get("pem_keys") or []
        if pems:
            pems_dir.mkdir(parents=True, exist_ok=True)
            for i, pem in enumerate(pems):
                fp   = pem_fingerprint(pem)
                path = pems_dir / f"Seestar_{ver}_key{i}_{fp}.pem"
                if path.exists():
                    print(f"    PEM      = {path}  (already present)")
                else:
                    path.write_text(pem.strip() + "\n")
                    print(f"    PEM      → {path}")
        write_metadata_json(ver, entry, metadata_dir)

    write_markdown_report(inventory, output_dir / "certificates" / "README.md")


# ── Core scan cycle ────────────────────────────────────────────────────────────

def run_cycle(args, dl_dir: Path, inv_path: Path, output_dir: Path) -> dict:
    """Run one full fetch → download → scan → write cycle."""
    inventory = load_inventory(inv_path)

    versions = fetch_versions()
    print(f"API returned {len(versions)} version(s): "
          f"{', '.join(v['version'] for v in versions)}\n")

    new_versions = []
    for item in versions:
        ver = item["version"]
        url = item["download_url"]

        if _ver_sort_key(ver) < [3, 0, 0]:
            print(f"[{ver}] skipped — no embedded keys before 3.0.0")
            continue

        already_done = ver in inventory and inventory[ver].get("scanned") and not args.rescan
        if already_done:
            print(f"[{ver}] already scanned — skipping (use --rescan to force)")
            continue

        new_versions.append(ver)
        print(f"\n[{ver}]  {url}")
        inventory.setdefault(ver, {})
        inventory[ver].update({"version": ver, "download_url": url})

        if args.skip_download:
            xapk_path = dl_dir / f"Seestar_{ver}_APKPure.xapk"
            if not xapk_path.exists():
                print(f"  Not on disk, skipping (--skip-download is set)")
                continue
        else:
            try:
                xapk_path = download_xapk(ver, url, dl_dir)
            except Exception as exc:
                print(f"  Download failed: {exc}")
                inventory[ver]["download_error"] = str(exc)
                save_inventory(inventory, inv_path)
                continue

        inventory[ver]["xapk_size"] = xapk_path.stat().st_size

        print(f"  Scanning for PEM keys...")
        try:
            pems, sos = extract_pems(xapk_path)
        except Exception as exc:
            print(f"  Scan failed: {exc}")
            inventory[ver]["scan_error"] = str(exc)
            save_inventory(inventory, inv_path)
            continue

        fps = [pem_fingerprint(k) for k in pems]
        inventory[ver].update({
            "so_files_found":   sos,
            "pem_count":        len(pems),
            "pem_keys":         pems,
            "pem_fingerprints": fps,
            "scanned":          True,
            "scanned_at":       datetime.now(timezone.utc).isoformat(),
        })
        inventory[ver].pop("download_error", None)
        inventory[ver].pop("scan_error",     None)

        xapk_path.unlink()
        inventory[ver].pop("xapk_path", None)
        print(f"  Deleted {xapk_path.name}")

        if pems:
            print(f"  {len(pems)} key(s) found — fingerprint(s): {', '.join(fps)}")
        else:
            print(f"  No PEM keys found  (SO files present: {sos or 'none'})")

        save_inventory(inventory, inv_path)

    print(f"\nWriting outputs to {output_dir}/")
    write_outputs(inventory, output_dir)

    print(f"\n{'─'*70}")
    print(f"  {'Version':<12} {'Keys':>5}  {'SO':^6}  Fingerprints")
    print(f"{'─'*70}")
    for ver in sorted(inventory, key=_ver_sort_key):
        entry = inventory[ver]
        n     = entry.get("pem_count", "?")
        sos   = "yes" if entry.get("so_files_found") else "no"
        fps   = ", ".join(entry.get("pem_fingerprints") or [])
        err   = " [error]" if ("download_error" in entry or "scan_error" in entry) else ""
        ns    = "" if entry.get("scanned") else " [not scanned]"
        print(f"  {ver:<12} {str(n):>5}  {sos:<6}  {fps}{err}{ns}")
    print(f"{'─'*70}")
    print(f"  {len(inventory)} version(s) total  |  inventory: {inv_path}")
    if new_versions:
        print(f"  Newly processed: {', '.join(new_versions)}")

    return inventory


# ── Subcommand wiring ──────────────────────────────────────────────────────────

def add_subparser(sub):
    p = sub.add_parser(
        "inventory",
        help="Download APK versions and extract embedded PEM private keys",
    )
    p.add_argument("--download-dir",  default="apk_cache",
                   help="Directory for downloaded XAPKs (default: apk_cache)")
    p.add_argument("--output-dir",    default=".",
                   help="Output directory for report.md, certificates/ (default: .)")
    p.add_argument("--inventory",     default="certificates/pem_inventory.json",
                   help="Master inventory JSON file (default: certificates/pem_inventory.json)")
    p.add_argument("--skip-download", action="store_true",
                   help="Scan already-downloaded files only, skip fetching new ones")
    p.add_argument("--rescan",        action="store_true",
                   help="Re-scan versions already in the inventory")
    p.add_argument("--watch",         action="store_true",
                   help="Poll for new versions continuously")
    p.add_argument("--interval",      type=int, default=3600,
                   help="Polling interval in seconds for --watch mode (default: 3600)")
    p.set_defaults(func=run)


def run(args):
    dl_dir     = Path(args.download_dir)
    inv_path   = Path(args.inventory)
    output_dir = Path(args.output_dir)

    if args.watch:
        print(f"Watch mode — polling every {args.interval}s  (Ctrl+C to stop)\n")
        while True:
            ts = datetime.now(timezone.utc).isoformat()
            print(f"\n{'='*70}")
            print(f"  Check at {ts}")
            print(f"{'='*70}\n")
            try:
                run_cycle(args, dl_dir, inv_path, output_dir)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"Cycle error: {exc}", file=sys.stderr)
            print(f"\nSleeping {args.interval}s until next check...")
            time.sleep(args.interval)
    else:
        run_cycle(args, dl_dir, inv_path, output_dir)
