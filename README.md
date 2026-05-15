# seestar-shell

Security research tools for the ZWO Seestar smart telescope.  The scope
runs a Pi-based Linux system and accepts firmware updates over the local
network — no authentication required.  These tools recover the firmware
signing key embedded in the Android app, build custom firmware payloads,
and push them to the scope.

---

## Quick start: enable SSH on your Seestar

Make sure your scope is on the same network (often reachable as `seestar.local`), then:

```bash
git clone https://github.com/humanpowercell-spec/seestar-shell.git && cd seestar-shell
python3 -m venv && source venv/bin/activate && pip install -e .
seestar-shell enable-ssh seestar.local
```

This builds and uploads a signed firmware payload that enables SSH password
authentication and sets the `pi` and `root` passwords to `password`.  The
scope reboots automatically; once it comes back online you can SSH in:

```bash
ssh pi@<SCOPE_IP>
# password: password
```

---

## How it works

### The key

The Seestar app ships a native library — `libopenssllib.so` — inside its APK.
This library handles firmware verification on the Android side, and it contains
the RSA-1024 **private** key as a plaintext PEM string embedded directly in the
binary.  Shipping the private key in the app is a fundamental design flaw: a
correct implementation would embed only the public key and keep the private key
on ZWO's signing server.  Because the private key is in the app, anyone who has
the app can sign arbitrary firmware that the scope will accept.

Extracting it requires no special tooling — a standard `strings` pass over the
`.so` file surfaces the PEM block, which begins and ends with the familiar
`-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` markers.  The key
has been identical across every app version surveyed (3.0.0 through 3.1.2), and
is built into this tool.  You do not need to extract it yourself.

### Signing and deploying

1. **Build a firmware package** — `seestar-shell pack` tars a directory of
   files, bzip2-compresses the archive, and appends an RSA-1024 PKCS#1v15
   / SHA-1 signature using the recovered key — matching the format the
   scope's updater expects.

2. **Deploy to the scope** — `seestar-shell upload` (or the higher-level
   `enable-ssh`, `cmd`, and `run-script` subcommands) connects over TCP,
   streams the signed `.bz` file, and optionally waits for the scope to
   reboot and come back online.

### Key surveillance

The `inventory` subcommand downloads every historical Seestar APK from APKPure,
extracts `libopenssllib.so` from each one, and scans it for embedded PEM blocks.
It is not required for normal use, but can be run continuously (`--watch`) to
detect if ZWO ships a new app version with a rotated or different key.

---

## Installation

```
pip install -e .
```

Requires Python 3.10+.  Dependencies (`requests`, `cryptography`) are
declared in `pyproject.toml` and installed automatically.

---

## Usage

```
seestar-shell COMMAND [args]
```

### `inventory` — extract signing keys from APK releases

Downloads and scans every Seestar APK version for embedded PEM private keys.
Only versions 3.0.0 and later are scanned (earlier releases do not contain keys).
```
seestar-shell inventory [options]

  --download-dir DIR   Cache dir for XAPKs (default: apk_cache/)
  --output-dir DIR     Output root (default: .)
  --inventory FILE     Master JSON inventory
                       (default: certificates/pem_inventory.json)
  --skip-download      Scan files already on disk, skip new downloads
  --rescan             Re-scan versions already recorded in the inventory
  --watch              Poll APKPure continuously for new versions
  --interval N         Polling interval in seconds for --watch (default: 3600)
```

**Outputs** (all under `certificates/`):

| Path | Description |
|------|-------------|
| `certificates/pem_inventory.json` | Master inventory — one record per APK version |
| `certificates/README.md` | Narrative Markdown with per-version summary and key blocks |
| `certificates/pems/` | Individual `.pem` files named `Seestar_<version>_key<n>_<fingerprint>.pem` |
| `certificates/metadata/` | Per-version JSON files |

XAPKs are deleted immediately after a successful scan.  PEM files are only
written if not already present; the report is always regenerated.

---

### `pack` — build a signed firmware package

Packs a directory into a signed Seestar firmware `.bz` file.

```
seestar-shell pack FIRMWARE_DIR [OUTPUT.bz] [--key KEY.pem]

  FIRMWARE_DIR   Directory whose contents to pack
  OUTPUT.bz      Output file (default: iscope_64.packed.bz)
  --key KEY.pem  Private key to sign with (default: embedded recovered key)
```

The output format is `bzip2(tar) || RSA_signature` — exactly what the
scope's updater verifies before applying a package.

---

### `upload` — upload a firmware package

Uploads a pre-built firmware `.bz` to the scope over TCP.

```
seestar-shell upload HOST FILE [REMOTE_NAME] [--no-wait]

  HOST         Scope IP address or hostname
  FILE         Firmware .bz file to upload
  REMOTE_NAME  Name sent to scope (default: iscope_64)
               Use "iscope" for S50/S30, "iscope_64" for S30 Pro / S50 Pro
  --no-wait    Exit immediately after upload without waiting for reboot
```

---

### `enable-ssh` — enable SSH on the scope

Builds and deploys a firmware payload that enables SSH password
authentication and sets the `pi` and `root` passwords to `password`.

```
seestar-shell enable-ssh HOST [REMOTE_NAME] [--no-wait]
```

---

### `cmd` — run an inline shell command on the scope

Wraps an arbitrary shell command in the firmware ceremony and deploys it.

```
seestar-shell cmd HOST 'COMMAND' [REMOTE_NAME] [--no-wait]
```

Example:

```
seestar-shell cmd 192.168.1.42 'sleep 10; echo yeet'
```

---

### `run-script` — deploy a local script to the scope

Copies a local script file into the firmware payload alongside a ceremony
wrapper that invokes it.

```
seestar-shell run-script HOST SCRIPT [REMOTE_NAME] [--no-wait]

  HOST     Scope IP address or hostname
  SCRIPT   Path to local script file to run on the scope
```

---

## Firmware ceremony

The `enable-ssh`, `cmd`, and `run-script` subcommands all wrap their
payload in the same on-device ceremony:

1. Source the Seestar environment (`/home/pi/ASIAIR/config`)
2. Kill the updater process
3. Remount the root filesystem read-write
4. **Run the payload**
5. Restart the updater
6. Remount the root filesystem read-only
7. Signal completion

---

## Credits

Inspired by and built on top of prior work by
[@bguthro](https://github.com/bguthro/seestar-tool), whose reverse
engineering of the Seestar firmware update protocol made this possible.

---

## Findings

See `certificates/README.md` and
`certificates/pem_inventory.json` for the full version-by-version survey
of embedded keys across all published Seestar APK releases.
