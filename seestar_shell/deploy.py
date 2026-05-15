"""
Deploy subcommands: pack + upload in one step.

  enable-ssh HOST [remote_name] [--no-wait]
      Deploys SSH-enabling firmware (sets passwords, enables sshd auth).

  run-script HOST SCRIPT [remote_name] [--no-wait]
      Wraps a user-provided script in the on-device ceremony and deploys it.
"""

import shutil
import tempfile
from pathlib import Path

from seestar_shell import pack, upload

_CEREMONY_HEADER = """\
#!/bin/bash
source /home/pi/ASIAIR/config
sudo killall -2 $updater_exec
sudo mount -o remount,rw / 2>&1
"""

_CEREMONY_FOOTER = """\
sudo chmod +x $updater_path$updater_exec
$updater_path$updater_exec > /dev/null 2>&1 &
echo "updater is restarted"
sudo mount -o remount,ro / 2>&1
echo "update is done"
${updater_path}${updater_exec} -p 31 > /dev/null 2>&1
"""

_ENABLE_SSH_SCRIPT = """\
echo -e "password\\npassword" | sudo passwd pi
echo -e "password\\npassword" | sudo passwd root

sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/#UsePAM no/UsePAM yes/' /etc/ssh/sshd_config
sudo systemctl reload sshd
"""


def _do_deploy(firmware_dir: Path, host: str, remote_name: str, wait: bool) -> None:
    with tempfile.NamedTemporaryFile(suffix=".bz", delete=False) as f:
        tmp_bz = Path(f.name)
    try:
        pack.pack(firmware_dir, tmp_bz, pack._EMBEDDED_KEY_PEM)
        upload.upload(host, str(tmp_bz), remote_name, wait)
    finally:
        tmp_bz.unlink(missing_ok=True)


def _write_script(path: Path, payload: str) -> None:
    path.write_text(_CEREMONY_HEADER + "\n" + payload + "\n" + _CEREMONY_FOOTER)
    path.chmod(0o755)


def _cmd_run(args):
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_script(Path(tmpdir) / "update_package.sh", args.cmd)
        _do_deploy(Path(tmpdir), args.host, args.remote_name, wait=not args.no_wait)


def _enable_ssh_run(args):
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_script(Path(tmpdir) / "update_package.sh", _ENABLE_SSH_SCRIPT)
        _do_deploy(Path(tmpdir), args.host, args.remote_name, wait=not args.no_wait)


def _run_script_run(args):
    script_path = Path(args.script)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        user_script = tmp_path / script_path.name
        shutil.copy(str(script_path), user_script)
        user_script.chmod(0o755)

        _write_script(tmp_path / "update_package.sh", f"./{script_path.name}")

        _do_deploy(tmp_path, args.host, args.remote_name, wait=not args.no_wait)


def add_subparser(sub):
    p0 = sub.add_parser("cmd", help="Run an inline shell command on the scope")
    p0.add_argument("host", help="Scope IP address or hostname")
    p0.add_argument("cmd", help="Shell command to run (e.g. 'sleep 10; echo yeet')")
    p0.add_argument("remote_name", nargs="?", default="iscope_64",
                    help="Filename sent to scope (default: iscope_64)")
    p0.add_argument("--no-wait", action="store_true",
                    help="Exit after upload without waiting for reboot")
    p0.set_defaults(func=_cmd_run)

    p1 = sub.add_parser("enable-ssh", help="Deploy SSH-enabling firmware to scope")
    p1.add_argument("host", help="Scope IP address or hostname")
    p1.add_argument("remote_name", nargs="?", default="iscope_64",
                    help="Filename sent to scope (default: iscope_64)")
    p1.add_argument("--no-wait", action="store_true",
                    help="Exit after upload without waiting for reboot")
    p1.set_defaults(func=_enable_ssh_run)

    p2 = sub.add_parser("run-script", help="Deploy a custom script to the scope")
    p2.add_argument("host", help="Scope IP address or hostname")
    p2.add_argument("script", help="Path to script file to run on scope")
    p2.add_argument("remote_name", nargs="?", default="iscope_64",
                    help="Filename sent to scope (default: iscope_64)")
    p2.add_argument("--no-wait", action="store_true",
                    help="Exit after upload without waiting for reboot")
    p2.set_defaults(func=_run_script_run)
