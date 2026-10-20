"""Run the ignored Linux network response test inside a new network namespace.

Compile tests without root first. Pass the resulting whohack_respond executable.
Only the isolated loopback interface is enabled; the host firewall is untouched.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--recovery-only", action="store_true", help="Test cleanup without requiring NFT_SOCKET support")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run the already compiled test as root on Linux")
    executable = args.executable.resolve(strict=True)
    if not args.inside:
        command = ["unshare", "--net", "--fork", sys.executable,
                   str(Path(__file__).resolve()), str(executable), "--inside"]
        if args.recovery_only:
            command.append("--recovery-only")
        result = subprocess.run(command, timeout=75)
    else:
        if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            parser.error("Refusing to run in the host network namespace")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
        test = "isolated_missing_table_recovery" if args.recovery_only else "isolated_network_block_release_and_external_loss"
        result = subprocess.run([str(executable), "--exact", "linux::acceptance::" + test,
                                 "--ignored", "--nocapture"],
                                env=dict(os.environ, WHOHACK_RESPONSE_ISOLATED="1"), timeout=60)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
