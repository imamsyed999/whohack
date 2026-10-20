"""Build a Windows MSVC service in WSL using an already installed Windows SDK.

LLVM is a build tool only; no Windows runtime, SDK, or system policy is installed
or changed by this script. See docs/building.md for the optional LLVM setup.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-root", type=Path, default=Path.home() / "vigil-cross-tools")
    parser.add_argument("--msvc-dir", type=Path, default=Path(
        "/mnt/c/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/VC/Tools/MSVC/14.29.30133"))
    parser.add_argument("--sdk-dir", type=Path, default=Path("/mnt/c/Program Files (x86)/Windows Kits/10"))
    parser.add_argument("--sdk-version", default="10.0.19041.0")
    parser.add_argument("--stage", action="store_true", help="Copy built executables to target/<profile> for the Windows launcher")
    parser.add_argument("--release", action="store_true", help="Build optimized release executables")
    parser.add_argument("--jobs", type=int, default=4, help="Maximum concurrent compiler jobs (default: 4)")
    parser.add_argument("--target-dir", type=Path, default=Path.home() / "whohack-build-cache",
                        help="Shared, disposable build cache for the service and UI")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--package", action="append", help="Workspace package to build (repeatable)")
    selection.add_argument("--workspace", action="store_true", help="Build every workspace member")
    selection.add_argument("--ui", action="store_true", help="Build the separate native Windows tray workspace")
    parser.add_argument("command", nargs="?", choices=("build", "clippy", "test-build"), default="build")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if sys.platform != "linux":
        parser.error("Run this optional cross-compiler inside WSL.")
    root = Path(__file__).resolve().parents[2]
    llvm = args.llvm_root.resolve()
    llvm_bin = llvm / "usr/lib/llvm-18/bin"
    includes = [args.msvc_dir / "include"] + [args.sdk_dir / "Include" / args.sdk_version / part
                                             for part in ("ucrt", "shared", "um", "winrt")]
    libs = [args.msvc_dir / "lib/x64"] + [args.sdk_dir / "Lib" / args.sdk_version / part / "x64"
                                        for part in ("ucrt", "um")]
    for path in [llvm_bin / "clang", llvm_bin / "lld-link", llvm_bin / "llvm-lib", *includes, *libs]:
        if not path.exists():
            parser.error(f"Missing build prerequisite: {path}. See docs/building.md.")
    wrappers = Path.home() / ".cache/whohack-msvc-tools"
    wrappers.mkdir(parents=True, exist_ok=True)
    commands = {
        "clang-cl": [str(llvm_bin / "clang"), "--driver-mode=cl"],
        "llvm-lib": [str(llvm_bin / "llvm-lib")],
        "link": [str(llvm_bin / "lld-link"), *["-libpath:" + str(p) for p in libs]],
    }
    if args.ui:
        if not (llvm_bin / "llvm-rc").is_file():
            parser.error("The Windows tray build also requires llvm-rc")
        commands["llvm-rc"] = [str(llvm_bin / "llvm-rc"), *["/I" + str(p) for p in includes]]
    for name, command in commands.items():
        wrapper = wrappers / name
        wrapper.write_text("#!/bin/sh\nexport LD_LIBRARY_PATH=" + shlex.quote(str(llvm / "usr/lib/x86_64-linux-gnu"))
                           + "\nexec " + shlex.join(command) + ' "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
    target = args.target_dir.resolve()
    cargo = Path.home() / ".cargo/bin/cargo"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CC_SHELL_ESCAPED_FLAGS="1")
    env["PATH"] = os.pathsep.join([str(wrappers), str(cargo.parent), str(llvm_bin), env["PATH"]])
    env.update(CC_x86_64_pc_windows_msvc=str(wrappers / "clang-cl"),
               CXX_x86_64_pc_windows_msvc=str(wrappers / "clang-cl"),
               AR_x86_64_pc_windows_msvc=str(wrappers / "llvm-lib"),
               CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=str(wrappers / "link"),
               CFLAGS_x86_64_pc_windows_msvc=shlex.join(["-imsvc" + str(p) for p in includes]))
    command = [str(cargo), "test" if args.command == "test-build" else args.command,
               "--target", "x86_64-pc-windows-msvc", "--locked", "--jobs", str(args.jobs)]
    if args.release:
        command.append("--release")
    if args.ui:
        command += ["--manifest-path", str(root / "ui/src-tauri/Cargo.toml")]
    if args.command == "clippy":
        command += ["--workspace", "--all-targets", "--", "-D", "warnings"]
    elif args.workspace or args.ui:
        command += ["--workspace"]
    else:
        for package in args.package or (["whohack-respond"] if args.command == "test-build" else ["whohack-service", "whohack-launcher", "whohack-response-helper"]):
            command += ["-p", package]
    if args.command == "test-build":
        command += ["--no-run", "--message-format=json"]
        artifacts = []
        with subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                record = json.loads(line)
                if record.get('reason') == 'compiler-message':
                    rendered = record.get('message', {}).get('rendered')
                    if rendered: print(rendered, end='', file=sys.stderr)
                if record.get('reason') == 'compiler-artifact' and record.get('executable'):
                    path = Path(record['executable'])
                    destination = root / '.vigil/checks/native-tests' / path.name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
                    if record.get('profile', {}).get('test'):
                        artifacts.append({'name': record['target']['name'], 'path': str(destination.relative_to(root))})
            if process.wait(): raise SystemExit(process.returncode)
        report = root / '.vigil/checks/native-tests/artifacts.json'
        report.write_text(json.dumps(artifacts, indent=2) + '\n', encoding='utf-8')
        print(f'Windows test executables: {report}')
    else:
        subprocess.run(command, cwd=root, env=env, check=True)
    if args.stage and args.command == "build":
        profile = "release" if args.release else "debug"
        for name in args.package or (["whohack-tray"] if args.ui else ["whohack-service", "whohack-launcher", "whohack-response-helper"]):
            source = target / f'x86_64-pc-windows-msvc/{profile}/{name}.exe'
            if source.is_file():
                destination = (root / "ui/src-tauri" if args.ui else root) / f'target/{profile}/{name}.exe'
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                print(f"Windows executable ready: {destination}")


if __name__ == "__main__":
    main()
