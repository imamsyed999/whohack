"""Build an unsigned, per-user Windows preview MSI from the verified ZIP.

Build-only requirement: Windows x64 Python 3.11/3.12 (msilib was removed in 3.13).
The installed app requires no Python. This command does not install the package.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = uuid.UUID("a8dbf377-7fa3-4321-af81-39b8f14a477b")
# Stable upgrade/storage identity: existing installs must retain their chosen path.
REGISTRY_ROOT = r"Software\Vigil\Preview"


def guid(name):
    return "{" + str(uuid.uuid5(NAMESPACE, name)).upper() + "}"


def key(prefix, name):
    return prefix + hashlib.sha256(name.encode()).hexdigest()[:28]


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def rows(db, table):
    view = db.OpenView(f"SELECT * FROM `{table}`")
    view.Execute(None)
    result = []
    while (r := view.Fetch()) is not None:
        result.append([r.GetString(i) for i in range(1, r.GetFieldCount() + 1)])
    view.Close()
    return result


def build():
    if sys.platform != "win32" or sys.version_info[:2] not in {(3, 11), (3, 12)}:
        raise SystemExit("Use Windows Python 3.11 or 3.12 for this build-only helper.")
    import msilib as m
    from msilib import schema, sequence
    archive = ROOT / ".vigil/packages/whohack-Windows-Preview.zip"
    archive_sha = digest(archive)
    if archive_sha != archive.with_suffix(".zip.sha256").read_text().split()[0]:
        raise ValueError("preview archive checksum does not match")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    target = archive.with_suffix(".msi")
    with tempfile.TemporaryDirectory(prefix="whohack MSI build ") as directory:
        temp = Path(directory)
        with zipfile.ZipFile(archive) as z:
            if not all((temp / n).resolve().is_relative_to(temp.resolve()) for n in z.namelist()):
                raise ValueError("archive path escapes staging")
            z.extractall(temp)
        source = temp / "whohack-Windows-Preview"
        manifest = json.loads((source / "WHOHACK-PACKAGE.json").read_text())
        for name, sha in manifest.items():
            path = (source / name).resolve(strict=True)
            if not path.is_relative_to(source.resolve()) or digest(path) != sha:
                raise ValueError(f"package integrity failure: {name}")
        files = sorted(manifest) + ["WHOHACK-PACKAGE.json"]
        db = m.init_database(str(temp / "preview.msi"), schema, "whohack Preview", guid("product:" + archive_sha), version, "whohack contributors")
        try:
            summary = db.GetSummaryInformation(3)
            summary.SetProperty(m.PID_TEMPLATE, "x64;1033")
            summary.SetProperty(m.PID_PAGECOUNT, 500)
            summary.SetProperty(m.PID_WORDCOUNT, 10)  # compressed; no elevation required
            summary.Persist()
            del summary
            upgrade = guid("windows-user-preview")
            m.add_data(db, "Property", [
                ("UpgradeCode", upgrade), ("INSTALLLEVEL", "1"), ("ARPNOMODIFY", "1"),
                ("ARPCOMMENTS", "Unsigned native Windows monitoring preview. User data is preserved on removal."),
                ("ARPURLINFOABOUT", "https://github.com/imamsyed999/whohack"),
                ("SecureCustomProperties", "OLDPRODUCTS;NEWERPRODUCTS"),
            ])
            m.add_data(db, "LaunchCondition", [
                ("VersionNT64", "whohack Preview requires 64-bit Windows."),
                ("NOT ALLUSERS", "This preview installs only for the current user."),
                ("NOT NEWERPRODUCTS", "A newer whohack Preview is already installed."),
            ])
            m.add_data(db, "Directory", [
                ("TARGETDIR", None, "SourceDir"), ("LocalAppDataFolder", "TARGETDIR", "."),
                ("ProgramsDir", "LocalAppDataFolder", "Programs"), ("INSTALLDIR", "ProgramsDir", "whohack"),
                ("ProgramMenuFolder", "TARGETDIR", "."), ("MenuDir", "ProgramMenuFolder", "whohack"),
            ])
            directories = {Path("."): "INSTALLDIR"}
            parents = set()
            for name in files:
                parents.update(p for p in Path(name).parents if p != Path("."))
            for index, parent in enumerate(sorted(parents, key=lambda p: (len(p.parts), str(p))), 1):
                logical = key("D", parent.as_posix())
                directories[parent] = logical
                m.add_data(db, "Directory", [(logical, directories[parent.parent], f"D{index}|{parent.name}")])
            m.add_data(db, "Feature", [("Main", None, "whohack", "Native service and tray (monitor mode)", 1, 1, "INSTALLDIR", 0)])
            cabinet = []
            for index, name in enumerate(files, 1):
                path = source / name
                file_key, component, registry = key("F", name), key("C", name), key("R", name)
                directory_id = directories[Path(name).parent]
                m.add_data(db, "Component", [(component, guid("component:" + name), directory_id, 256 | 4, None, registry)])
                m.add_data(db, "FeatureComponents", [("Main", component)])
                m.add_data(db, "Registry", [(registry, 1, REGISTRY_ROOT + r"\Files", file_key, "[#" + file_key + "]", component)])
                m.add_data(db, "File", [(file_key, component, f"F{index}|{path.name}", path.stat().st_size, None, None, 512, index)])
                cabinet.append((str(path), file_key))
            # A HKCU key path anchors the non-advertised per-user shortcuts.
            m.add_data(db, "Component", [("Shortcuts", guid("shortcuts"), "MenuDir", 256 | 4, None, "ShortcutKey")])
            m.add_data(db, "Registry", [("ShortcutKey", 1, REGISTRY_ROOT, "InstallDir", "[INSTALLDIR]", "Shortcuts")])
            m.add_data(db, "RegLocator", [("ExistingInstallDir", 1, REGISTRY_ROOT, "InstallDir", 2 | 16)])
            m.add_data(db, "AppSearch", [("INSTALLDIR", "ExistingInstallDir")])
            m.add_data(db, "FeatureComponents", [("Main", "Shortcuts")])
            m.add_data(db, "Shortcut", [
                ("Startwhohack", "MenuDir", "whohack", "Shortcuts", "[INSTALLDIR]whohack.exe", "start", "Open whohack monitoring", None, None, None, 1, "INSTALLDIR"),
                ("Stopwhohack", "MenuDir", "Stop|Stop whohack", "Shortcuts", "[INSTALLDIR]whohack.exe", "stop", "Stop this whohack preview", None, None, None, 1, "INSTALLDIR"),
            ])
            m.add_data(db, "RemoveFile", [("RemoveMenu", "Shortcuts", None, "MenuDir", 2)])
            m.add_data(db, "Upgrade", [
                (upgrade, None, version, None, 512, None, "OLDPRODUCTS"),
                (upgrade, version, None, None, 2, None, "NEWERPRODUCTS"),
            ])
            # Embedded native launcher, synchronous return checking, current user. Stop only
            # its marker-owned session; no SCM/firewall/elevation custom actions.
            m.add_data(db, "Binary", [("StopLauncher", m.Binary(str(source / "whohack.exe")))])
            m.add_data(db, "CustomAction", [("Stopwhohack", 2, "StopLauncher", 'stop --root "[INSTALLDIR]."')])
            for table in sequence.tables:
                actions = [row for row in getattr(sequence, table) if row[0] != "RemoveExistingProducts"]
                # FindRelatedProducts must precede the downgrade launch condition.
                actions = [(a, c, 300 if a == "LaunchConditions" else n) for a, c, n in actions]
                if table == "InstallExecuteSequence":
                    actions += [("Stopwhohack", 'Installed AND REMOVE="ALL"', 1390), ("RemoveExistingProducts", "OLDPRODUCTS", 1510)]
                m.add_data(db, table, actions)
            cabinet_path = temp / "payload.cab"
            m.FCICreate(str(cabinet_path), cabinet)
            extracted = temp / "verified-cabinet"
            extracted.mkdir()
            subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/expand.exe"), "-F:*", str(cabinet_path), str(extracted)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
            for name in files:
                assert digest(extracted / key("F", name)) == digest(source / name), "MSI cabinet payload differs from verified archive"
            m.add_data(db, "Media", [(1, len(files), None, "#payload.cab", None, None)])
            m.add_stream(db, "payload.cab", str(cabinet_path))
            db.Commit()
            assert len(rows(db, "File")) == len(files)
            assert all(not name.startswith(".vigil/") for name in files), "private runtime data must not be packaged"
            assert all(row[1] == "1" for row in rows(db, "Registry")), "registry writes must stay under HKCU"
            assert not rows(db, "ServiceInstall") and not rows(db, "ServiceControl")
            assert dict(rows(db, "Property")).get("ALLUSERS") is None
        finally:
            db.Close()
        (temp / "preview.msi").replace(target)
    target.with_suffix(".msi.sha256").write_text(f"{digest(target)}  {target.name}\n", encoding="ascii")
    print(f"Built unsigned per-user MSI: {target}")
    print("Database/payload checks passed. Clean-machine install, upgrade and uninstall acceptance is still required.")


if __name__ == "__main__":
    build()
