#!/usr/bin/env python3
"""Patch the Tauri-generated iOS project before building the unsigned IPA:
1. Disable code signing for CI unsigned IPA output and sync MARKETING_VERSION.
2. Enable UIFileSharingEnabled & LSSupportsOpeningDocumentsInPlace in Info.plist
   so iOS Files app / iCloud Drive integration works smoothly.
3. Patch tauri-plugin-dialog's iOS DialogPlugin.swift (if present in Cargo cache)
   to pass `asCopy: true` to UIDocumentPickerViewController so iCloud / File Provider
   files (.zip, .7z, etc.) are copied into readable local storage and never yield 0 KB.
"""

import glob
import json
import os
import re
import sys


def read_app_version() -> str:
    conf = "src-tauri/tauri.conf.json"
    if os.path.exists(conf):
        data = json.load(open(conf, encoding="utf-8"))
        if isinstance(data.get("version"), str) and data["version"].strip():
            return data["version"].strip()
    return "0.3.0"


def patch_pbxproj() -> None:
    matches = glob.glob("src-tauri/gen/apple/**/project.pbxproj", recursive=True)
    if not matches:
        print("ERROR: project.pbxproj not found under src-tauri/gen/apple", file=sys.stderr)
        sys.exit(1)
    pbx = matches[0]
    version = read_app_version()
    txt = open(pbx, encoding="utf-8").read()
    if "CODE_SIGNING_ALLOWED = NO;" not in txt:
        txt = txt.replace(
            "buildSettings = {",
            'buildSettings = {\n\t\t\t\tCODE_SIGNING_ALLOWED = NO;\n\t\t\t\tCODE_SIGNING_REQUIRED = NO;\n\t\t\t\tCODE_SIGN_IDENTITY = "";',
        )
    txt = re.sub(r"MARKETING_VERSION\s*=\s*[^;]+;", f"MARKETING_VERSION = {version};", txt)
    open(pbx, "w", encoding="utf-8").write(txt)
    print(f"Patched {pbx} (unsigned build + MARKETING_VERSION={version})")


def patch_info_plist() -> None:
    plists = glob.glob("src-tauri/gen/apple/**/Info.plist", recursive=True)
    for plist in plists:
        txt = open(plist, encoding="utf-8").read()
        additions = []
        if "UIFileSharingEnabled" not in txt:
            additions.append("\t<key>UIFileSharingEnabled</key>\n\t<true/>")
        if "LSSupportsOpeningDocumentsInPlace" not in txt:
            additions.append("\t<key>LSSupportsOpeningDocumentsInPlace</key>\n\t<true/>")
        if additions and "</dict>" in txt:
            block = "\n".join(additions) + "\n</dict>"
            idx = txt.rfind("</dict>")
            txt = txt[:idx] + block + txt[idx + len("</dict>") :]
            open(plist, "w", encoding="utf-8").write(txt)
            print(f"Patched {plist} with UIFileSharingEnabled & LSSupportsOpeningDocumentsInPlace")


def patch_ios_dialog_as_copy() -> None:
    cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
    candidates = glob.glob(
        os.path.join(cargo_home, "registry/src/**/tauri-plugin-dialog-*/ios/Sources/**/*.swift"),
        recursive=True,
    )
    patched = 0
    for swift_path in candidates:
        txt = open(swift_path, encoding="utf-8").read()
        if "UIDocumentPickerViewController" not in txt:
            continue
        # Ensure forOpeningContentTypes uses asCopy: true so iCloud / File Provider
        # archives (.zip, .7z) are materialized cleanly instead of 0-byte placeholders.
        updated = re.sub(
            r"UIDocumentPickerViewController\(\s*forOpeningContentTypes:\s*([^,\)]+)\s*\)",
            r"UIDocumentPickerViewController(forOpeningContentTypes: \1, asCopy: true)",
            txt,
        )
        updated = re.sub(
            r"UIDocumentPickerViewController\(\s*forOpeningContentTypes:\s*([^,\)]+),\s*asCopy:\s*false\s*\)",
            r"UIDocumentPickerViewController(forOpeningContentTypes: \1, asCopy: true)",
            updated,
        )
        if updated != txt:
            open(swift_path, "w", encoding="utf-8").write(updated)
            patched += 1
            print(f"Patched {swift_path} to use UIDocumentPickerViewController(..., asCopy: true)")
    if patched == 0:
        print("Info: DialogPlugin.swift already uses asCopy: true or not cached yet (tauri-plugin-fs fallback active).")


def main() -> None:
    patch_pbxproj()
    patch_info_plist()
    patch_ios_dialog_as_copy()


if __name__ == "__main__":
    main()
