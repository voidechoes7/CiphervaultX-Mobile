#!/usr/bin/env python3
"""Patch the Tauri-generated Android project before building the APK:
1. Bump versionCode / versionName in build.gradle.kts for seamless in-place upgrades.
2. Add READ/WRITE/MANAGE_EXTERNAL_STORAGE permissions, requestLegacyExternalStorage,
   and largeHeap (for Argon2id RAM headroom) in AndroidManifest.xml.
3. Enhance MainActivity.kt with AndroidStorageBridge (@JavascriptInterface) so the
   WebView can check & open Android's 'All files access' settings screen and auto-refresh
   on resume.
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
    return "0.2.1"


def patch_gradle() -> None:
    gradle = "src-tauri/gen/android/app/build.gradle.kts"
    if not os.path.exists(gradle):
        print(f"WARNING: {gradle} not found")
        return
    version = read_app_version()
    txt = open(gradle, encoding="utf-8").read()
    vcode = 20000 + int(os.environ.get("RUN_NUMBER", "1"))
    txt = re.sub(r"versionCode\s*=\s*[^\n]+", f"versionCode = {vcode}", txt)
    txt = re.sub(r"versionName\s*=\s*[^\n]+", f'versionName = "{version}"', txt)
    open(gradle, "w", encoding="utf-8").write(txt)
    print(f"Patched Android versionCode={vcode}, versionName={version}")


def patch_manifest() -> None:
    manifest = "src-tauri/gen/android/app/src/main/AndroidManifest.xml"
    if not os.path.exists(manifest):
        print(f"WARNING: {manifest} not found")
        return
    txt = open(manifest, encoding="utf-8").read()

    permissions = [
        '<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" android:maxSdkVersion="32" />',
        '<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="32" />',
        '<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />',
    ]
    missing = [p for p in permissions if p.split('"')[1] not in txt]
    if missing:
        block = "\n    ".join(missing)
        txt = txt.replace("<application", f"    {block}\n\n    <application", 1)

    if 'android:requestLegacyExternalStorage=' not in txt:
        txt = txt.replace(
            "<application",
            '<application\n        android:requestLegacyExternalStorage="true"',
            1,
        )
    if 'android:largeHeap=' not in txt:
        txt = txt.replace(
            "<application",
            '<application\n        android:largeHeap="true"',
            1,
        )

    open(manifest, "w", encoding="utf-8").write(txt)
    print("Patched AndroidManifest.xml with storage permissions and largeHeap=true")


def patch_main_activity() -> None:
    matches = glob.glob("src-tauri/gen/android/app/src/main/java/**/MainActivity.kt", recursive=True)
    if not matches:
        print("ERROR: MainActivity.kt not found under src-tauri/gen/android", file=sys.stderr)
        sys.exit(1)

    activity_path = matches[0]
    original = open(activity_path, encoding="utf-8").read()
    pkg_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", original, re.MULTILINE)
    package_name = pkg_match.group(1) if pkg_match else "io.ciphervaultx.fortress"

    kotlin_src = f"""package {package_name}

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {{
  private var attachedWebView: WebView? = null

  override fun onWebViewCreate(webView: WebView) {{
    super.onWebViewCreate(webView)
    attachedWebView = webView
    webView.addJavascriptInterface(AndroidStorageBridge(), "AndroidStorageBridge")
  }}

  override fun onResume() {{
    super.onResume()
    attachedWebView?.post {{
      attachedWebView?.evaluateJavascript(
        "window.dispatchEvent(new CustomEvent('android-storage-resumed'));",
        null
      )
    }}
  }}

  inner class AndroidStorageBridge {{
    @JavascriptInterface
    fun hasAllFilesAccess(): Boolean {{
      return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {{
        Environment.isExternalStorageManager()
      }} else {{
        val read = ContextCompat.checkSelfPermission(
          this@MainActivity,
          Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
        val write = ContextCompat.checkSelfPermission(
          this@MainActivity,
          Manifest.permission.WRITE_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
        read && write
      }}
    }}

    @JavascriptInterface
    fun requestAllFilesAccess(): Boolean {{
      runOnUiThread {{
        try {{
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {{
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {{
              data = Uri.parse("package:$packageName")
            }}
            try {{
              startActivity(intent)
            }} catch (_: Exception) {{
              startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
            }}
          }} else {{
            ActivityCompat.requestPermissions(
              this@MainActivity,
              arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
              ),
              1001
            )
          }}
        }} catch (_: Exception) {{
          // Settings activity unavailable on this device
        }}
      }}
      return true
    }}

    @JavascriptInterface
    fun getExternalStorageRoot(): String {{
      return try {{
        Environment.getExternalStorageDirectory().absolutePath
      }} catch (_: Exception) {{
        "/storage/emulated/0"
      }}
    }}
  }}
}}
"""
    open(activity_path, "w", encoding="utf-8").write(kotlin_src)
    print(f"Patched {activity_path} (package={package_name}) with AndroidStorageBridge")


def main() -> None:
    patch_gradle()
    patch_manifest()
    patch_main_activity()


if __name__ == "__main__":
    main()
