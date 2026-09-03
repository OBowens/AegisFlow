# PyInstaller spec for aegis-agent.exe -- build on Windows:
#
#     cd endpoint_agent
#     python -m venv build-venv && build-venv\Scripts\activate
#     pip install pyinstaller pywin32==306
#     pyinstaller --clean --noconfirm packaging/aegis-agent.spec
#
# Output: dist\aegis-agent.exe (one file, console). The Inno Setup
# script (packaging/installer.iss) expects it at that path.

# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

# pywin32 pieces the agent uses that PyInstaller's static analysis can
# miss (imported lazily / via pywin32's own machinery).
hiddenimports = [
    "win32timezone",
    "win32evtlog",
    "win32evtlogutil",
    "win32service",
    "win32serviceutil",
    "servicemanager",
    "win32event",
    "win32api",
    "pywintypes",
    "pythoncom",
]

a = Analysis(
    ["entry.py"],
    pathex=[os.path.abspath(os.path.join("packaging", ".."))],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "test", "unittest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="aegis-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
