# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['sys19.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'win32evtlog',
        'win32event',
        'win32api',
        'xml.etree.ElementTree',
        'requests',
        'watchdog.observers.winapi'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='Sysmonlog',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # This hides the console window
    icon='icon.ico' if os.path.exists('icon.ico') else None,
)