# -*- mode: python ; coding: utf-8 -*-
# FireWall Migrator Pro — PyInstaller spec

import os

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('fw_migrator/ui.html', 'fw_migrator'),
    ],
    hiddenimports=[
        'flask',
        'flask_cors',
        'paramiko',
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'bcrypt',
        'nacl',
        'nacl.bindings',
        'werkzeug',
        'werkzeug.serving',
        'werkzeug.routing',
        'jinja2',
        'click',
        'itsdangerous',
        'fw_migrator.fortigate_connector',
        'fw_migrator.checkpoint_connector',
        'fw_migrator.fortigate_parser',
        'fw_migrator.checkpoint_parser',
        'fw_migrator.checkpoint_to_forti',
        'fw_migrator.forti_to_forti',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy', 'PIL'],
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
    name='FirewallMigratorPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # Set False for windowless (hides CMD window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='fw_migrator/icon.ico',  # uncomment if you add an icon
)
