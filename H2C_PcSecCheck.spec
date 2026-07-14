# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['H2C_PcSecCheck.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['openpyxl', 'zipfile', 'hashlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# onefile：產出單一 exe，方便帶到客戶端當場執行。
# version=version.txt 補上發行者/版本 metadata；upx=False 不打包（打包會提高誤判）。
# 注意：真正能讓 AV/ML 不誤判的是「程式碼簽章 + 普及度」，這裡只是把該做的衛生做好。
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='H2C_PcSecCheck',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    uac_admin=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version.txt',
)
