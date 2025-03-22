# TCP服务器.spec
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('plugins/*.py', 'plugins'),
        ('plugins/proto/*.py', 'plugins/proto'),
        ('plugins/proto/*.proto', 'plugins/proto')
    ],
    hiddenimports=[
        'cryptography',
        'tkinter',
        'PIL',
        'google.protobuf',
        'google.protobuf.descriptor',
        'plugins.proto.message_pb2',
        'plugins.base',
        'plugins.default_protobuf'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TCP服务器',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None
    # Removed icon parameter icon='icon.ico'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='TCP服务器'
)