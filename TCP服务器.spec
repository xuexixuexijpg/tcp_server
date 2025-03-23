# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['./app/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        # 工具插件目录
        ('tools/tcp_server/plugins/*.py', 'tools/tcp_server/plugins'),
        ('tools/tcp_server/plugins/proto/*.py', 'tools/tcp_server/plugins/proto'),
        ('tools/tcp_server/plugins/proto/*.proto', 'tools/tcp_server/plugins/proto'),

        # 资源文件
        ('resources/images/icons/*.png', 'resources/images/icons'),
#        ('resources/images/icons/*.ico', 'resources/images/icons'),
#        ('resources/styles/*.css', 'resources/styles'),

        # 其他工具资源
#        ('tools/*/resources/*', 'tools/*/resources')
    ],
    hiddenimports=[
        # 基础依赖
        'cryptography',
        'tkinter',
        'PIL',
        'customtkinter',

        # protobuf相关
        'google.protobuf',
        'google.protobuf.descriptor',

        # TCP服务器工具
        'tools.tcp_server.plugins.proto.message_pb2',
        'tools.tcp_server.plugins.base',
        'tools.tcp_server.plugins.default_protobuf',

        # GUI组件
        'gui.main_window',
        'gui.widgets.tool_card',
        'gui.widgets.navigation',
        'gui.styles.colors',
        'gui.styles.themes'
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
    name='工具集',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='resources/images/icons/app.png'  # 更新图标路径
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='工具集'
)