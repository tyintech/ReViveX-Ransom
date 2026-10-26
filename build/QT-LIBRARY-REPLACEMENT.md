# Qt library source and replacement / Qt 库源码与替换

ReViveX Ransom uses Qt / PySide6 Essentials / Shiboken6 6.12.0 under the
GNU Lesser General Public License version 3. Original copyright notices,
LGPL/GPL texts and bundled third-party notices are supplied in
`third-party-licenses/Qt`. The application is AGPL-3.0-or-later.

The libraries are dynamically loaded from the portable directory or the
per-user installation directory. There is no signature lock, activation,
DRM, integrity check or license term preventing modification, replacement,
relinking or reverse engineering for debugging modifications to these libraries.
The installer does not make system-wide Qt registrations.

## Replace libraries

1. Close the app and all recovery jobs. Copy the entire application directory
   to a separate writable folder before experimenting; keep evidence elsewhere.
2. Use ABI-compatible x64 release builds of the relevant Qt 6.12 libraries and
   PySide6/Shiboken bindings, or rebuild the application from source against
   your modified versions. Preserve the original directory layout.
3. In the PyInstaller layout, Qt DLLs and plugins are normally beneath
   `_internal/PySide6/`; Shiboken and binding extension DLLs are also beneath
   `_internal/`. Locate the actual files by name if a packaging version changes.
   Replace matching DLLs, `.pyd` bindings and affected plugins together; keep
   architecture, compiler runtime and ABI consistent.
4. Run `ReViveX-Ransom.exe --self-test`, then test with synthetic samples.
   Back up and restore the original application folder if needed. No product
   key, signing certificate, special password or vendor permission is required.
5. To rebuild the whole application, extract `application-source.zip` from
   `corresponding-source.zip` and follow `build/README.md`. Qt and PySide sources,
   their build scripts, license files and upstream instructions are inside
   `dependency-sources/qt/`. Replace the pinned library installations with your
   rebuilt versions and update the local dependency/source manifest accordingly.

Official build documentation:
- https://doc.qt.io/qt-6/build-sources.html
- https://doc.qt.io/qtforpython-6/building_from_source/index.html

## 中文说明

Qt / PySide6 Essentials / Shiboken6 6.12.0 按 LGPLv3 使用；完整许可证及第三方声明位于
`third-party-licenses/Qt`。相同版本的库源码与构建脚本随发布页的
`corresponding-source.zip` 一起提供，位于 `dependency-sources/qt/`。

库为动态加载，可在关闭程序后替换。先复制整个程序目录，在副本中用 ABI、架构及编译器
运行时兼容的库替换 `_internal` 下对应 DLL、`.pyd` 和插件，然后运行
`ReViveX-Ransom.exe --self-test`，再用合成样本测试。也可按构建说明使用修改后的库
重新编译整个应用。没有阻止替换的签名锁、激活或完整性检查，亦不限制 LGPL 所允许的
修改、重新链接及为调试修改而进行的逆向工程。请勿在操作库时接触原始证据文件。
