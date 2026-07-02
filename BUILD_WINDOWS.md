# Building the ThreatOne Windows GUI

ThreatOne can be built in two modes:

- **Console mode** (`-DENABLE_QT=OFF`, the default): a headless console executable
  used for CI smoke tests and on Linux. No Qt required.
- **GUI mode** (`-DENABLE_QT=ON`): the full Qt6 Quick desktop application with a
  visible window.

## Prerequisites for the GUI build

1. **Visual Studio 2022** (or the Build Tools) with the C++ workload, so MSVC and
   the Windows SDK / RC compiler are available.
2. **Qt 6.8.1** for MSVC 2022 64-bit (`win64_msvc2022_64`). Install it with the Qt
   online installer or with [`aqtinstall`](https://github.com/miurahr/aqtinstall),
   including these modules:
   - `qtbase` (Core, Gui, Widgets, Network, Sql) — included by default
   - `qtdeclarative` (Quick, Qml) — included by default
   - `qtcharts`
   - `qtquick3d`
   - `qtwebsockets`
   - `qtshadertools`
3. **CMake 3.22+** and **Ninja**.

## Building locally

From a *Developer Command Prompt / PowerShell for VS 2022* (so MSVC is on PATH),
with `<QtRoot>` pointing at your Qt install (e.g. `C:\Qt\6.8.1\msvc2022_64`):

```powershell
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DENABLE_QT=ON `
      -DCMAKE_PREFIX_PATH="C:\Qt\6.8.1\msvc2022_64"
cmake --build build
```

The GUI executable is produced at `build\bin\threatone.exe`.

## Bundling the Qt runtime (windeployqt)

`threatone.exe` needs the Qt DLLs and QML plugins next to it to run outside a Qt
developer environment. Use `windeployqt` to copy them into a distributable folder:

```powershell
mkdir dist\ThreatOne
copy build\bin\threatone.exe dist\ThreatOne\
& "C:\Qt\6.8.1\msvc2022_64\bin\windeployqt.exe" `
    --qmldir .\qml --release --no-translations dist\ThreatOne\threatone.exe
```

`dist\ThreatOne` is then a self-contained folder you can zip and run anywhere.
This is exactly what the GitHub Actions Windows job does, publishing the result as
the `threatone-windows-gui` artifact.

## Executable file properties (version metadata)

The version information shown on the **Details** tab of the executable's Windows
properties comes from `src/app/resources/threatone.rc`, which is compiled into the
binary automatically on `WIN32` builds. Update the `VERSIONINFO` block there to
change the company name, description, version, or copyright.

## Adding a custom application icon

By default no icon is embedded (so the resource always compiles even without an
icon asset). To add one:

1. Create a valid binary Windows icon file named `threatone.ico` and place it at
   `src/app/resources/threatone.ico`. (Use a tool such as ImageMagick,
   `magick convert logo.png threatone.ico`, or an online PNG-to-ICO converter.)
2. In `src/app/resources/threatone.rc`, uncomment the icon line:

   ```rc
   IDI_ICON1 ICON "threatone.ico"
   ```

3. Rebuild. Windows Explorer will now show your icon for `threatone.exe`.
