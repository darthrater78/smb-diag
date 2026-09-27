# README screenshots

`run.sh` regenerates `docs/screenshots/*.png` from mock data (the `contoso.com` domain), so the README never shows a real environment.

It builds a harness from the app's own `MainForm.cs` plus `Shots.cs`, which is a separate entry point. `Shots.cs` injects mock results for both scenarios as run history, then captures the Results tab for each and the Kerberos Tickets tab. The shipped app is unchanged. The Kerberos Tickets tab runs the app's own refresh against stand-in `klist.exe` and `dsregcmd.exe` (`faketool.c`, listed in `fake-tools.txt`), which print the mock output `Shots.cs` writes. Both exist only inside the throwaway Wine prefix. The harness runs under Wine on a virtual X display, so it works on a Linux machine with no Windows.

```
tools/screenshots/run.sh
```

Requires: .NET 8 SDK, `wine`, `xvfb-run`, `python3` (with `venv`), `curl`, `unzip`, DejaVu Sans (`fonts-dejavu-core`) and MinGW (`gcc-mingw-w64-x86-64`). The script downloads pinned, checksum-verified copies of Cascadia Code and Selawik, and installs `fonttools` and `pillow` into a private venv. Its working files (Wine prefix, fonts, build) go in `~/.cache/winforms-screenshots`; set `SHOTS_WORK` to use another folder.

Change the mock data in `Shots.cs` (`MockAd`, `MockEntra`, `MockDsregcmd`, `MockKlist`). The harness reaches the form's private fields and methods by name, so renaming one of those in `MainForm.cs` makes the run fail with the missing name.

## How it differs from real Windows

- **Fonts:** Segoe UI isn't redistributable, so Selawik (Microsoft's open-source metric-compatible stand-in) takes its place. Cascadia Code is the real font.
- **Controls:** scrollbars and text box borders use Wine's classic style, and the Kerberos Tickets tab can show a horizontal scrollbar that Windows doesn't.

`prep.py` works around two Wine font issues: GDI+ doesn't find Cascadia Code by name, and the rich text control doesn't fall back to another font for glyphs Selawik lacks (`●`, `═`). See the comment at the top of that file.
