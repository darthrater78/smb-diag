# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/).

Releases up to 1.3.1 are listed in the README's Version History and on the
[GitHub releases page](https://github.com/darthrater78/smb-diag/releases).

## [1.4.0] - 2026-10-05

### Added
- Optional logging, off by default and kept in memory only. The **Log** link in the
  header switches between Off, On (runs, results, timeouts and errors) and Debug
  (also every tool's command line and raw output, DNS lookups and port probes).
  **Save log...** writes it to a file you choose; nothing is written otherwise.
- Unit tests for the process runner and the log, run in CI.
- Release builds carry a signed build provenance attestation; check a download with
  `gh attestation verify smb-diag.exe --repo darthrater78/smb-diag`.
- Pull requests are checked for newly added packages or actions with known
  High or Critical advisories.

### Fixed
- The app could stay running with no window after it was closed, when a test was
  still waiting on Windows for an unreachable server or domain controller. It now
  ends at once on close.
- Tools still running when the app closed (`net use`, `nslookup`, `w32tm`, …) were
  left behind. Every tool now runs in a job that Windows empties when the app exits,
  including after a crash.
- DNS lookups and the SSPI negotiation had no time limit, so a run could sit on
  "running..." for as long as Windows chose. They now give up after 8 and 20 seconds.
- A tool that left a child process holding its output could hang a test forever.
- A tool that asked for input (`net use` prompting for a user name) waited for its
  whole timeout; it now gets end-of-file immediately.
- When a tool wrote its error to stderr only, the result showed an empty message.

### Changed
- A tool that times out now reports the timeout instead of being parsed as if its
  partial output were complete.
- Closing the window during a run cancels it: running tools are stopped and no more
  are started.
- Minimum window width is 660 px (was 600), to fit the Log link.
- CI builds every branch push, runs the tests, and skips the build for docs-only
  changes.

## [1.3.2] - 2026-09-27

### Security
- System tools (`klist`, `net`, `nslookup`, `powershell`, …) are now launched by
  their full System32 path, so a same-named exe placed next to `smb-diag.exe` or
  in the current directory can no longer run in their place.
- `secur32.dll` is loaded only from System32.
- Hostname validation now enforces DNS label rules (no leading/trailing `-`, no
  empty labels such as `..`).

### Changed
- Failures to load, save or delete the settings file are now reported instead of
  being silently ignored.

### Added
- GitHub Actions: CI build on every PR and push to `main`, a tag-triggered
  release workflow that attaches `smb-diag.exe`, workflow linting, and
  Dependabot for actions and NuGet.
