# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/).

Releases up to 1.3.1 are listed in the README's Version History and on the
[GitHub releases page](https://github.com/darthrater78/smb-diag/releases).

## [Unreleased]

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
