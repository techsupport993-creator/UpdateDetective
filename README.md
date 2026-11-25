# Update Detective 1.3.0

**Know what changed after a software update.**

Local-first Windows software integrity investigation. C# / .NET 8 / Windows Forms.

[Downloads](https://github.com/techsupport993-creator/UpdateDetective/releases) · [Report an issue](https://github.com/techsupport993-creator/UpdateDetective/issues)

## Features
- Executable baselines, SHA-256 comparison, version and offline Authenticode verification.
- Investigation history and JSON exports.
- Installation folder monitoring: recursive file hashes, added/modified/deleted files and timestamp-only changes.
- Automatic folder scans every five minutes while the application is open (can be disabled).
- Simple and Advanced modes, persisted locally.
- Optional startup update checks against GitHub releases, disabled by default; manual checks and official release link.
- Dark tabbed dashboard and custom application icon.

## Download
Choose the standalone Windows x64 EXE in Releases. No separate .NET runtime is required for that asset. Alternatively, extract the entire framework-dependent ZIP and install the .NET 8 Desktop Runtime. Compare the EXE or ZIP SHA-256 using the provided checksum file. Builds are unsigned.

## Get started
1. In Executables, add a file or discover installed applications; scan to compare it against its baseline.
2. In Installations, choose an application folder, capture a baseline, then scan after updating. Select a folder to inspect changes. Use the filter to view additions, modifications or deletions.
3. In Settings, enable Advanced mode for full hashes and certificate evidence. Enable startup update checks only if desired.
4. Export evidence before accepting a new baseline; accepting replaces the previous baseline.

## Privacy and limitations
Data stays in %LOCALAPPDATA%\UpdateDetective (snapshots.json, folders.json, history.jsonl, settings-v13.json). Reports may contain private paths; review before sharing. No telemetry, automatic repairs or software installation. Optional update checks request the public GitHub releases endpoint and send no diagnostics. GitHub sees normal request metadata such as IP address.
Folder scans hash ordinary files recursively, exclude reparse points and reject incomplete scans; a 50,000-entry cap limits accidental broad scans. Scans are not atomic and can be slow. No scans run after closing the program. File changes alone do not establish that an update occurred or that malware is present. Executable signature verification is offline without revocation checks; catalog-signed files may not be recognized.
History is local and can grow until manually removed. Existing V1.1/V1.2 executable baselines are supported.

## Build from source
Install the .NET 8 SDK on Windows and run Build_EXE.bat. The icon is generated from the checked-in base64 source. The batch build creates a framework-dependent Release directory. GitHub Actions publishes the standalone self-contained executable separately.

## Smoke test
Use a temporary test folder (never modify real application files). Add a baseline containing two harmless text files, then modify one, delete the other and add a third. Scan and confirm all three results; restart and confirm persistence. Check Simple/Advanced mode, export, and update checker. Verify old executable baselines and history. Runtime validation pending.

## License
GPL-3.0. See LICENSE.
