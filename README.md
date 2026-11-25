# Update Detective

**Know what changed after a software update.**

A local-first, read-only Windows executable integrity investigator built in C# with .NET 8 and Windows Forms.

[Releases](https://github.com/techsupport993-creator/UpdateDetective/releases) · [Report an issue](https://github.com/techsupport993-creator/UpdateDetective/issues)

## Build on Windows 10/11 x64
1. Install the .NET 8 SDK: `winget install Microsoft.DotNet.SDK.8`
2. Extract the ZIP. Double-click `Build_EXE.bat`.
3. Run `Release\UpdateDetective.exe`. This framework-dependent build requires the .NET 8 Desktop Runtime on the destination PC (included with the Windows .NET 8 SDK). Keep all Release files together. Install the runtime if necessary: `winget install Microsoft.DotNet.DesktopRuntime.8`.

## Changes in 1.1.0
- Disabled single-file publishing, trimming and related analyzers to avoid the ILLink package requirement that caused NU1100.
- Build retries using the official NuGet source if the first attempt fails, without modifying global NuGet settings. Internet access may be needed for the retry.
- All existing monitoring features and baseline storage are unchanged.

## Use
- Add executable: select one or more EXE files. This saves a baseline.
- Discover apps: select applications whose uninstall registry DisplayIcon points to an existing EXE. Discovery is deliberately limited; add missing programs manually.
- Scan all: compare the same paths against their baseline. Changes remain visible until you explicitly accept a new baseline. Missing or inaccessible files invalidate the latest observation, not the baseline.
- Select a row to see file version, product version, company metadata, SHA-256, size, timestamps, certificate information and offline WinVerifyTrust result.
- Optional five-minute checks run only while the application is open.
- Export JSON saves evidence locally. Reports can contain private file paths; review before sharing.

## Privacy and limits
Snapshots are stored in `%LOCALAPPDATA%\UpdateDetective\snapshots.json`. No telemetry, uploads, firewall changes, administrator requirement, or automatic repair. Baselines are local observations, not known-good reference files. A changed hash can be a legitimate update or other modification; an unchanged hash does not establish safety. Offline signature verification does not check revocation; catalog-signed files may not be recognized. Certificate metadata is not independently proof of trust. Tracks selected executable files, not entire packages, DLLs or behavior. Does not follow executables moved to new paths. Accepting a baseline replaces prior evidence; export first if needed. No background Windows service in V1.1.0.

## Smoke test
Add an EXE and scan it unchanged. For a changed binary test, copy two different harmless executables into a temporary test folder, name the first `test.exe`, baseline it, then replace the temporary file with the second one and scan. Verify SHA-256 and change status, export JSON, close/reopen, and check persistence. Delete the temporary files afterward. Do not replace real installed application files.

## Build verification
Source provided; Windows compilation and runtime testing have not been performed in the creation environment. The executable is not code-signed.

## Roadmap
- V1.2.0: investigation history, explicit unavailable-file status and improved dashboard.
- Future: service, registry and network behavior comparisons.
