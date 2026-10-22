# Security scan — 2026-10-23

Read the generated [security report](report.md), with the metadata corrections below. This PR records findings and proposed remediation; it does not apply fixes.

- Reviewed revision: `a1fa3ca1529eb361e777c397dee437c7e1e6a046`.
- Scan ID: `2c7c7084-978d-4241-b23d-b28670a7edb9`.
- Result: **7 validated findings: 5 medium, 2 low**.
- All 33 tracked current files were reviewed offline. Overall coverage remains **partial** because the external `Shell.pm` execution boundary is unresolved. Suspected command execution is deferred, not a confirmed finding.
- Validation used static source tracing. Application code, tests, exploit inputs, live devices and network targets were not executed. The existing test only checks module loading.
- Independent baseline and architecture review plus a focused investigation completed within four runtime slots. No deployment-specific exposure was assumed.

## Metadata corrections

The sealed generated report and canonical JSON are retained byte-for-byte. Two metadata issues were found during packaging:

1. The generated `Artifacts reviewed` field accidentally includes two command-output truncation notices and omits `lib/Net/UPnP/Service.pm` and `t/UPnP.t`. Those notices are not source files. Both omitted paths were reviewed; [reviewed-paths.txt](reviewed-paths.txt) is the corrected complete 33-file inventory, captured separately from `git ls-files` before adding these audit documents. This correction does not change the findings or their evidence.
2. The scope limitation says token measurement was unavailable while the draft was written. Completion subsequently returned measured usage: **5,594,483 total tokens**, including **5,320,320 cached input tokens** (5,565,104 input and 29,379 output; source `codex_rollout`, measurement coverage `complete`). This is the tool's accounting, including cache reads, not an estimate of newly generated text.

## Files

- [report.md](report.md): deterministic generated report, evidence, severity, remediation and follow-up.
- [threatmodel.md](threatmodel.md): generated architecture and trust boundaries.
- [findings.json](findings.json): sealed canonical validated findings.
- [coverage.json](coverage.json): reviewed, rejected and deferred surfaces, including unresolved Shell behavior.
- [scan-manifest.json](scan-manifest.json): sealed scan identity, source revision and original artifact digests.
- [reviewed-paths.txt](reviewed-paths.txt): corrected repository source inventory.

The canonical exports retain original local provenance paths. Those identify the original workstation, not portable filesystem locations; repository-relative source locations identify the reviewed code. Artifact digests describe the original sealed files; this README and inventory are packaging addenda, not modifications to that sealed scan.

The next verification target is the exact installed `Shell.pm` implementation used by `examples/dms2vodcast.pl:294-306`. Inspect its argument and interpreter behavior before asserting command execution. No patch or dependency installation is included here.
