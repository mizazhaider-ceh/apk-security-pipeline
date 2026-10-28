# Deep test report: APK Security Pipeline v0.1.0

Date: 2026-10-28. Method: unit tests plus manual CLI checks, same style
as the AgentArsenal test rounds (happy path, edge cases, failure paths,
leak checks, determinism, performance).

## Results

- Total tests: 38, all passing (8 original + 30 deep).
- Original suite (tests/test_pipeline.py): 8 tests.
- Deep suite (tests/test_deep.py): 30 tests.
- Frida scripts: all 4 pass `node --check` syntax validation.
- Performance: a 200 file APK (about 1 MB of filler) scans in 0.15 seconds.
- Determinism: two runs on the same input produce byte identical JSON reports.
- Demo scores, re-verified: clean sample 100/100 grade A, 0 findings;
  vulnerable sample 0/100 grade F, 24 findings (1 critical, 8 high,
  7 medium, 8 low); dynamic log demo adds exactly 2 dynamic findings.

## Deep test coverage

- Manifest variants (7): exported component with permission is not
  flagged; implicit export via intent filter is flagged; all four
  component kinds parse; plain XML inside an APK zip parses; bad magic,
  truncated binary, and empty manifests all fail with a clean error.
- Input handling (6): missing file, non zip file, zip without manifest,
  directory without manifest all fail cleanly; decoded directory input
  and single manifest file input both scan correctly.
- Scoring and masking (4): score math (1 critical + 1 high + 1 medium +
  1 low + 1 info = 50, grade D); score floor at 0; secret and URL
  masking; namespace URLs are not flagged as cleartext.
- Custom rules and baseline (4): custom pattern found; bad regex in a
  custom rule does not crash; missing baseline file is a clean error
  (fixed this round, see below); baseline detects fixed findings.
- Reports and CLI (7): report HTML escapes markup in component names
  (no script injection through a crafted name); report formats
  html/json/both write only the requested files; fail-on thresholds
  behave (critical fails, never passes, clean passes low); missing
  input, missing rules file, and missing dynamic log all exit 1 with a
  plain error, never a traceback.
- Dynamic log (2): bad JSON lines are skipped; unknown severity
  defaults to low; empty log gives zero findings.

## Defects found and fixed this round

- D1 (fixed): missing baseline file raised a raw FileNotFoundError
  traceback instead of a clean scan error. Fixed in scanner.py:
  baseline loading now raises ScanError, CLI exits 1 with a plain message.

## Defects fixed in earlier rounds (re-verified here)

- Namespace URL false positive: the Android namespace URI was flagged
  as a cleartext URL. Fixed: namespace URIs are skipped for URL rules.
  Covered by test_namespace_url_not_flagged.
- HTML report template crash: a CSS percent sign broke string
  formatting. Fixed by escaping it. Covered by every report test.

## Still open, stated not passed

- Real production APK validation: no real APK was available on this
  machine (no Android tools, no apktool). Binary manifest parsing is
  verified by writer plus parser roundtrip and by plain XML paths, but
  a scan of a real app built from his own test project is still the
  final proof. Run it on his own test APK when he has one.
- Live Frida run: needs an emulator he owns plus Frida server, neither
  present here. The scripts pass syntax checks, and the log feeding
  path is verified with sample logs, but a live device run is untested.
- No-args CLI output is argparse standard behaviour (usage error,
  exit 2), not a crash. That is intended.
