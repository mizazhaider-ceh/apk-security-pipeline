# Deep test report: APK Security Pipeline v2.0.0

## v2.0.0 deep mode verification (2026-10-28)

- Total tests: 54, all passing (42 before + 12 new deep mode tests).
- Real tools installed and verified on this machine: Java 17.0.20.1, apktool 3.0.3, jadx 1.5.6, androguard 4.1.4. `python3 -m apk_pipeline tools` finds all four.
- Real APK deep scan (TestActivity.apk, 175 KB, debug signed test app):
  apktool decoded 340 smali files (2600 methods seen, 8 smali findings
  with method context), jadx produced 134 Java files (1 Java finding
  with file, line, and method), androguard reported 340 dex classes
  and 3602 dex methods, debug certificate correctly detected, final
  score 26/100 grade F with 12 findings (up from 2 basic findings).
- Graceful degradation: deep scan on the synthetic vulnerable sample
  completes with 24 findings and reports apktool and jadx stages
  honestly instead of crashing.
- Defects fixed during v2 testing: (1) deep strings summary counted
  the Android namespace URI as a URL host; fixed by excluding
  namespace hosts, same rule as the static stage. (2) androguard 4
  returns raw dex bytes from get_dex(), not a DEX object; fixed by
  parsing bytes explicitly with androguard.core.dex.DEX, and
  androguard's own debug logging is silenced so CLI output stays clean.

## v1.0.1 and earlier report

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

## Real APK validation, added 2026-10-28 (v1.0.1)

A real run on a course lab APK reported package unknown and 0
permissions while components parsed, which exposed a parser bug that
synthetic tests could not see. Root cause: the parser read attributes
from chunk start + attributeStart, but the spec defines attributeStart
relative to the end of the node header, and real toolchains store 20
there (attributes at chunk start + 16 + 20 = 36). The project's own
writer stored 36, so roundtrip tests stayed green while real APKs
parsed garbage attributes. Fixed in axml.py (base = chunk start +
header size + attributeStart) and axml_write.py (now stores the spec
value 20). Verified against androguard as ground truth:

| APK | Ours package | Truth package | Perms | Components |
| --- | --- | --- | --- | --- |
| Test-debug.apk | org.t0t0.androguard.test | org.t0t0.androguard.test | 0 / 0 | 1 / 1 |
| TestActivity.apk | tests.androguard | tests.androguard | 0 / 0 | 1 / 1 |
| TC-debug.apk | org.t0t0.androguard.TC | org.t0t0.androguard.TC | 0 / 0 | 1 / 1 |

4 regression tests added (spec attributeStart value, UTF-16 pool,
resource map skipping, many root attributes). Total suite now 42 tests.

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
