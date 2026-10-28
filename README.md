# APK Security Pipeline

One command that security checks an Android app and explains every step it takes.

## Safety first, read this

Only run this tool against apps you built yourself, or apps you have
explicit permission to test, on devices and emulators you own. Never
run it against apps from a store, apps from other people, or apps with
real user data. The dynamic scripts never log full URLs, tokens, keys,
or file contents, and the static scanner masks secret-like values in
every report.

## What it is

A pipeline tool, not a single check. You give it one APK file (or a
decoded APK directory, or a manifest file), and it runs stages in order
and merges everything into one report:

1. **Intake:** reads the package and confirms it is scannable.
2. **Manifest parse:** turns the manifest (binary or plain XML) into structured facts.
3. **Manifest rules:** debuggable flag, backup flag, cleartext flag, exported components, dangerous permissions.
4. **Strings and code patterns:** secret patterns, cleartext URLs, and risky code patterns in dex and smali files.
5. **Dynamic (Frida):** runtime observations from your own test app, or an honest skip report when no device is present.
6. **Scoring:** one score from 100, one grade, counts per severity.
7. **Baseline compare (optional):** only what changed since the last run.

Every stage logs its goal, what it checked, what it found, and what it
skipped and why. Run with `--explain` to see that log in the terminal.
The same log is embedded in every HTML report, so the tool always tells
you what it is doing.

## Install

Nothing to install. Python 3.10 or newer, standard library only.

```bash
cd apk-security-pipeline
python3 -m apk_pipeline version
```

## Use it

```bash
# Full explanation mode, HTML plus JSON reports in out/
python3 -m apk_pipeline scan my-test-app.apk --explain

# Static only, no dynamic stage
python3 -m apk_pipeline scan my-test-app.apk --static-only

# Fail the build (exit code 2) on high or worse findings
python3 -m apk_pipeline scan my-test-app.apk --fail-on high

# Compare against a previous run, only new issues matter in CI
python3 -m apk_pipeline scan my-test-app.apk --baseline out/report.json

# Feed a manual Frida log back in (see frida/README.md)
python3 -m apk_pipeline scan my-test-app.apk --dynamic-log frida-log.jsonl

# List every built-in rule
python3 -m apk_pipeline rules
```

Exit codes: 0 means clean at your threshold, 2 means findings at or
above your threshold, 1 means an input or scan error.

## What you get

- `report.html`: single file, no external requests, no JavaScript. Score bar, stage log, findings with severity, location, masked evidence, why it matters, and how to fix it.
- `report.json`: the same data for scripts, CI, and baseline compares.

## Dynamic testing, how it works

The automatic run never fakes dynamic evidence. If Frida or a device is
missing, the report says so, with the exact reason and setup steps.
When you do have an emulator you own, run a script from `frida/`
manually (network, storage, crypto, intents), use your test app through
a scripted flow, save the JSON lines, and feed them back with
`--dynamic-log`. Full steps are in `frida/README.md`.

Spawn versus attach, in short: spawn starts the app under Frida from the
beginning and catches early calls. Attach connects to a running app
where classes are already loaded. If a trace shows little at spawn, try
attach after the main screen loads.

## Try it with the samples

Two synthetic test APKs ship in `samples/`, built by
`samples/generate_samples.py` with fake data only:

```bash
python3 -m apk_pipeline scan samples/clean.apk --static-only --explain
# Score: 100 / 100, grade A, findings: 0

python3 -m apk_pipeline scan samples/vulnerable.apk --static-only
# Score: 0 / 100, grade F, findings: 24
```

The vulnerable sample plants, on purpose: a debuggable app, cleartext
traffic, backup allowed, five exported components without permissions,
four dangerous permissions, secret patterns, a cleartext URL, and risky
code patterns (WebView settings, ECB, MD5, plain Random, debug logs).

## Custom rules

Add your own string patterns with a JSON file:

```json
{"patterns": [{"id": "MY_RULE", "pattern": "my-secret-marker",
"explanation": "My custom pattern.", "fix": "Remove it."}]}
```

```bash
python3 -m apk_pipeline scan app.apk --rules my-rules.json
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

38 tests: binary and plain manifest parsing, manifest variants, input
handling, scoring math, secret masking, custom rules, baseline compares,
report escaping, determinism, CLI exit codes and formats, and dynamic
log edge cases. See TEST_REPORT.md for the full deep test report.

## Project layout

```text
apk_pipeline/
  axml.py        binary XML parser
  axml_write.py  binary XML writer (test fixtures)
  manifest.py    manifest extraction
  rules.py       rules, scoring, masking
  scanner.py     stage orchestration, baseline
  dynamic.py     Frida harness, device checks
  report.py      HTML and JSON writers
  cli.py         command line interface
frida/           runtime trace scripts plus guide
samples/         sample APK generator plus test APKs
tests/           unit tests
```

## Limits, honest version

- Static patterns are review flags, not proof of exploitability.
- Dynamic results only cover the flows you actually ran.
- The tool never proves an app is safe. It reports what it found and what it checked.
- Binary manifest parsing covers the common manifest shapes. Very unusual manifests may need a decoded directory input instead.

## Roadmap

- More manifest rules (network security config review, deep link review).
- Smali level checks with method context, not just byte patterns.
- Automatic dynamic runs once a target package and flow file are given.
- SARIF output for GitHub code scanning.

## License

MIT. Created by Muhammad Izaz Haider.
