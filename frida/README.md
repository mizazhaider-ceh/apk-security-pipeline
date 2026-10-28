# Frida dynamic scripts

Only run these against test apps you built yourself or have explicit
permission to test, on an emulator or device you own.

## What each script does

- `trace-network.js`: logs HTTP client calls, scheme plus host only. Never logs full URLs, headers, bodies, or tokens.
- `trace-storage.js`: logs preference keys and file names touched. Never logs values or file contents.
- `trace-crypto.js`: logs Cipher and MessageDigest algorithm names only. Never logs keys or plaintext.
- `trace-intents.js`: logs started screens and intent actions only. Never logs extras or user data.

## How to run, step by step

1. Start an emulator you own. Confirm it with `adb devices`.
2. Install your own test app on that emulator.
3. Start Frida server on the emulator (see Frida docs for your device type).
4. Run one script at a time, for example:
   `frida -U -f com.example.mytestapp -l trace-network.js`
   Replace the package with your own test app package.
5. Use the app through a scripted flow: open screens, save data, trigger a network call.
6. Save the JSON lines from the Frida output to a file, for example `frida-log.jsonl`.
7. Feed the log back into the pipeline:
   `python3 -m apk_pipeline scan my-test-app.apk --dynamic-log frida-log.jsonl`

## Spawn versus attach, in short

- Spawn (`-f`) starts the app under Frida from the beginning, so you catch early calls.
- Attach (`-p <pid>`) connects to an already running app, so classes and screens are already loaded.
- If a trace shows little at spawn, try attach after the main screen loads. Both behaviours are normal and worth noting in your report.

## Safety rules

- Never run these against apps you do not own.
- Never publish full URLs, tokens, keys, or user data from logs.
- If a log line contains sensitive data by accident, redact it before sharing the log.
