// trace-storage.js
// Purpose: log storage access by a test app you own: preferences, files.
// What it does: logs which preference keys and file names are touched.
// It never logs values, file contents, or secrets.
// Usage: frida -U -f <your-test-app-package> -l trace-storage.js
// Only run against apps you own or have explicit permission to test.
"use strict";
function log(tag, detail, severity) {
  console.log(JSON.stringify({tag: tag, detail: detail, severity: severity || "low"}));
}
try {
  var Prefs = Java.use("android.content.SharedPreferences");
  var editor = Java.use("android.content.SharedPreferences$Editor");
  editor.putString.overload("java.lang.String", "java.lang.String").implementation = function (k, v) {
    log("storage", "SharedPreferences write, key only: " + k, "low");
    return this.putString(k, v);
  };
} catch (e) { log("storage", "SharedPreferences hook not available: " + e, "info"); }
try {
  var FileOutput = Java.use("java.io.FileOutputStream");
  FileOutput.$init.overload("java.io.File", "boolean").implementation = function (f, append) {
    log("storage", "File write: " + f.getAbsolutePath(), "low");
    return this.$init(f, append);
  };
} catch (e) { log("storage", "FileOutputStream hook not available: " + e, "info"); }
