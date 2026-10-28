// trace-intents.js
// Purpose: log screens and intents started by a test app you own.
// What it does: logs component names and action strings only.
// It never logs intent extras, user data, or tokens.
// Usage: frida -U -f <your-test-app-package> -l trace-intents.js
// Only run against apps you own or have explicit permission to test.
"use strict";
function log(tag, detail, severity) {
  console.log(JSON.stringify({tag: tag, detail: detail, severity: severity || "low"}));
}
try {
  var Activity = Java.use("android.app.Activity");
  Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
    var comp = "unknown";
    try { comp = intent.getComponent() ? intent.getComponent().getClassName() : intent.getAction(); } catch (e) {}
    log("intent", "startActivity: " + comp, "low");
    return this.startActivity(intent);
  };
} catch (e) { log("intent", "Activity hook not available: " + e, "info"); }
