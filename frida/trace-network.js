// trace-network.js
// Purpose: log network calls made by a test app you own, at runtime.
// What it does: hooks common HTTP clients and logs scheme plus host only.
// It never logs full URLs, headers, bodies, or tokens.
// Usage: frida -U -f <your-test-app-package> -l trace-network.js
// Only run against apps you own or have explicit permission to test.
"use strict";
function log(tag, detail, severity) {
  console.log(JSON.stringify({tag: tag, detail: detail, severity: severity || "low"}));
}
function hostOf(url) {
  try {
    var m = url.match(/^(https?:\/\/[^/?#]+)/);
    return m ? m[1] : "unknown host";
  } catch (e) { return "unknown host"; }
}
try {
  var URL = Java.use("java.net.URL");
  URL.openConnection.overload().implementation = function () {
    var conn = this.openConnection();
    log("network", "URL opened: " + hostOf(this.toString()), this.toString().indexOf("http://") === 0 ? "medium" : "low");
    return conn;
  };
} catch (e) { log("network", "java.net.URL hook not available: " + e, "info"); }
try {
  var OkHttp = Java.use("okhttp3.OkHttpClient");
  OkHttp.newCall.overload("okhttp3.Request").implementation = function (req) {
    try { log("network", "OkHttp call: " + hostOf(req.url().toString()), req.url().toString().indexOf("http://") === 0 ? "medium" : "low"); } catch (e) {}
    return this.newCall(req);
  };
} catch (e) { log("network", "OkHttp hook not available (app may not use OkHttp)", "info"); }
