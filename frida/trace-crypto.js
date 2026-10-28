// trace-crypto.js
// Purpose: log crypto choices made by a test app you own at runtime.
// What it does: logs Cipher and MessageDigest algorithm names only.
// It never logs keys, plaintext, or ciphertext.
// Usage: frida -U -f <your-test-app-package> -l trace-crypto.js
// Only run against apps you own or have explicit permission to test.
"use strict";
function log(tag, detail, severity) {
  console.log(JSON.stringify({tag: tag, detail: detail, severity: severity || "low"}));
}
try {
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.getInstance.overload("java.lang.String").implementation = function (name) {
    var sev = (name.indexOf("ECB") !== -1) ? "medium" : "low";
    log("crypto", "Cipher requested: " + name, sev);
    return this.getInstance(name);
  };
} catch (e) { log("crypto", "Cipher hook not available: " + e, "info"); }
try {
  var Digest = Java.use("java.security.MessageDigest");
  Digest.getInstance.overload("java.lang.String").implementation = function (name) {
    var sev = (name === "MD5" || name === "SHA1" || name === "SHA-1") ? "medium" : "low";
    log("crypto", "MessageDigest requested: " + name, sev);
    return this.getInstance(name);
  };
} catch (e) { log("crypto", "MessageDigest hook not available: " + e, "info"); }
