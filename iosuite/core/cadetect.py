"""
iOS CA-trust pre-flight detector.

Asks the device's own Security.framework whether a given CA is currently
trusted, without reading the sandbox-denied TrustStore.sqlite3 and without the
macOS-only SecTrustSettings APIs (which do not exist on iOS).

Inputs (pick one):
  * an exported CA file in DER or PEM form (e.g. ``.diag/burp_ca.cer``)
  * a live fetch from the Burp listener at ``http://<burp-host>:<burp-port>/cert``

The certificate bytes are shipped to the device over a temporary Frida script
attached to SpringBoard (which uses the same CFNetwork/NSURLSession trust path
as the target app and WKWebView). There,

    SecCertificateCreateWithData -> SecTrustCreateWithCertificates
    -> SecTrustEvaluateWithError

returns `trusted: true` when the CA is anchored in the device trust store and
`trusted: false` otherwise. Proven on this iPhone iOS 16.7.16:

    Burp PortSwigger CA          -> trusted: true,  subject "PortSwigger CA"
    fresh self-signed throwaway  -> trusted: false, errCode -67843

This is the strongest non-invasive pre-flight answer to "is the Burp CA a
problem on the iPhone?" — and it works whether or not Burp is reachable, as
long as the CA bytes are available locally.
"""

from __future__ import annotations

import base64
import json
import socket
import time
from pathlib import Path
from typing import Optional

import frida

# ---- Frida 17 ObjC bridge (removed from frida core in 17) ----
_BRIDGE_PATH = (
    r"C:\Users\Anonre\AppData\Local\Programs\Python\Python312"
    r"\Lib\site-packages\frida_tools\bridges\objc.js"
)

_DEF_BURP_HOST = "192.168.50.216"
_DEF_BURP_PORT = 1337

_CA_JS_HEADER = """\
function sec(sym) {
  try {
    var m = Process.getModuleByName('Security');
    return m ? m.findExportByName(sym) : null;
  } catch (e) { return null; }
}
function g(n) {
  try { return Module.findGlobalExportByName(n); } catch (e) { return null; }
}

var result = {
  trusted: null,
  subject: null,
  errCode: null,
  errDomain: null,
  error: null
};

try {
  var s64 = ObjC.classes.NSString.alloc().initWithString_(CA_B64);
  var data = ObjC.classes.NSData.alloc().initWithBase64EncodedString_options_(s64, 0);
  if (!data || data.isNull()) throw new Error('NSData is null');
  var fCreate = new NativeFunction(sec('SecCertificateCreateWithData'), 'pointer',
                                   ['pointer', 'pointer']);
  var cert = fCreate(NULL, data.handle);
  if (!cert || cert.isNull()) throw new Error('SecCertificateCreateWithData returned null');
  try {
    var fSum = new NativeFunction(sec('SecCertificateCopySubjectSummary'), 'pointer',
                                   ['pointer']);
    var summ = fSum(cert);
    result.subject = summ && !summ.isNull() ? new ObjC.Object(summ).toString() : null;
  } catch (e) { result.subjErr = String(e); }

  var fPol = new NativeFunction(sec('SecPolicyCreateBasicX509'), 'pointer', []);
  var policy = fPol();
  if (!policy || policy.isNull()) throw new Error('SecPolicyCreateBasicX509 returned null');
  var tp = Memory.alloc(Process.pointerSize);
  tp.writePointer(NULL);
  var fTrust = new NativeFunction(sec('SecTrustCreateWithCertificates'), 'int',
                                  ['pointer', 'pointer', 'pointer']);
  var st = fTrust(cert, policy, tp);
  if (st !== 0) throw new Error('SecTrustCreateWithCertificates status ' + st);
  var trust = tp.readPointer();
  if (!trust || trust.isNull()) throw new Error('trust is null');

  if (sec('SecTrustEvaluateWithError')) {
    var fEv = new NativeFunction(sec('SecTrustEvaluateWithError'), 'bool',
                                 ['pointer', 'pointer']);
    var errP = Memory.alloc(Process.pointerSize);
    errP.writePointer(NULL);
    result.trusted = !!fEv(trust, errP);
    var e = errP.readPointer();
    if (e && !e.isNull()) {
      try {
        result.errCode = new NativeFunction(g('CFErrorGetCode'), 'long', ['pointer'])(e);
      } catch (x) {}
      try {
        var d = new NativeFunction(g('CFErrorGetDomain'), 'pointer', ['pointer'])(e);
        if (d && !d.isNull()) result.errDomain = new ObjC.Object(d).toString();
      } catch (x) {}
    }
  } else {
    var fEv2 = new NativeFunction(sec('SecTrustEvaluate'), 'int', ['pointer', 'pointer']);
    var resP = Memory.alloc(4);
    resP.writeU32(0);
    result.evalStatus = fEv2(trust, resP);
    result.trusted = resP.readU32() > 0;
  }
} catch (e) {
  result.error = String(e);
}

send(result);
"""

_CA_JS_BOOT = (
    "__BRIDGE_SRC__"
    "var __bridge_fn = Script.evaluate('/frida/bridges/objc.js', "
    "'(function () { ' + __BRIDGE_SRC__ + \" Object.defineProperty(globalThis, 'ObjC', "
    "{ value: bridge }); return bridge; \" + ' })();');\n"
    "__bridge_fn;\n"
)


def _load_bridge_src() -> str:
    with open(_BRIDGE_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _ca_script_src(ca_b64: str) -> str:
    # Frida 17 removed the ObjC bridge from the runtime; it ships with
    # frida-tools and must be injected explicitly before any ObjC.classes use.
    bridge = json.dumps(_load_bridge_src())
    boot = (
        "var __bridge_src = " + bridge + ";\n"
        "var __bridge_fn = Script.evaluate('/frida/bridges/objc.js', "
        "'(function () { ' + __bridge_src + \" Object.defineProperty(globalThis, 'ObjC', "
        "{ value: bridge }); return bridge; \" + ' })();');\n"
        "__bridge_fn;\n"
    )
    header = _CA_JS_HEADER.replace("CA_B64", json.dumps(ca_b64), 1)
    return boot + header


def _fetch_burp_ca(host: str, port: int, timeout: float = 8.0) -> Optional[bytes]:
    """Download the DER-form CA Burp serves at http://burp/cert."""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.sendall(b"GET http://burp/cert HTTP/1.1\r\nHost: burp\r\nConnection: close\r\n\r\n")
        s.settimeout(timeout)
        chunks = []
        while True:
            try:
                part = s.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
        s.close()
    except OSError:
        return None
    body = b"".join(chunks).split(b"\r\n\r\n", 1)[-1]
    return body or None


def _load_ca_file(path: str) -> Optional[bytes]:
    """Load a CA cert from a DER or PEM file."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    # PEM? Extract the first -----BEGIN CERTIFICATE----- block.
    text = raw.decode("ascii", "replace")
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    b = text.find(begin)
    e = text.find(end, b + 1) if b >= 0 else -1
    if b >= 0 and e >= 0:
        b64 = text[b + len(begin):e]
        try:
            return base64.b64decode("".join(b64.split()))
        except Exception:
            return None
    return raw  # assume DER


def _run_on_device(ca_b64: str, timeout: float = 25.0) -> dict:
    """Evaluate the CA on SpringBoard. Returns the raw device payload.

    Split out from `detect_ca_trust_state` so the state mapping can be tested
    without hardware. Never raises: transport failures come back as
    ``{"error": ...}`` so callers can report the real cause.
    """
    try:
        dev = frida.get_usb_device(timeout=12)
    except Exception as e:
        return {"error": f"No USB iOS device reachable: {type(e).__name__}: {e}"}

    try:
        pids = [p.pid for p in dev.enumerate_processes() if p.name == "SpringBoard"]
    except Exception as e:
        return {"error": f"Could not enumerate device processes: {type(e).__name__}: {e}"}
    if not pids:
        return {"error": "SpringBoard not found on device"}

    sess = None
    try:
        sess = dev.attach(pids[0])
        script = sess.create_script(_ca_script_src(ca_b64))
        msgs = []
        script.on("message", lambda m, d: msgs.append(m))
        script.load()

        t0 = time.time()
        while time.time() - t0 < timeout:
            if any(
                m.get("type") == "error"
                or (m.get("type") == "send" and isinstance(m.get("payload"), dict)
                    and m["payload"].get("trusted") is not None)
                for m in msgs
            ):
                break
            time.sleep(0.2)
        time.sleep(0.3)

        for m in msgs:
            if m.get("type") == "send" and isinstance(m.get("payload"), dict):
                return m["payload"]
            if m.get("type") == "error":
                return {"error": f"Frida script error: {m.get('description')}"}
        return {"error": "timeout waiting for device"}
    except Exception as e:
        return {"error": f"CA check raised on device: {type(e).__name__}: {e}"}
    finally:
        if sess:
            try:
                sess.detach()
            except Exception:
                pass


def detect_ca_trust_state(
    ca_cert: Optional[str] = None,
    burp_host: str = _DEF_BURP_HOST,
    burp_port: int = _DEF_BURP_PORT,
    attach_timeout: float = 12.0,
    script_timeout: float = 25.0,
) -> dict:
    """
    Return a dict describing whether the given CA is trusted on the iPhone.

    Keys:

    * ``state`` — ``"trusted"`` | ``"untrusted"`` | ``"unavailable"``
    * ``subject`` — certificate subject summary, if readable
    * ``detail`` — human-readable explanation
    * ``hint`` — actionable remediation when the state is not ``trusted``
    * ``errCode`` / ``errDomain`` — raw Security.framework error (untrusted)
    """
    result: dict = {
        "state": "unavailable",
        "subject": None,
        "detail": "CA detection not performed",
        "hint": None,
        "error": None,
    }

    # ---- obtain CA bytes ----------------------------------------------------
    der: Optional[bytes] = None
    if ca_cert:
        der = _load_ca_file(ca_cert)
        if der is None:
            result["detail"] = f"Could not read CA file: {ca_cert}"
            result["error"] = "ca_file_unreadable"
            return result
    else:
        der = _fetch_burp_ca(burp_host, burp_port)
        if der is None:
            result["detail"] = (
                f"Could not reach Burp CA at http://{burp_host}:{burp_port}/cert "
                f"(provide --ca-cert instead)"
            )
            result["error"] = "burp_unreachable"
            return result

    try:
        b64 = base64.b64encode(der).decode()
    except Exception as e:
        result["detail"] = f"CA bytes could not be encoded: {e}"
        result["error"] = "ca_encode_error"
        return result

    # ---- run on device ------------------------------------------------------
    payload = _run_on_device(b64, timeout=script_timeout)

    if not isinstance(payload, dict) or payload.get("error"):
        err = (payload or {}).get("error", "no payload")
        result["detail"] = f"CA check could not complete: {err}"
        result["error"] = err
        # Distinguish "no hardware" from "the check itself failed".
        if "No USB iOS device" in str(err):
            result["error"] = "no_device"
        return result

    result["subject"] = payload.get("subject")
    trusted = bool(payload.get("trusted"))
    result["errCode"] = payload.get("errCode")
    result["errDomain"] = payload.get("errDomain")

    if trusted:
        result["state"] = "trusted"
        result["detail"] = (
            f"CA is trusted on this iPhone"
            + (f" ({payload.get('subject')})" if payload.get("subject") else "")
        )
        result["hint"] = None
    else:
        result["state"] = "untrusted"
        result["detail"] = (
            f"CA is NOT trusted on this iPhone"
            + (f" ({payload.get('subject')})" if payload.get("subject") else "")
        )
        result["hint"] = (
            "Install the Burp CA on the iPhone: open Safari at "
            f"http://{burp_host}:{burp_port}/cert, install the profile, then enable "
            "full trust in Settings → General → About → Certificate Trust Settings."
        )

    return result
