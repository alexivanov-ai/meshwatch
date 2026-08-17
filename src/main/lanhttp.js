// HTTP(S) to private LAN hosts only. Never follows redirects off-LAN.
const http = require("http");
const https = require("https");
const { URL } = require("url");

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isPrivateIp(ip) {
  if (!IPV4_RE.test(ip)) return false;
  if (ip.indexOf("10.") === 0) return true;
  if (ip.indexOf("192.168.") === 0) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) {
    const n = Number(m[1]);
    return n >= 16 && n <= 31;
  }
  return false;
}

function hostOf(urlOrHost) {
  if (IPV4_RE.test(urlOrHost)) return urlOrHost;
  try {
    const u = new URL(urlOrHost.indexOf("://") === -1 ? "http://" + urlOrHost : urlOrHost);
    return u.hostname;
  } catch (e) {
    return null;
  }
}

function assertLan(urlOrHost) {
  const host = hostOf(urlOrHost);
  if (!host || !isPrivateIp(host)) {
    const err = new Error("refusing non-LAN host");
    err.code = "NOT_LAN";
    throw err;
  }
  return host;
}

function request({
  url,
  method = "GET",
  headers = {},
  body = null,
  timeoutMs = 8000,
  insecureTls = true
}) {
  const full = url.indexOf("://") === -1 ? "http://" + url : url;
  assertLan(full);
  const u = new URL(full);
  const payload = body == null ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  const hdrs = Object.assign({}, headers);
  if (payload && !hdrs["Content-Length"]) hdrs["Content-Length"] = String(payload.length);
  if (payload && !hdrs["Content-Type"]) {
    hdrs["Content-Type"] = typeof body === "string" ? "application/x-www-form-urlencoded" : "application/json";
  }

  const lib = u.protocol === "https:" ? https : http;
  const opts = {
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port || (u.protocol === "https:" ? 443 : 80),
    path: u.pathname + u.search,
    method,
    headers: hdrs,
    timeout: timeoutMs,
    rejectUnauthorized: !insecureTls
  };

  return new Promise((resolve, reject) => {
    const req = lib.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => {
        chunks.push(c);
        if (chunks.reduce((n, x) => n + x.length, 0) > 2e6) res.destroy();
      });
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        const text = buf.toString("utf8");
        let json = null;
        try { json = JSON.parse(text); } catch (e) { /* not json */ }
        const setCookie = res.headers["set-cookie"] || [];
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text,
          json,
          cookies: setCookie
        });
      });
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("timeout"));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function cookieValue(setCookie, name) {
  for (const c of setCookie || []) {
    const m = String(c).match(new RegExp("(?:^|,\\s*)" + name + "=([^;]+)"));
    if (m) return m[1];
  }
  return null;
}

module.exports = { isPrivateIp, assertLan, request, cookieValue, hostOf };
