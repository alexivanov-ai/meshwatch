// MAC prefix to vendor lookup.
//
// oui-data.json is the full IEEE MA-L (24-bit) registry, bundled locally so
// lookups never call a web service at runtime. Regenerate it occasionally
// with `node scripts/build-oui.js`, which fetches
// https://standards-oui.ieee.org/oui/oui.csv - the only place that URL is
// used.

const REGISTRY = require("./oui-data.json");

function vendor(mac) {
  if (!mac) return null;
  const prefix = mac.toUpperCase().split(":").slice(0, 3).join(":");
  return REGISTRY[prefix] || null;
}

// A locally administered / randomised address - iPhones and Androids use these.
function isRandomised(mac) {
  if (!mac) return false;
  const firstByte = parseInt(mac.split(":")[0], 16);
  return (firstByte & 0x02) === 0x02;
}

module.exports = { vendor, isRandomised };
