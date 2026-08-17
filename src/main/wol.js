// Wake-on-LAN: broadcasts the standard 102-byte magic packet. Whether the
// target device actually wakes depends on WOL being enabled in its own
// BIOS/OS — that can't be verified remotely, so this never claims success
// beyond "packet sent".
const dgram = require("dgram");

function buildPacket(mac) {
  const macBytes = Buffer.from(mac.replace(/[:-]/g, ""), "hex");
  if (macBytes.length !== 6) throw new Error("invalid MAC");
  return Buffer.concat([Buffer.alloc(6, 0xff), Buffer.concat(Array(16).fill(macBytes))]);
}

function wake(mac, broadcastAddr = "255.255.255.255") {
  return new Promise((resolve) => {
    let packet;
    try { packet = buildPacket(mac); } catch (e) { return resolve({ ok: false, reason: "invalid MAC address" }); }
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.close();
      resolve(result);
    };
    socket.on("error", (err) => finish({ ok: false, reason: String(err.message || err) }));
    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(packet, 0, packet.length, 9, broadcastAddr, (err) => {
        finish(err ? { ok: false, reason: String(err.message || err) } : { ok: true });
      });
    });
  });
}

module.exports = { wake };
