#!/usr/bin/env node
const crypto = require("crypto");
const secret = process.argv[2];
if (!secret || secret === "-h" || secret === "--help") {
  console.log("Usage: totp-verify <base32-secret-or-text>");
  console.log("Example: totp-verify JBSWY3DPEHPK3PXP");
  process.exit(secret ? 0 : 1);
}
const epoch = Math.floor(Date.now() / 1000);
const timeStep = Math.floor(epoch / 30);
const buf = Buffer.alloc(8);
buf.writeBigInt64BE(BigInt(timeStep));
const hmac = crypto.createHmac("sha1", Buffer.from(secret)).update(buf).digest();
const offset = hmac[hmac.length - 1] & 0xf;
const code = ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
console.log(`Current TOTP Code: \x1b[32m${code}\x1b[0m (valid for ${30 - (epoch % 30)}s)`);
