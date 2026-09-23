// Zips dist/windows-disk-cleaner/ into dist/windows-disk-cleaner-skill.zip plus SHA256SUMS.txt.
// Only node built-ins are used, so no archive tool has to exist on the runner.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
const root = path.resolve(import.meta.dirname, "..");
const source = path.join(root, "dist", "windows-disk-cleaner");
const archive = path.join(root, "dist", "windows-disk-cleaner-skill.zip");
// Fixed 1980-01-01 timestamp and fixed entry order keep the archive reproducible.
const DOS_DATE = 0x0021,
  DOS_TIME = 0;
const crcTable = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crcTable[n] = c >>> 0;
}
function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
async function listFiles(dir, prefix) {
  const found = [];
  for (const entry of (await fs.readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, entry.name);
    const name = prefix + "/" + entry.name;
    if (entry.isDirectory()) found.push(...(await listFiles(full, name)));
    else found.push({ name, full });
  }
  return found;
}
if (!(await fs.stat(source).catch(() => null))?.isDirectory())
  throw Error("package not found: " + source + " (run: node scripts/package-skill.mjs)");
const entryRoot = path.basename(source);
const entries = await listFiles(source, entryRoot);
const local = [],
  central = [];
let offset = 0;
for (const entry of entries) {
  const data = await fs.readFile(entry.full);
  const compressed = deflateRawSync(data, { level: 9 });
  const name = Buffer.from(entry.name, "utf8");
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0x0800, 6);
  header.writeUInt16LE(8, 8);
  header.writeUInt16LE(DOS_TIME, 10);
  header.writeUInt16LE(DOS_DATE, 12);
  header.writeUInt32LE(crc32(data), 14);
  header.writeUInt32LE(compressed.length, 18);
  header.writeUInt32LE(data.length, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  local.push(header, name, compressed);
  const directory = Buffer.alloc(46);
  directory.writeUInt32LE(0x02014b50, 0);
  directory.writeUInt16LE(20, 4);
  directory.writeUInt16LE(20, 6);
  directory.writeUInt16LE(0x0800, 8);
  directory.writeUInt16LE(8, 10);
  directory.writeUInt16LE(DOS_TIME, 12);
  directory.writeUInt16LE(DOS_DATE, 14);
  directory.writeUInt32LE(crc32(data), 16);
  directory.writeUInt32LE(compressed.length, 20);
  directory.writeUInt32LE(data.length, 24);
  directory.writeUInt16LE(name.length, 28);
  directory.writeUInt16LE(0, 30);
  directory.writeUInt16LE(0, 32);
  directory.writeUInt16LE(0, 34);
  directory.writeUInt16LE(0, 36);
  directory.writeUInt32LE(0, 38);
  directory.writeUInt32LE(offset, 42);
  central.push(directory, name);
  offset += header.length + name.length + compressed.length;
}
const centralSize = central.reduce((total, part) => total + part.length, 0);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(0, 4);
end.writeUInt16LE(0, 6);
end.writeUInt16LE(entries.length, 8);
end.writeUInt16LE(entries.length, 10);
end.writeUInt32LE(centralSize, 12);
end.writeUInt32LE(offset, 16);
end.writeUInt16LE(0, 20);
const zip = Buffer.concat([...local, ...central, end]);
await fs.writeFile(archive, zip);
const digest = createHash("sha256").update(zip).digest("hex");
await fs.writeFile(path.join(root, "dist", "SHA256SUMS.txt"), digest + "  " + path.basename(archive) + "\n", "utf8");
console.log(JSON.stringify({ archive, entries: entries.length, bytes: zip.length, sha256: digest }, null, 2));
