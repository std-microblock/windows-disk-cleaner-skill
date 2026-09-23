// Assembles the distributable skill package under dist/windows-disk-cleaner/.
// Copies only the release binary, the skill sources and the license texts.
// Nothing is installed globally and no user configuration is touched.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
const root = path.resolve(import.meta.dirname, "..");
const source = path.join(root, "skill", "windows-disk-cleaner");
const binary = path.join(root, "target", "release", "disk-cleaner.exe");
const output = path.join(root, "dist", "windows-disk-cleaner");
function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}
async function listFiles(dir, prefix = "") {
  const found = [];
  for (const entry of (await fs.readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, entry.name);
    const name = prefix ? prefix + "/" + entry.name : entry.name;
    if (entry.isDirectory()) found.push(...(await listFiles(full, name)));
    else found.push({ name, full });
  }
  return found;
}
const manifest = await fs.readFile(path.join(root, "Cargo.toml"), "utf8");
const crateVersion = manifest.match(/^version = "([^"]+)"/m)?.[1];
if (!crateVersion) throw Error("Cargo.toml has no package version");
const version = (argument("--version") ?? process.env.SKILL_VERSION ?? crateVersion).replace(/^v/, "");
const data = await fs.readFile(binary);
if (data.subarray(0, 2).toString() !== "MZ") throw Error(binary + " is not a Windows executable");
const sha256 = createHash("sha256").update(data).digest("hex");
await fs.rm(output, { recursive: true, force: true });
await fs.cp(source, output, { recursive: true });
await fs.mkdir(path.join(output, "bin"), { recursive: true });
await fs.copyFile(binary, path.join(output, "bin", "disk-cleaner.exe"));
await fs.copyFile(path.join(root, "LICENSE"), path.join(output, "LICENSE"));
await fs.copyFile(path.join(root, "THIRD_PARTY_NOTICES.md"), path.join(output, "THIRD_PARTY_NOTICES.md"));
await fs.cp(path.join(root, "licenses"), path.join(output, "licenses"), { recursive: true });
await fs.writeFile(path.join(output, "bin", "SHA256SUMS"), sha256 + "  disk-cleaner.exe\n", "utf8");
await fs.writeFile(path.join(output, "VERSION"), version + "\n", "utf8");
const files = (await listFiles(output)).map((entry) => entry.name);
console.log(
  JSON.stringify({ package: output, version, binaryBytes: data.length, binarySha256: sha256, files }, null, 2),
);
