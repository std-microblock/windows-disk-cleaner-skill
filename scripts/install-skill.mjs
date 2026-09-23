// Copies an assembled skill package into a local Codex skills directory.
// Read-only with respect to the source tree; writes only inside the destination.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}
const source = path.resolve(argument("--source") ?? path.join(root, "dist", "windows-disk-cleaner"));
const skillsDir = path.resolve(
  argument("--dest") ?? process.env.CODEX_SKILLS_DIR ?? path.join(os.homedir(), ".agents", "skills"),
);
const force = process.argv.includes("--force");
const name = path.basename(source);
const target = path.join(skillsDir, name);
if (!(await fs.stat(source).catch(() => null))?.isDirectory())
  throw Error("package not found: " + source + " (run: node scripts/package-skill.mjs)");
const binary = path.join(source, "bin", "disk-cleaner.exe");
const binaryStat = await fs.stat(binary).catch(() => null);
if (!binaryStat?.size) throw Error("package has no bin/disk-cleaner.exe: " + source);
if ((await fs.stat(target).catch(() => null)) && !force)
  throw Error(target + " already exists; re-run with --force to replace it");
const staging = target + ".staging-" + process.pid;
await fs.rm(staging, { recursive: true, force: true });
await fs.mkdir(skillsDir, { recursive: true });
await fs.cp(source, staging, { recursive: true });
await fs.rm(target, { recursive: true, force: true });
await fs.rename(staging, target);
const version = (await fs.readFile(path.join(target, "VERSION"), "utf8")).trim();
console.log(JSON.stringify({ installed: target, version, skillsDir, binaryBytes: binaryStat.size }, null, 2));
