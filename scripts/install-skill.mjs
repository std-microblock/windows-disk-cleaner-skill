// Installs a skill package into a local Codex skills directory.
//   node scripts/install-skill.mjs                        # dist/windows-disk-cleaner (local build)
//   node scripts/install-skill.mjs --release latest       # newest GitHub release
//   node scripts/install-skill.mjs --release v0.2.1       # one published release
// Writes only inside the destination skills directory; the source tree is untouched.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
const root = path.resolve(import.meta.dirname, "..");
const repository = "std-microblock/windows-disk-cleaner-skill";
const zipName = "windows-disk-cleaner-skill.zip";
const sumsName = "SHA256SUMS.txt";
function argument(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}
/// Windows resolves executables only with an explicit extension here.
const exe = (name) => (process.platform === "win32" ? name + ".exe" : name);
function run(file, args) {
  return new Promise((resolve, reject) =>
    execFile(exe(file), args, { windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) =>
      error ? reject(error) : resolve(stdout),
    ),
  );
}
/// git's configured proxy is what makes github.com reachable on this machine; the
/// built-in fetch ignores it, curl takes it explicitly.
let proxyCache;
async function proxy() {
  if (proxyCache !== undefined) return proxyCache;
  proxyCache = "";
  for (const key of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]) {
    if (process.env[key]) return (proxyCache = process.env[key]);
  }
  try {
    proxyCache = (await run("git", ["config", "--get", "http.proxy"])).trim();
  } catch (error) {
    proxyCache = "";
  }
  return proxyCache;
}
/// curl first: it follows the machine's proxy settings on Windows, where the
/// built-in fetch has no proxy at all unless NODE_USE_ENV_PROXY is set.
async function download(url, destination) {
  const endpoint = await proxy();
  for (const extra of endpoint ? [[], ["--proxy", endpoint]] : [[]]) {
    try {
      await run("curl", ["-sSL", "--fail", "--retry", "2", ...extra, "-o", destination, url]);
      const stat = await fs.stat(destination);
      if (stat.size > 0) return fs.readFile(destination);
    } catch (error) {
      // try the next transport
    }
  }
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) throw Error(`${url}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  await fs.writeFile(destination, bytes);
  return bytes;
}
async function fetchJson(url) {
  try {
    const response = await fetch(url, { headers: { Accept: "application/vnd.github+json" } });
    if (response.ok) return await response.json();
  } catch (error) {
    // fall through to curl below
  }
  const work = path.join(os.tmpdir(), `disk-cleaner-release-${process.pid}.json`);
  const bytes = await download(url, work);
  const parsed = JSON.parse(bytes.toString("utf8"));
  await fs.rm(work, { force: true });
  return parsed;
}
async function extract(archive, directory) {
  await fs.mkdir(directory, { recursive: true });
  try {
    await run("tar", ["-xf", archive, "-C", directory]);
    return;
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
  await run("powershell", [
    "-NoProfile",
    "-Command",
    `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${directory}' -Force`,
  ]);
}
/// Downloads a released package, verifies it against the published checksum and
/// returns the extracted skill directory.
async function fetchRelease(reference) {
  const api = `https://api.github.com/repos/${repository}/releases/${reference === "latest" ? "latest" : `tags/${reference}`}`;
  const release = await fetchJson(api);
  const asset = (name) => release.assets.find((a) => a.name === name);
  const zip = asset(zipName);
  const sums = asset(sumsName);
  if (!zip || !sums) throw Error(`release ${release.tag_name} has no ${zipName}/${sumsName}`);
  const work = path.join(os.tmpdir(), `disk-cleaner-install-${process.pid}`);
  await fs.rm(work, { recursive: true, force: true });
  await fs.mkdir(work, { recursive: true });
  const archive = path.join(work, zipName);
  const bytes = await download(zip.browser_download_url, archive);
  const expected = (await download(sums.browser_download_url, path.join(work, sumsName)))
    .toString("utf8")
    .trim()
    .split(/\s+/)[0];
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (expected !== actual) throw Error(`${zipName} checksum mismatch: expected ${expected}, got ${actual}`);
  const extracted = path.join(work, "extracted");
  await extract(archive, extracted);
  return { directory: path.join(extracted, "windows-disk-cleaner"), release: release.tag_name, sha256: actual };
}
const release = argument("--release");
const local = path.join(root, "dist", "windows-disk-cleaner");
const skillsDir = path.resolve(
  argument("--dest") ?? process.env.CODEX_SKILLS_DIR ?? path.join(os.homedir(), ".agents", "skills"),
);
const force = process.argv.includes("--force");
let source = path.resolve(argument("--source") ?? local);
let targetDirectory = source;
let from;
if (release) {
  const fetched = await fetchRelease(release);
  source = fetched.directory;
  from = `release ${fetched.release} (sha256 ${fetched.sha256})`;
} else {
  from = "local build in dist/";
}
const name = path.basename(targetDirectory);
const targetDir = path.join(skillsDir, name);
if (!(await fs.stat(source).catch(() => null))?.isDirectory())
  throw Error("package not found: " + source + " (run: node scripts/package-skill.mjs)");
const binary = path.join(source, "bin", "disk-cleaner.exe");
const binaryStat = await fs.stat(binary).catch(() => null);
if (!binaryStat?.size) throw Error("package has no bin/disk-cleaner.exe: " + source);
if ((await fs.stat(targetDir).catch(() => null)) && !force)
  throw Error(targetDir + " already exists; re-run with --force to replace it");
const staging = targetDir + ".staging-" + process.pid;
await fs.rm(staging, { recursive: true, force: true });
await fs.mkdir(skillsDir, { recursive: true });
await fs.cp(source, staging, { recursive: true });
let stashed;
try {
  await fs.rm(targetDir, { recursive: true, force: true });
} catch (error) {
  // A running disk-cleaner.exe holds its own file open; Windows still allows the
  // directory to be renamed, so an in-use install is moved aside instead.
  if (!["EPERM", "EACCES", "EBUSY"].includes(error.code)) throw error;
  stashed = targetDir + ".in-use-" + Date.now();
  await fs.rename(targetDir, stashed);
}
await fs.rename(staging, targetDir);
for (const entry of await fs.readdir(skillsDir)) {
  // Best effort: retire copies left behind by a running executable or a crash.
  if (/^windows-disk-cleaner\.(staging|in-use)-/.test(entry) && path.join(skillsDir, entry) !== stashed) {
    await fs.rm(path.join(skillsDir, entry), { recursive: true, force: true }).catch(() => {});
  }
}
if (stashed && !(await fs.stat(stashed).catch(() => null))) stashed = undefined;
if (release) await fs.rm(path.dirname(source), { recursive: true, force: true });
const version = (await fs.readFile(path.join(targetDir, "VERSION"), "utf8")).trim();
console.log(
  JSON.stringify(
    {
      installed: targetDir,
      version,
      source: from,
      binaryBytes: binaryStat.size,
      skillsDir,
      previousCopyStillRunning: stashed,
    },
    null,
    2,
  ),
);
