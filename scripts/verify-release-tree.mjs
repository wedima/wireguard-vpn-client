import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { verifyArtifact } from "./verify-artifact.mjs";

function walk(dir, found = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, found);
    else found.push(path);
  }
  return found;
}

export function verifyReleaseTree(dir) {
  const counts = { dmg: 0, gzip: 0, x64: 0, arm64: 0, msi: 0, sig: 0 };
  for (const file of walk(dir)) {
    const name = basename(file).toLowerCase();
    const bytes = readFileSync(file);
    if (name.endsWith(".dmg")) {
      verifyArtifact("dmg", bytes);
      counts.dmg += 1;
    } else if (name.endsWith(".tar.gz")) {
      verifyArtifact("gzip", bytes);
      counts.gzip += 1;
    } else if (name.endsWith(".msi")) {
      verifyArtifact("msi", bytes);
      counts.msi += 1;
    } else if (name.endsWith(".sig")) {
      verifyArtifact("sig", bytes);
      counts.sig += 1;
    } else if (name.endsWith(".exe")) {
      const { machine } = verifyArtifact("pe", bytes);
      if (machine === 0xaa64) counts.arm64 += 1;
      else if (machine === 0x8664) counts.x64 += 1;
      else throw new Error(`${file} has unexpected PE machine 0x${machine.toString(16)}`);
    }
  }
  const missing = [];
  if (counts.dmg < 1) missing.push("macOS dmg");
  if (counts.gzip < 1) missing.push("macOS app.tar.gz");
  if (counts.x64 < 1) missing.push("Windows x64 exe");
  if (counts.msi < 1) missing.push("Windows msi");
  if (missing.length) {
    throw new Error(`Release is missing ${missing.join(", ")}`);
  }
  return counts;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("Usage: verify-release-tree.mjs <directory>");
    process.exit(2);
  }
  const counts = verifyReleaseTree(dir);
  console.log(`release artifacts ok ${JSON.stringify(counts)}`);
}
