import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { assertUpdaterSignature } from "./verify-artifact.mjs";

const REPO = "wedima/wireguard-vpn-client";

export function releaseAssetUrl(tag, filename) {
  if (!/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(tag)) {
    throw new Error(`Refusing update manifest: tag ${tag} is not a release tag`);
  }
  if (filename.includes("/") || filename.includes("\\") || filename.includes("..")) {
    throw new Error("Refusing update manifest: artifact name is not a single file");
  }
  const url = `https://github.com/${REPO}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(filename)}`;
  if (!url.startsWith("https://github.com/")) {
    throw new Error("Refusing update manifest: asset URL is not HTTPS on GitHub");
  }
  return url;
}

export function buildLatestJson({ version, notes, pubDate, assets }) {
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error("Refusing update manifest: version is not semver");
  }
  if (!assets.length) {
    throw new Error("Refusing update manifest: no signed artifacts");
  }
  const platforms = {};
  for (const asset of assets) {
    const signature = String(asset.signature ?? "").trim();
    assertUpdaterSignature(signature, version);
    const url = releaseAssetUrl(asset.tag, asset.filename);
    platforms[asset.platform] = { signature, url };
  }
  return {
    version,
    notes: notes || "Wedima VPN WG",
    pub_date: pubDate,
    platforms,
  };
}

function walk(dir, found = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const info = statSync(path);
    if (info.isDirectory()) walk(path, found);
    else found.push(path);
  }
  return found;
}

export function discoverReleaseAssets(root, tag) {
  const files = walk(root);
  const sigFor = (file) => {
    const sig = files.find((candidate) => candidate === `${file}.sig`);
    return sig ? readFileSync(sig, "utf8") : "";
  };
  const assets = [];
  const tar = files.find((file) => file.endsWith(".app.tar.gz"));
  if (tar) {
    const signature = sigFor(tar);
    const filename = basename(tar);
    for (const platform of ["darwin-aarch64", "darwin-x86_64"]) {
      assets.push({ platform, filename, signature, tag });
    }
  }
  const nsis = files.filter((file) => {
    const name = basename(file).toLowerCase();
    return name.endsWith(".exe") && (name.includes("setup") || name.includes("nsis")) && !name.endsWith(".sig");
  });
  for (const exe of nsis) {
    const name = basename(exe).toLowerCase();
    const platform = name.includes("aarch64") || name.includes("arm64")
      ? "windows-aarch64"
      : "windows-x86_64";
    assets.push({
      platform,
      filename: basename(exe),
      signature: sigFor(exe),
      tag,
    });
  }
  return assets.filter((asset, index, all) =>
    all.findIndex((other) => other.platform === asset.platform) === index
  );
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) options[arg.slice(2)] = argv[++i];
  }
  return options;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  if (!args.dir || !args.tag || !args.out) {
    console.error("Usage: make-latest-json.mjs --dir <artifacts> --tag vX.Y.Z --out latest.json");
    process.exit(2);
  }
  const version = args.tag.replace(/^v/, "");
  const assets = discoverReleaseAssets(args.dir, args.tag);
  const signed = assets.filter((asset) => String(asset.signature).trim().length >= 80);
  if (signed.length === 0) {
    console.log("No updater signatures found. latest.json was not published.");
    process.exit(0);
  }
  if (signed.length !== assets.length) {
    console.error("A release artifact is missing its minisign signature. Refusing to publish latest.json.");
    process.exit(1);
  }
  const manifest = buildLatestJson({
    version,
    pubDate: new Date().toISOString(),
    assets: signed,
  });
  writeFileSync(args.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Wrote ${args.out} for ${Object.keys(manifest.platforms).join(", ")}`);
}
