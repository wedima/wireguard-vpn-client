import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const PE_MACHINES = {
  "0x8664": 0x8664,
  "0xaa64": 0xaa64,
  x64: 0x8664,
  arm64: 0xaa64,
};

export function verifyArtifact(kind, bytes, options = {}) {
  if (!bytes || bytes.length < 8) {
    throw new Error(`${kind} artifact is empty or truncated`);
  }
  switch (kind) {
    case "pe":
      return verifyPe(bytes, options.machine);
    case "msi":
      return verifyMsi(bytes);
    case "dmg":
      return verifyDmg(bytes);
    case "gzip":
      return verifyGzip(bytes);
    case "sig":
      return verifySignature(bytes);
    default:
      throw new Error(`Unknown artifact kind ${kind}`);
  }
}

function verifyPe(bytes, machine) {
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    throw new Error("Not a Windows PE executable (missing MZ header)");
  }
  if (bytes.length < 0x40) {
    throw new Error("PE header is truncated");
  }
  const peOffset = bytes.readUInt32LE(0x3c);
  if (peOffset + 6 > bytes.length) {
    throw new Error("PE header offset is out of range");
  }
  if (bytes.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0") {
    throw new Error("Not a Windows PE executable (missing PE signature)");
  }
  const actual = bytes.readUInt16LE(peOffset + 4);
  if (machine != null && actual !== machine) {
    throw new Error(
      `PE machine is 0x${actual.toString(16)} but expected 0x${machine.toString(16)}`
    );
  }
  return { machine: actual };
}

function verifyMsi(bytes) {
  const magic = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  if (!bytes.subarray(0, 8).equals(magic)) {
    throw new Error("Not an MSI installer (missing OLE header)");
  }
  return {};
}

function verifyDmg(bytes) {
  if (bytes.length < 512) {
    throw new Error("DMG is truncated");
  }
  const tail = bytes.subarray(bytes.length - 512, bytes.length - 508);
  if (tail.toString("ascii") !== "koly") {
    throw new Error("Not a DMG (missing koly trailer)");
  }
  return {};
}

function verifyGzip(bytes) {
  if (bytes[0] !== 0x1f || bytes[1] !== 0x8b) {
    throw new Error("Not a gzip archive");
  }
  return {};
}

export function assertUpdaterSignature(signature, version) {
  verifyArtifact("sig", Buffer.from(String(signature), "utf8"));
  const decoded = Buffer.from(String(signature).trim(), "base64").toString("utf8");
  const versionOk =
    decoded.includes(`version:${version}`) || decoded.includes(`version:v${version}`);
  if (!versionOk) {
    throw new Error(`Refusing update manifest: signature is not for version ${version}`);
  }
}

function verifySignature(bytes) {
  const text = bytes.toString("utf8").trim();
  if (text.length < 80) {
    throw new Error("Update signature is missing or too short to be a minisign signature");
  }
  let decoded;
  try {
    decoded = Buffer.from(text, "base64").toString("utf8");
  } catch {
    throw new Error("Update signature is not minisign base64");
  }
  if (!decoded.includes("untrusted comment:") || !decoded.includes("trusted comment:")) {
    throw new Error("Update signature is not a minisign signature");
  }
  if (!/version:\d+\.\d+\.\d+/.test(decoded)) {
    throw new Error("Update signature does not include a signed version");
  }
  return {};
}

function parseArgs(argv) {
  const options = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--kind" || arg === "--machine") {
      options[arg.slice(2)] = argv[++i];
    } else {
      options._.push(arg);
    }
  }
  return options;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  const file = args._[0];
  if (!args.kind || !file) {
    console.error("Usage: verify-artifact.mjs --kind <pe|msi|dmg|gzip|sig> [--machine <x64|arm64>] <file>");
    process.exit(2);
  }
  const bytes = readFileSync(file);
  const machine = args.machine ? PE_MACHINES[args.machine.toLowerCase()] : undefined;
  if (args.machine && machine == null) {
    console.error(`Unknown machine ${args.machine}`);
    process.exit(2);
  }
  verifyArtifact(args.kind, bytes, { machine });
  console.log(`ok ${args.kind} ${file}`);
}
