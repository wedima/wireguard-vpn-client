import assert from "node:assert/strict";
import test from "node:test";
import { verifyArtifact } from "./verify-artifact.mjs";

function pe(machine) {
  const bytes = Buffer.alloc(0x80);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write("PE\0\0", 0x40, "ascii");
  bytes.writeUInt16LE(machine, 0x44);
  return bytes;
}

test("accepts an x64 and an arm64 PE", () => {
  assert.equal(verifyArtifact("pe", pe(0x8664), { machine: 0x8664 }).machine, 0x8664);
  assert.equal(verifyArtifact("pe", pe(0xaa64), { machine: 0xaa64 }).machine, 0xaa64);
});

test("rejects the wrong PE architecture", () => {
  assert.throws(() => verifyArtifact("pe", pe(0x8664), { machine: 0xaa64 }), /machine/);
  assert.throws(() => verifyArtifact("pe", Buffer.from("not a pe")), /MZ/);
});

test("accepts an AppImage magic", () => {
  const bytes = Buffer.alloc(16);
  bytes[0] = 0x7f;
  bytes[1] = 0x45;
  bytes[2] = 0x4c;
  bytes[3] = 0x46;
  bytes[8] = 0x41;
  bytes[9] = 0x49;
  bytes[10] = 0x02;
  verifyArtifact("appimage", bytes);
  assert.throws(() => verifyArtifact("appimage", Buffer.from("not an appimage!!")), /ELF|AppImage/);
});

test("accepts msi, dmg, and gzip magics", () => {
  const msi = Buffer.alloc(16);
  msi.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  verifyArtifact("msi", msi);
  const dmg = Buffer.alloc(512);
  dmg.write("koly", 0);
  verifyArtifact("dmg", dmg);
  verifyArtifact("gzip", Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]));
});

function fakeSignature(version = "0.1.7") {
  const text = [
    "untrusted comment: test",
    "RUSaaaaaaaa",
    `trusted comment: timestamp:1\tfile:payload.bin\tversion:${version}`,
    "bbbb",
    "",
  ].join("\n");
  return Buffer.from(text).toString("base64");
}

test("rejects a short or unsigned update signature", () => {
  assert.throws(() => verifyArtifact("sig", Buffer.from("")), /empty|short|signature/);
  assert.throws(() => verifyArtifact("sig", Buffer.from("A".repeat(80))), /minisign|version|signature/);
  verifyArtifact("sig", Buffer.from(fakeSignature()));
});
