import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { verifyReleaseTree } from "./verify-release-tree.mjs";

function pe(machine) {
  const bytes = Buffer.alloc(0x80);
  bytes[0] = 0x4d;
  bytes[1] = 0x5a;
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write("PE\0\0", 0x40, "ascii");
  bytes.writeUInt16LE(machine, 0x44);
  return bytes;
}

test("requires macOS and Windows x64 artifacts", () => {
  const dir = mkdtempSync(join(tmpdir(), "wedima-release-"));
  try {
    const dmg = Buffer.alloc(512);
    dmg.write("koly", 0);
    writeFileSync(join(dir, "app.dmg"), dmg);
    writeFileSync(join(dir, "app.app.tar.gz"), Buffer.from([0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0]));
    const msi = Buffer.alloc(16);
    msi.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    writeFileSync(join(dir, "app.msi"), msi);
    assert.throws(() => verifyReleaseTree(dir), /Windows x64/);
    writeFileSync(join(dir, "setup.exe"), pe(0x8664));
    const counts = verifyReleaseTree(dir);
    assert.equal(counts.x64, 1);
    assert.equal(counts.dmg, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
