import assert from "node:assert/strict";
import test from "node:test";
import { buildLatestJson, releaseAssetUrl } from "./make-latest-json.mjs";

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

const signature = fakeSignature("0.1.7");

test("asset URLs stay on this repository over HTTPS", () => {
  const url = releaseAssetUrl("v0.1.7", "Wedima VPN WG_0.1.7_x64-setup.exe");
  assert.equal(
    url,
    "https://github.com/wedima/wireguard-vpn-client/releases/download/v0.1.7/Wedima%20VPN%20WG_0.1.7_x64-setup.exe"
  );
  assert.throws(() => releaseAssetUrl("main", "app.exe"));
  assert.throws(() => releaseAssetUrl("v0.1.7", "../app.exe"));
});

test("manifest requires a signature for every platform", () => {
  const manifest = buildLatestJson({
    version: "0.1.7",
    pubDate: "2026-10-24T00:00:00Z",
    assets: [
      { platform: "windows-x86_64", filename: "setup.exe", signature, tag: "v0.1.7" },
    ],
  });
  assert.equal(manifest.platforms["windows-x86_64"].signature, signature);
  assert.throws(
    () =>
      buildLatestJson({
        version: "0.1.7",
        pubDate: "2026-10-24T00:00:00Z",
        assets: [{ platform: "windows-x86_64", filename: "setup.exe", signature: "", tag: "v0.1.7" }],
      }),
    /unsigned|empty|signature/
  );
});
