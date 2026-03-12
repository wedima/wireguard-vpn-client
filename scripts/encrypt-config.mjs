#!/usr/bin/env node
/**
 * Admin tool to create encrypted WireGuard config files.
 * Usage: node scripts/encrypt-config.mjs wg0.conf output.enc
 *
 * Requires: npm/pnpm/yarn add argon2
 */
import { randomBytes, createCipheriv } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import readline from "node:readline";
import argon2 from "argon2";

const MAGIC = Buffer.from("WGCV1\0", "binary");
const SALT_LEN = 32;
const NONCE_LEN = 12;

const ARGON2_TIME_COST = 2;
const ARGON2_MEMORY_COST = 19456;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN = 32;

async function promptPassword(promptText) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  rl.stdoutMuted = true;
  rl._writeToOutput = function writeToOutput(value) {
    if (rl.stdoutMuted) {
      rl.output.write("*");
    } else {
      rl.output.write(value);
    }
  };

  const password = await new Promise((resolve) => {
    rl.question(promptText, (answer) => {
      rl.output.write("\n");
      resolve(answer);
    });
  });

  rl.close();
  return password;
}

async function encrypt(plaintext, password) {
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);

  const key = await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    timeCost: ARGON2_TIME_COST,
    memoryCost: ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLength: ARGON2_HASH_LEN,
    raw: true,
  });

  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Match Python/Rust payload format: ciphertext with auth tag appended.
  const encryptedPayload = Buffer.concat([ciphertext, tag]);
  return Buffer.concat([MAGIC, salt, nonce, encryptedPayload]);
}

async function main() {
  if (process.argv.length !== 4) {
    console.error(`Usage: ${process.argv[1]} <input.conf> <output.enc>`);
    process.exit(1);
  }

  const [, , inputPath, outputPath] = process.argv;
  const plaintext = await readFile(inputPath);

  const password = await promptPassword("Encryption password: ");
  const confirm = await promptPassword("Confirm password: ");

  if (password !== confirm) {
    console.error("Passwords do not match.");
    process.exit(1);
  }

  const encrypted = await encrypt(plaintext, password);
  await writeFile(outputPath, encrypted);

  console.log(`Encrypted config written to: ${outputPath}`);
  console.log(`Original size: ${plaintext.length} bytes -> Encrypted: ${encrypted.length} bytes`);
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
