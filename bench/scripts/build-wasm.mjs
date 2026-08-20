import { spawnSync } from "node:child_process";
import { access, mkdir } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const benchRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = resolve(benchRoot, "wasm/Cargo.toml");
const target = "wasm32-unknown-unknown";
const wasm = resolve(
  benchRoot,
  "wasm/target/wasm32-unknown-unknown/release/proof_benchmark_wasm.wasm",
);
const output = resolve(benchRoot, "wasm/pkg");

requireCommand("cargo", ["--version"]);
requireCommand("rustup", ["target", "list", "--installed"], target);
requireCommand("wasm-bindgen", ["--version"]);

run("cargo", ["build", "--manifest-path", manifest, "--target", target, "--release"]);
await access(wasm, constants.R_OK);
await mkdir(output, { recursive: true });
run("wasm-bindgen", [
  wasm,
  "--target",
  "web",
  "--out-dir",
  output,
  "--no-typescript",
]);

function requireCommand(command, args, requiredOutput) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.error?.code === "ENOENT") {
    fail(`${command} is required but is not installed`);
  }
  if (result.status !== 0) {
    fail(`${command} prerequisite check failed: ${result.stderr.trim()}`);
  }
  if (requiredOutput && !result.stdout.split(/\r?\n/).includes(requiredOutput)) {
    fail(
      `Rust target ${requiredOutput} is required; run: rustup target add ${requiredOutput}`,
    );
  }
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

