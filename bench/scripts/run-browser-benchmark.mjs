import { spawn, spawnSync } from "node:child_process";
import {
  access,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { cpus, machine, platform, release, tmpdir, totalmem } from "node:os";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const benchRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const options = parseOptions(process.argv.slice(2));
const pendingResults = new Map();
const server = createServer(handleRequest);
await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
const address = server.address();
if (!address || typeof address === "string") throw new Error("HTTP server did not bind");
const baseUrl = `http://127.0.0.1:${address.port}`;

const browserSpecs = {
  chrome: {
    executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    versionArgs: ["--version"],
    mode: "headless Web Worker",
  },
  firefox: {
    executable: "/Applications/Firefox.app/Contents/MacOS/firefox",
    versionArgs: ["--version"],
    mode: "headless Web Worker",
  },
  safari: {
    executable: "/usr/bin/safaridriver",
    versionArgs: ["--version"],
    mode: "WebDriver Web Worker",
  },
};

const browsers = [];
try {
  for (const browserName of options.browsers) {
    const specification = browserSpecs[browserName];
    if (!specification) {
      browsers.push({ browser: browserName, status: "skipped", reason: "unknown browser" });
      continue;
    }

    try {
      await access(specification.executable);
      const version = commandVersion(specification);
      console.log(`Running ${browserName} (${version})...`);
      const result =
        browserName === "safari"
          ? await runSafari(browserName)
          : await runHeadlessBrowser(browserName, specification);
      if (!result.ok) throw new Error(result.message ?? "worker failed");
      browsers.push({
        browser: browserName,
        status: "measured",
        installedVersion: version,
        mode: specification.mode,
        ...result,
      });
      console.log(
        `${browserName}: ${result.wasmToJavascriptRatio.toFixed(3)}x WASM/JavaScript`,
      );
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      browsers.push({
        browser: browserName,
        status: "skipped",
        installedVersion: await installedVersion(specification),
        reason,
      });
      console.error(`${browserName} skipped: ${reason}`);
    }
  }

  const wasmPath = resolve(benchRoot, "wasm/pkg/proof_benchmark_wasm_bg.wasm");
  const wasmStats = await stat(wasmPath);
  const report = {
    schemaVersion: 1,
    measuredAt: new Date().toISOString(),
    host: {
      platform: platform(),
      product: commandOutput("/usr/bin/sw_vers", ["-productName"]),
      productVersion: commandOutput("/usr/bin/sw_vers", ["-productVersion"]),
      release: release(),
      architecture: machine(),
      hardwareModel: commandOutput("/usr/sbin/sysctl", ["-n", "hw.model"]),
      cpu: cpus()[0]?.model ?? "unknown",
      logicalCpus: cpus().length,
      memoryBytes: totalmem(),
    },
    methodology: {
      location: "real browser Web Workers served from localhost",
      runs: options.runs,
      attemptsPerRun: options.attempts,
      warmupAttempts: options.warmupAttempts,
      sampleOrder: "alternating WASM-first and JavaScript-first",
      digestGate: "four shared vectors must equal native proof-core before timing",
      ratio: "median WASM hashes/second divided by median JavaScript hashes/second",
      spread: "minimum, maximum, p25 and p75 hashes/second",
    },
    wasm: {
      moduleBytes: wasmStats.size,
      directRustDependency: "wasm-bindgen 0.2.127",
      newRegistryCrateCount: 12,
      newRegistryCrates: [
        "bumpalo 3.20.3",
        "cfg-if 1.0.4",
        "once_cell 1.21.4",
        "proc-macro2 1.0.107",
        "quote 1.0.47",
        "rustversion 1.0.23",
        "syn 2.0.119",
        "unicode-ident 1.0.24",
        "wasm-bindgen 0.2.127",
        "wasm-bindgen-macro 0.2.127",
        "wasm-bindgen-macro-support 0.2.127",
        "wasm-bindgen-shared 0.2.127"
      ],
      proofRule: "unchanged proof-core path dependency",
    },
    javascript: {
      permutation: "@noble/hashes 2.3.0 keccakP",
      tuning:
        "pre-absorbed constant rate block; reusable typed arrays; fixed-layout tail absorption; in-place uint256 increment; no allocation per attempt",
    },
    browsers,
  };

  const outputPath = resolve(benchRoot, options.output);
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(`Wrote ${outputPath}`);

  if (!browsers.some((browser) => browser.status === "measured")) {
    process.exitCode = 1;
  }
} finally {
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function runHeadlessBrowser(browserName, specification) {
  const profile = await mkdtemp(join(tmpdir(), `bproof-bench-${browserName}-`));
  const token = randomUUID();
  const resultPromise = waitForResult(token);
  const url = benchmarkUrl(browserName, token);
  const args =
    browserName === "chrome"
      ? [
          "--headless=new",
          "--disable-background-networking",
          "--disable-default-apps",
          "--disable-extensions",
          "--disable-sync",
          "--metrics-recording-only",
          "--no-first-run",
          `--user-data-dir=${profile}`,
          url,
        ]
      : ["--headless", "--no-remote", "--profile", profile, url];
  const child = spawn(specification.executable, args, { stdio: ["ignore", "pipe", "pipe"] });
  const diagnostics = collectDiagnostics(child);

  try {
    const result = await Promise.race([
      resultPromise,
      processExit(child).then((status) => {
        throw new Error(
          `${browserName} exited before reporting (status ${status}): ${diagnostics()}`,
        );
      }),
    ]);
    return result;
  } finally {
    cancelPendingResult(token);
    await terminate(child);
    await removeOwnedProfile(profile);
  }
}

async function runSafari(browserName) {
  const driverPort = 49152 + Math.floor(Math.random() * 10000);
  const driver = spawn("/usr/bin/safaridriver", ["-p", String(driverPort)], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const diagnostics = collectDiagnostics(driver);

  try {
    await waitForWebDriver(driverPort, driver);
    const sessionResponse = await fetch(`http://127.0.0.1:${driverPort}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ capabilities: { alwaysMatch: { browserName: "safari" } } }),
    });
    const sessionBody = await sessionResponse.json();
    if (!sessionResponse.ok || sessionBody.value?.error) {
      throw new Error(
        sessionBody.value?.message ?? `safaridriver session failed: ${sessionResponse.status}`,
      );
    }
    const sessionId = sessionBody.value?.sessionId ?? sessionBody.sessionId;
    if (!sessionId) throw new Error("safaridriver did not return a session id");

    const token = randomUUID();
    const resultPromise = waitForResult(token);
    try {
      const navigateResponse = await fetch(
        `http://127.0.0.1:${driverPort}/session/${sessionId}/url`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url: benchmarkUrl(browserName, token) }),
        },
      );
      if (!navigateResponse.ok) {
        throw new Error(`Safari navigation failed: ${navigateResponse.status}`);
      }
      return await resultPromise;
    } finally {
      cancelPendingResult(token);
      await fetch(`http://127.0.0.1:${driverPort}/session/${sessionId}`, {
        method: "DELETE",
      }).catch(() => {});
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${reason}${diagnostics() ? `: ${diagnostics()}` : ""}`);
  } finally {
    await terminate(driver);
  }
}

async function waitForWebDriver(port, process) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (process.exitCode !== null) throw new Error("safaridriver exited during startup");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/status`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error("safaridriver did not become ready within 10 seconds");
}

function benchmarkUrl(browserName, token) {
  const query = new URLSearchParams({
    browser: browserName,
    token,
    runs: String(options.runs),
    attempts: String(options.attempts),
    warmupAttempts: String(options.warmupAttempts),
  });
  return `${baseUrl}/?${query}`;
}

function waitForResult(token) {
  return new Promise((resolveResult, rejectResult) => {
    const timer = setTimeout(() => {
      pendingResults.delete(token);
      rejectResult(new Error("browser did not report within 10 minutes"));
    }, 10 * 60 * 1000);
    pendingResults.set(token, {
      timer,
      resolve(value) {
        clearTimeout(timer);
        resolveResult(value);
      },
    });
  });
}

function cancelPendingResult(token) {
  const pending = pendingResults.get(token);
  if (!pending) return;
  clearTimeout(pending.timer);
  pendingResults.delete(token);
}

async function handleRequest(request, response) {
  try {
    const url = new URL(request.url ?? "/", baseUrl);
    if (request.method === "POST" && url.pathname === "/__result") {
      const token = url.searchParams.get("token");
      const pending = token ? pendingResults.get(token) : null;
      if (!pending) return send(response, 404, "unknown result token");
      const body = await readBody(request);
      const result = JSON.parse(body);
      pendingResults.delete(token);
      pending.resolve(result);
      return send(response, 204, "");
    }

    if (request.method !== "GET") return send(response, 405, "method not allowed");
    const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
    const filePath = resolve(benchRoot, `.${decodeURIComponent(pathname)}`);
    if (!filePath.startsWith(`${benchRoot}${sep}`)) return send(response, 403, "forbidden");
    const body = await readFile(filePath);
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-type": contentType(filePath),
    });
    response.end(body);
  } catch (error) {
    const code = error?.code === "ENOENT" ? 404 : 500;
    send(response, code, error instanceof Error ? error.message : String(error));
  }
}

function readBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) rejectBody(new Error("result body is too large"));
    });
    request.on("end", () => resolveBody(body));
    request.on("error", rejectBody);
  });
}

function send(response, status, body) {
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8" });
  response.end(body);
}

function contentType(path) {
  return (
    {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".json": "application/json; charset=utf-8",
      ".wasm": "application/wasm",
    }[extname(path)] ?? "application/octet-stream"
  );
}

function commandVersion(specification) {
  const result = spawnSync(specification.executable, specification.versionArgs, {
    encoding: "utf8",
  });
  return `${result.stdout}${result.stderr}`.trim() || "unknown";
}

async function installedVersion(specification) {
  try {
    await access(specification.executable);
    return commandVersion(specification);
  } catch {
    return null;
  }
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

function collectDiagnostics(child) {
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream?.setEncoding("utf8");
    stream?.on("data", (chunk) => {
      output = `${output}${chunk}`.slice(-4000);
    });
  }
  return () => output.trim();
}

function processExit(child) {
  return new Promise((resolveExit) => {
    child.once("exit", (code, signal) => resolveExit(code ?? signal ?? "unknown"));
  });
}

async function terminate(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    processExit(child),
    new Promise((resolveWait) =>
      setTimeout(() => {
        child.kill("SIGKILL");
        resolveWait();
      }, 3000),
    ),
  ]);
}

async function removeOwnedProfile(profile) {
  const prefix = `${tmpdir()}${sep}bproof-bench-`;
  if (!profile.startsWith(prefix)) throw new Error(`refusing to remove unexpected path ${profile}`);
  await rm(profile, { recursive: true, force: true });
}

function parseOptions(args) {
  const values = {
    browsers: ["chrome", "firefox", "safari"],
    runs: 9,
    attempts: 250_000,
    warmupAttempts: 50_000,
    output: "results/latest.json",
  };

  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    const value = args[index + 1];
    if (!value) throw new Error(`${key} requires a value`);
    index += 1;
    if (key === "--browsers") values.browsers = value.split(",");
    else if (key === "--runs") values.runs = parsePositiveInteger(value, key);
    else if (key === "--attempts") values.attempts = parsePositiveInteger(value, key);
    else if (key === "--warmup-attempts") {
      values.warmupAttempts = parsePositiveInteger(value, key);
    } else if (key === "--output") values.output = value;
    else throw new Error(`unknown option ${key}`);
  }
  return values;
}

function parsePositiveInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}
