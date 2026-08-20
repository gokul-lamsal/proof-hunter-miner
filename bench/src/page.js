const query = new URLSearchParams(location.search);
const settings = {
  browserLabel: query.get("browser") ?? "unknown",
  runs: positiveInteger(query.get("runs"), 9),
  attempts: positiveInteger(query.get("attempts"), 250_000),
  warmupAttempts: positiveInteger(query.get("warmupAttempts"), 50_000),
};
const token = query.get("token");
const output = document.querySelector("#output");

if (!token) {
  throw new Error("missing result token");
}

const workerStartedAt = performance.now();
const worker = new Worker("./src/worker.js", { type: "module" });
worker.onmessage = async (event) => {
  const result = {
    ...event.data,
    workerStartToCompletedBenchmarkMs: performance.now() - workerStartedAt,
  };
  output.textContent = JSON.stringify(result, null, 2);
  await fetch(`/__result?token=${encodeURIComponent(token)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(result),
  });
  worker.terminate();
};
worker.onerror = async (event) => {
  const result = {
    ok: false,
    message: event.message,
    filename: event.filename,
    line: event.lineno,
  };
  output.textContent = JSON.stringify(result, null, 2);
  await fetch(`/__result?token=${encodeURIComponent(token)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(result),
  });
};
worker.postMessage(settings);

function positiveInteger(value, fallback) {
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`invalid positive integer: ${value}`);
  }
  return parsed;
}
