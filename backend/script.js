import { spawn } from "child_process";
import * as fs from "fs/promises";
import * as path from "path";
import { Buffer } from "buffer";

const defaults = { executable: "/usr/bin/sqlmap", script: "", python: "/usr/bin/python3", concurrency: 2, timeout: 600, findingSource: "owasp" };
// exec replaces this tiny launcher; sqlmap retains the same PID and inherits unbuffered Python I/O.
const UNBUFFERED_LAUNCHER = "import os,sys; os.environ['PYTHONUNBUFFERED']='1'; os.execvp(sys.argv[1],sys.argv[1:])";
const busyStates = ["queued", "starting", "running", "stopping"];
let sdk, root, settings = { ...defaults }, jobs = [], ready, mutation = Promise.resolve();
const runtime = new Map();
const clean = value => JSON.parse(JSON.stringify(value));
const message = error => String(error?.message || error);
// Caido's runtime can omit Node's .code and expose the OS error in .message.
function isMissingFile(error) {
  return error?.code === "ENOENT" ||
    /No such file or directory\s*\(os error 2\)/i.test(message(error));
}
function serialized(fn) {
  const result = mutation.then(fn);
  mutation = result.catch(() => {});
  return result;
}
async function save() {
  await fs.writeFile(path.join(root, "state.json"), JSON.stringify({ settings, jobs }, null, 2), { mode: 0o600 });
}
async function currentProject() {
  const project = await sdk.projects.getCurrent();
  if (!project) throw new Error("Select a Caido project first.");
  return String(project.getId());
}
function options(input = {}) {
  const parameters = String(input.parameters || "").trim();
  if (parameters.length > 1000 || /[\r\n\0]/.test(parameters)) throw new Error("Invalid parameter list");
  return { parameters, profile: input.profile === "cookies" ? "cookies" : "basic" };
}
function snapshot(job) { return clean(job); }
async function initialize() {
  root = path.join(sdk.meta.path(), "sqlmap-manager");
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  try {
    const stored = JSON.parse(await fs.readFile(path.join(root, "state.json"), "utf8"));
    settings = { ...defaults, ...stored.settings };
    jobs = Array.isArray(stored.jobs) ? stored.jobs : [];
    for (const job of jobs) {
      if (busyStates.includes(job.state)) {
        job.state = "interrupted";
        job.error = "Plugin restarted. Previous process state is unknown; inspect its recorded PID before retrying.";
      }
    }
  } catch (error) {
    if (!isMissingFile(error)) throw new Error("Cannot read plugin state: " + message(error));
  }
  await save();
}
function flushLog(job, run) {
  run.writes = run.writes.then(async () => {
    await fs.writeFile(path.join(job.directory, "console.log"), run.diskLog, { mode: 0o600 });
    delete job.logError;
  }).catch(error => { job.logError = message(error); });
  return run.writes;
}
function log(job, text) {
  const run = runtime.get(job.id);
  if (!run) return;
  run.tail = (run.tail + text).slice(-200000);
  job.lastOutput = new Date().toISOString();
  // Keep the on-disk journal bounded too. sqlmap's own output remains separate.
  const remaining = 5000000 - run.bytes;
  if (remaining > 0) {
    const chunk = text.slice(0, remaining);
    run.bytes += chunk.length;
    run.diskLog += chunk;
    // fs.appendFile is absent in some Caido runtimes. Flush bounded snapshots instead.
    if (!run.flushTimer) run.flushTimer = setTimeout(() => {
      run.flushTimer = undefined;
      void flushLog(job, run);
    }, 250);
  }
}
function terminate(job, reason) {
  const run = runtime.get(job.id);
  if (!run?.child) return;
  run.reason = reason;
  job.state = "stopping";
  try { run.child.kill("SIGTERM"); } catch (error) { job.error = message(error); }
  if (!run.killTimer) run.killTimer = setTimeout(() => {
    if (!run.closed) {
      try { run.child.kill("SIGKILL"); } catch (error) { job.error = message(error); }
    }
  }, 3000);
}
function detected(text) {
  // Require sqlmap's final injection-point summary, not a heuristic warning.
  const start = text.search(/sqlmap (?:identified|resumed) the following injection point/i);
  if (start < 0) return "";
  const summary = text.slice(start, start + 16000);
  return /Parameter:\s*.+/.test(summary) && /Type:\s*.+/.test(summary) && /Payload:\s*.+/.test(summary)
    ? summary.split(/\n\[[\d:]+\]/)[0].slice(0, 12000) : "";
}
async function publish(job) {
  if (!job.evidence || job.findingId || job.projectId !== await currentProject()) return;
  const pair = await sdk.requests.get(job.requestId);
  if (!pair?.request) { job.reportError = "Original request is unavailable"; return; }
  try {
    const finding = await sdk.findings.create({
      title: `SQLmap reported SQL injection — ${job.method} ${job.endpoint}`,
      reporter: "SQLmap Manager",
      request: pair.request,
      dedupeKey: `sqlmap-result:${job.key}`,
      description: `SQLmap reported the following injection point. Review its evidence before confirming.\n\n${job.evidence}\n\nTask: ${job.id}\nLog: ${job.directory}/console.log`
    });
    job.findingId = finding.getId();
    job.reportError = undefined;
  } catch (error) { job.reportError = message(error); }
}
async function finish(job, code, signal, error) {
  const run = runtime.get(job.id);
  if (!run || run.closed) return;
  log(job, `\n[Manager] Process exited: code=${code}, signal=${signal || "none"}${error ? ", error=" + message(error) : ""}\n`);
  run.closed = true;
  clearTimeout(run.timer);
  clearTimeout(run.killTimer);
  clearTimeout(run.flushTimer);
  await flushLog(job, run);
  job.exitCode = code;
  job.signal = signal;
  job.finished = new Date().toISOString();
  job.state = run.reason || (error || code !== 0 ? "failed" : "finished");
  if (error) job.error = message(error);
  job.evidence = detected(run.tail);
  job.verdict = job.evidence ? "reported" : "not-confirmed";
  // Report only while the original project is active. Otherwise listTasks retries later.
  try { await publish(job); } catch (error) { job.reportError = message(error); }
  runtime.delete(job.id);
  await serialized(save);
  pump();
}
async function launch(job) {
  try {
    if (job.cancelRequested) { job.state = "cancelled"; await serialized(save); pump(); return; }
    if (job.projectId !== await currentProject()) throw new Error("Project changed before launch; run this task again in its original project.");
    const pair = await sdk.requests.get(job.requestId);
    if (!pair?.request || !sdk.requests.inScope(pair.request)) throw new Error("Request is missing or outside the current Scope.");
    const raw = Buffer.from(pair.request.getRaw().toBytes());
    const header = raw.toString("latin1").split(/\r?\n\r?\n/)[0];
    if (/^X-Caido-SQLmap-Manager:/im.test(header)) throw new Error("Skipping plugin-generated traffic");
    await fs.mkdir(job.directory, { recursive: true, mode: 0o700 });
    await fs.writeFile(path.join(job.directory, "request.txt"), raw, { mode: 0o600 });
    await fs.writeFile(path.join(job.directory, "console.log"), "", { mode: 0o600 });
    const config = job.config;
    const args = config.script ? [config.script] : [];
    args.push("-r", path.join(job.directory, "request.txt"), "--batch", "--disable-coloring",
      "--risk=1", `--level=${job.options.profile === "cookies" ? 2 : 1}`, "--technique=BE",
      "--threads=1", "--delay=0.3", "--timeout=10", "--retries=1", "--ignore-redirects",
      "--ignore-proxy", "--ignore-stdin", "--headers=X-Caido-SQLmap-Manager: 1", `--output-dir=${path.join(job.directory, "output")}`);
    if (pair.request.getTls()) args.push("--force-ssl");
    if (job.options.parameters) args.push("-p", job.options.parameters);
    if (job.cancelRequested) { job.state = "cancelled"; await serialized(save); pump(); return; }
    const run = { tail: "", diskLog: "", bytes: 0, writes: Promise.resolve(), closed: false };
    runtime.set(job.id, run);
    job.started = new Date().toISOString();
    job.state = "running";
    log(job, `[Manager] Starting ${config.executable}\n`);
    // Python disables buffering before exec. No shell expansion; arguments stay separate.
    run.child = spawn(config.python || defaults.python,
      ["-u", "-c", UNBUFFERED_LAUNCHER, config.executable, ...args],
      { stdio: ["ignore", "pipe", "pipe"] });
    job.pid = run.child.pid;
    const receive = chunk => {
      const text = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      log(job, text);
    };
    run.child.stdout?.on("data", receive);
    run.child.stderr?.on("data", receive);
    run.child.stdout?.on("error", error => log(job, `[stdout error] ${message(error)}\n`));
    run.child.stderr?.on("error", error => log(job, `[stderr error] ${message(error)}\n`));
    run.child.stdout?.resume?.();
    run.child.stderr?.resume?.();
    log(job, `[Manager] PID: ${job.pid || "pending"}; stdout/stderr connected; Python buffering disabled.\n`);
    run.child.on("error", error => {
      log(job, `[Manager error] ${message(error)}\n`);
      // A kill error does not mean that a live process has exited.
      if (!run.child.pid) void finish(job, null, null, error).catch(e => sdk.console.error(message(e)));
      else job.error = message(error);
    });
    run.child.on("close", (code, signal) => {
      void finish(job, code, signal, job.error).catch(e => sdk.console.error(message(e)));
    });
    run.timer = setTimeout(() => terminate(job, "timeout"), config.timeout * 1000);
    await serialized(save);
  } catch (error) {
    if (runtime.has(job.id)) await finish(job, null, null, error);
    else {
      job.state = "failed"; job.error = message(error); job.finished = new Date().toISOString();
      await serialized(save); pump();
    }
  }
}
function pump() {
  let active = jobs.filter(j => ["starting", "running", "stopping"].includes(j.state)).length;
  for (const job of jobs) {
    if (active >= settings.concurrency) break;
    if (job.state !== "queued") continue;
    job.state = "starting";
    active++;
    void launch(job).catch(error => sdk.console.error(message(error)));
  }
}
async function submit(requestId, input) {
  const projectId = await currentProject();
  const pair = await sdk.requests.get(String(requestId));
  if (!pair?.request) throw new Error("Saved request not found. Send/save the request in Caido first.");
  const request = pair.request;
  if (!sdk.requests.inScope(request)) throw new Error("Request is outside the current Scope.");
  if (request.getRaw().toBytes().length > 1048576) throw new Error("Request exceeds 1 MiB.");
  const opts = options(input);
  const endpoint = request.getUrl().split("?")[0];
  const key = JSON.stringify([projectId, String(requestId), opts]);
  const existing = jobs.find(j => j.key === key && busyStates.includes(j.state));
  if (existing) return snapshot(existing);
  if (jobs.filter(j => busyStates.includes(j.state)).length >= 20) throw new Error("Queue is full (20 tasks).");
  const id = Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 10);
  const job = { id, projectId, requestId: String(requestId), endpoint, method: request.getMethod(),
    key, options: opts, config: clean(settings), directory: path.join(root, id),
    state: "queued", created: new Date().toISOString(), verdict: "pending" };
  jobs.push(job);
  await save();
  return snapshot(job);
}
function sourceMatches(finding) {
  if (!finding || finding.reporter === "SQLmap Manager") return false;
  const source = String(settings.findingSource || "owasp").trim().toLowerCase();
  return `${finding.reporter || ""} ${finding.title || ""}`.toLowerCase().includes(source);
}
async function listCandidates(after) {
  const projectId = await currentProject();
  if (after !== undefined && after !== null && (typeof after !== "string" || after.length > 2000)) throw new Error("Invalid Findings cursor.");
  const result = await sdk.graphql.execute(`
    query SQLmapCandidateFindings($after: String) {
      findings(first: 100, after: $after, order: {by: CREATED_AT, ordering: DESC}) {
        edges { node { id title reporter description request { id } } }
        pageInfo { hasNextPage endCursor }
      }
    }`, { after: after || null });
  if (result.errors?.length) throw new Error("Findings: " + result.errors.map(e => e.message).join("; "));
  const connection = result.data?.findings;
  if (!connection) throw new Error("Caido returned no Findings connection.");
  const items = [];
  for (const edge of connection.edges || []) {
    const finding = edge.node;
    if (!sourceMatches(finding) || !finding.request?.id) continue;
    const pair = await sdk.requests.get(String(finding.request.id));
    if (!pair?.request) continue;
    const latestJob = jobs.slice().reverse().find(j => j.projectId === projectId && j.requestId === String(finding.request.id));
    items.push({ id: String(finding.id), projectId, requestId: String(finding.request.id),
      title: finding.title, reporter: finding.reporter, description: (finding.description || "").slice(0, 12000),
      endpoint: pair.request.getUrl().split("?")[0], method: pair.request.getMethod(),
      inScope: sdk.requests.inScope(pair.request), taskId: latestJob?.id, taskState: latestJob?.state });
  }
  if (projectId !== await currentProject()) throw new Error("Project changed while reading Findings; refresh the list.");
  return {projectId, items, hasMore: connection.pageInfo.hasNextPage, after: connection.pageInfo.endCursor};
}
export function init(api) {
  sdk = api;
  ready = initialize();
  ready.catch(error => sdk.console.error(message(error)));
  const register = (name, fn) => sdk.api.register(name, async (_sdk, ...args) => { await ready; return fn(...args); });
  register("getSettings", () => clean(settings));
  register("saveSettings", input => serialized(async () => {
    if (!input || typeof input.executable !== "string" || !input.executable.trim() || /[\r\n\0]/.test(input.executable)) throw new Error("Specify the sqlmap executable path.");
    if (typeof input.script !== "string" || /[\r\n\0]/.test(input.script)) throw new Error("Invalid script path.");
    const python = String(input.python || defaults.python).trim();
    if (!python || /[\r\n\0]/.test(python)) throw new Error("Invalid Python path.");
    const findingSource = String(input.findingSource || "owasp").trim();
    if (!findingSource || findingSource.length > 200) throw new Error("Specify a Findings reporter/title filter (up to 200 characters).");
    const concurrency = Number(input.concurrency), timeout = Number(input.timeout);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4 || !Number.isInteger(timeout) || timeout < 10 || timeout > 3600) throw new Error("Concurrency: 1–4; timeout: 10–3600 seconds.");
    settings = { executable: input.executable.trim(), script: input.script.trim(), python, concurrency, timeout, findingSource };
    await save(); return clean(settings);
  }));
  register("submit", async (id, opts) => {
    const result = await serialized(() => submit(id, opts)); pump(); return result;
  });
  register("listCandidates", after => serialized(() => listCandidates(after)));
  register("submitFinding", async (id, input, expectedProject) => {
    const result = await serialized(async () => {
      const projectId = await currentProject();
      if (expectedProject !== projectId) throw new Error("Project changed; refresh the candidate list.");
      const response = await sdk.graphql.execute(`query SQLmapSourceFinding($id: ID!) {
        finding(id: $id) { id title reporter request { id } }
      }`, { id: String(id) });
      if (response.errors?.length) throw new Error(response.errors.map(e => e.message).join("; "));
      const source = response.data?.finding;
      if (!sourceMatches(source) || !source.request?.id) throw new Error("Finding was deleted or no longer matches the source filter.");
      if (projectId !== await currentProject()) throw new Error("Project changed; select the finding again.");
      const task = await submit(source.request.id, input);
      const job = jobs.find(j => j.id === task.id);
      job.sourceFindingId = String(id);
      await save(); return snapshot(job);
    });
    pump(); return result;
  });
  register("listTasks", () => serialized(async () => {
    const projectId = await currentProject();
    const visible = jobs.filter(j => j.projectId === projectId);
    for (const job of visible) if (!busyStates.includes(job.state)) await publish(job);
    await save(); return visible.map(snapshot).reverse();
  }));
  register("getLog", async id => {
    const projectId = await currentProject();
    const job = jobs.find(j => j.id === id && j.projectId === projectId);
    if (!job) throw new Error("Task not found in this project.");
    if (runtime.has(id)) return runtime.get(id).tail;
    try { return String(await fs.readFile(path.join(job.directory, "console.log"), "utf8")).slice(-200000); }
    catch (error) { if (isMissingFile(error)) return job.error || "Waiting for process launch."; throw error; }
  });
  register("stop", id => serialized(async () => {
    const projectId = await currentProject();
    const job = jobs.find(j => j.id === id && j.projectId === projectId);
    if (!job) throw new Error("Task not found.");
    job.cancelRequested = true;
    if (job.state === "queued") job.state = "cancelled";
    else if (job.state === "running") terminate(job, "cancelled");
    await save(); return snapshot(job);
  }));
}
