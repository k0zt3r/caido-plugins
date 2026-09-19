export function init(sdk) {
  const root = document.createElement("div");
  root.className = "sqlmap-manager";
  // Only static markup is inserted as HTML; request and process data use textContent.
  root.innerHTML = `
    <header><h1>SQLmap Manager</h1><span>Запросы · задачи · журнал · Findings</span></header>
    <div class="notice" role="status"></div>
    <details><summary>Настройки запуска</summary><div class="settings">
      <label>Исполняемый файл<input name="executable" value="/usr/bin/sqlmap"></label>
      <label>Путь к sqlmap.py (если запускаешь через Python)<input name="script" placeholder="Оставь пустым для /usr/bin/sqlmap"></label>
      <label>Python для вывода без буферизации<input name="python" value="/usr/bin/python3"></label>
      <label>Источник Findings (часть reporter или заголовка)<input name="findingSource" value="owasp"></label>
      <label>Одновременно<input name="concurrency" type="number" min="1" max="4" value="2"></label>
      <label>Таймаут, секунд<input name="timeout" type="number" min="10" max="3600" value="600"></label>
      <button data-action="save">Сохранить настройки</button>
    </div></details>
    <section class="submit">
      <label>ID сохранённого запроса<input name="requestId" placeholder="Или выбери Send to SQLmap в меню запроса"></label>
      <label>Параметры (-p)<input name="parameters" placeholder="id,search — пусто: выбор sqlmap"></label>
      <label>Профиль<select name="profile"><option value="basic">Базовый · GET / тело</option><option value="cookies">GET / тело / cookies</option></select></label>
      <button data-action="submit">Запустить</button>
      <button data-action="refresh">Обновить</button>
    </section>
    <p class="hint">Запуск вручную, только для запросов в Scope. Установка плагина ничего не сканирует.</p>
    <details class="candidates" open><summary>Кандидаты из Findings</summary>
      <p class="hint">Новые Findings из выбранного источника появляются здесь. Проверка запускается только кнопкой.</p>
      <button data-action="candidates-refresh">Обновить Findings</button>
      <button data-action="candidates-more" disabled>Загрузить более старые</button>
      <div class="candidate-status" role="status"></div><div class="candidate-list"></div>
    </details>
    <div class="workspace"><section class="tasks"><h2>Задачи текущего проекта</h2><div class="task-list"></div></section>
      <section class="output"><h2>Журнал</h2><button data-action="copy-log">Копировать журнал</button><div class="task-info"></div><pre class="log" tabindex="0">Выбери задачу.</pre></section></div>`;
  const field = name => root.querySelector(`[name="${name}"]`);
  const notice = root.querySelector(".notice");
  const list = root.querySelector(".task-list");
  const log = root.querySelector(".log");
  const info = root.querySelector(".task-info");
  let selected, tasks = [], refreshing = false, visible = false;
  let candidateProject, candidateCursor, candidateLoading = false, candidateUpdated = 0;
  let candidates = new Map(), selectedFinding;
  const candidateList = root.querySelector(".candidate-list");
  const candidateStatus = root.querySelector(".candidate-status");
  const moreCandidates = root.querySelector('[data-action="candidates-more"]');
  const say = (text, error = false) => { notice.textContent = text; notice.classList.toggle("error", error); };
  const fail = error => say(String(error?.message || error), true);
  const opts = () => ({parameters: field("parameters").value, profile: field("profile").value});
  const run = fn => async () => { try { await fn(); } catch (error) { fail(error); } };
  const labels = {queued:"В очереди", starting:"Запускается", running:"Работает", stopping:"Останавливается", finished:"Завершено", failed:"Ошибка", timeout:"Таймаут", cancelled:"Остановлено", interrupted:"Прервано перезапуском"};
  async function showLog() {
    if (!selected) return;
    const id = selected;
    const text = await sdk.backend.getLog(id);
    if (selected !== id) return;
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    const display = text || "Процесс ещё не вывел сообщений.";
    // Avoid resetting the selection every time the polling timer fires.
    const selection = window.getSelection();
    const selectingLog = selection && !selection.isCollapsed &&
      (log.contains(selection.anchorNode) || log.contains(selection.focusNode));
    if (log.textContent !== display && !selectingLog) log.textContent = display;
    if (atBottom) log.scrollTop = log.scrollHeight;
    const job = tasks.find(j => j.id === id);
    if (job) info.textContent = [job.directory, job.pid ? `PID: ${job.pid}` : "",
      job.lastOutput ? `Последний вывод: ${job.lastOutput}` : "",
      job.error || "", job.logError ? `Запись журнала: ${job.logError}` : "", job.reportError ? `Findings: ${job.reportError}` : "",
      job.findingId ? `Finding: ${job.findingId}` : "",
      job.verdict === "not-confirmed" ? "Итог: подтверждения в распознанном выводе нет; это не гарантия отсутствия SQLi." : ""].filter(Boolean).join("\n");
  }
  function render() {
    list.replaceChildren();
    if (!tasks.length) { const empty = document.createElement("p"); empty.textContent = "Задач пока нет."; list.append(empty); }
    for (const job of tasks) {
      const row = document.createElement("div"); row.className = "task";
      if (job.id === selected) row.classList.add("selected");
      const select = document.createElement("button"); select.className = "task-select";
      select.textContent = `${labels[job.state] || job.state} · ${job.method} ${job.endpoint}\n${job.id}${job.verdict === "reported" ? " · SQLmap сообщил об SQLi" : ""}`;
      select.onclick = run(async () => { selected = job.id; render(); await showLog(); });
      row.append(select);
      if (["queued","starting","running"].includes(job.state)) {
        const stop = document.createElement("button"); stop.textContent = "Стоп";
        stop.onclick = run(async () => { await sdk.backend.stop(job.id); await refresh(); }); row.append(stop);
      } else if (!["stopping"].includes(job.state)) {
        const retry = document.createElement("button"); retry.textContent = "Повторить";
        retry.onclick = run(async () => { const next = await sdk.backend.submit(job.requestId, job.options); selected = next.id; await refresh(); }); row.append(retry);
      }
      list.append(row);
    }
  }
  function renderCandidates() {
    candidateList.replaceChildren();
    for (const candidate of candidates.values()) {
      const row = document.createElement("div"); row.className = "task";
      const content = document.createElement("div"); content.className = "candidate-content";
      const title = document.createElement("strong"); title.textContent = candidate.title;
      const meta = document.createElement("p");
      const latest = tasks.find(job => job.requestId === candidate.requestId);
      meta.textContent = `${candidate.reporter} · ${candidate.method} ${candidate.endpoint} · ${candidate.inScope ? "In Scope" : "Вне Scope"}${latest ? " · " + (labels[latest.state] || latest.state) : ""}`;
      const details = document.createElement("details"), summary = document.createElement("summary"), description = document.createElement("pre");
      summary.textContent = "Описание Finding"; description.textContent = candidate.description || "Нет описания.";
      details.append(summary, description); content.append(title, meta, details); row.append(content);
      const choose = document.createElement("button"); choose.textContent = "Выбрать";
      choose.onclick = () => {
        field("requestId").value = candidate.requestId;
        field("parameters").value = "";
        selectedFinding = { id: candidate.id, requestId: candidate.requestId, projectId: candidate.projectId };
        say("Кандидат выбран. Настрой параметры выше и нажми «Запустить».");
        root.querySelector(".submit").scrollIntoView({ block: "nearest" });
      };
      const start = document.createElement("button"); start.textContent = "Запустить базовый";
      start.disabled = !candidate.inScope;
      start.onclick = run(async () => {
        const job = await sdk.backend.submitFinding(candidate.id, {profile: "basic", parameters: ""}, candidate.projectId);
        selected = job.id; say(`Задача ${job.id} добавлена из Finding.`); await refresh();
      });
      row.append(choose, start); candidateList.append(row);
    }
    if (!candidates.size) candidateList.textContent = "Подходящих Findings на загруженных страницах пока нет.";
  }
  async function refreshCandidates(older = false) {
    if (candidateLoading) return;
    candidateLoading = true;
    try {
      const page = await sdk.backend.listCandidates(older ? candidateCursor : null);
      if (candidateProject !== page.projectId) {
        candidates = new Map(); selectedFinding = undefined; candidateCursor = undefined;
        candidateProject = page.projectId;
      }
      for (const item of page.items) candidates.set(item.id, item);
      if (older || candidateCursor === undefined) candidateCursor = page.hasMore ? page.after : null;
      moreCandidates.disabled = !candidateCursor;
      candidateUpdated = Date.now();
      candidateStatus.textContent = `Кандидатов загружено: ${candidates.size}. ${page.hasMore ? "Есть более старые Findings." : ""}`;
      renderCandidates();
    } catch (error) {
      candidateStatus.textContent = `Findings: ${String(error?.message || error)}`;
      candidateUpdated = Date.now();
    } finally { candidateLoading = false; }
  }
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      tasks = await sdk.backend.listTasks();
      if (selected && !tasks.some(j => j.id === selected)) { selected = undefined; log.textContent = "Выбери задачу."; info.textContent = ""; }
      render(); renderCandidates(); await showLog();
      if (Date.now() - candidateUpdated > 8000) await refreshCandidates();
    } finally { refreshing = false; }
  }
  root.querySelector('[data-action="save"]').onclick = run(async () => {
    await sdk.backend.saveSettings({ executable: field("executable").value, script: field("script").value,
      python: field("python").value, findingSource: field("findingSource").value,
      concurrency: Number(field("concurrency").value), timeout: Number(field("timeout").value) });
    candidates.clear(); candidateCursor = undefined; selectedFinding = undefined;
    await refreshCandidates();
    say("Настройки сохранены. Они применяются к новым задачам.");
  });
  root.querySelector('[data-action="submit"]').onclick = run(async () => {
    const id = field("requestId").value.trim();
    if (!id) throw new Error("Выбери запрос через контекстное меню или укажи его ID.");
    const job = selectedFinding?.requestId === id
      ? await sdk.backend.submitFinding(selectedFinding.id, opts(), selectedFinding.projectId)
      : await sdk.backend.submit(id, opts());
    selected = job.id;
    say(`Задача ${job.id} добавлена.`); await refresh();
  });
  root.querySelector('[data-action="refresh"]').onclick = run(refresh);
  root.querySelector('[data-action="copy-log"]').onclick = run(async () => {
    const text = log.textContent || "";
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard API unavailable");
      await navigator.clipboard.writeText(text);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.cssText = "position:fixed;left:-9999px;top:0;";
      root.append(area); area.focus(); area.select();
      let copied;
      try { copied = document.execCommand("copy"); } finally { area.remove(); }
      if (!copied) {
        const range = document.createRange(); range.selectNodeContents(log);
        const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
        say("Текст выделен — нажми Ctrl+C."); return;
      }
    }
    say("Журнал скопирован.");
  });
  root.querySelector('[data-action="candidates-refresh"]').onclick = run(async () => {
    if (candidateLoading) return;
    candidates.clear(); candidateCursor = undefined; selectedFinding = undefined;
    await refreshCandidates();
  });
  moreCandidates.onclick = run(() => refreshCandidates(true));
  field("requestId").addEventListener("input", () => { selectedFinding = undefined; });
  sdk.navigation.addPage("/sqlmap-manager", { body: root, onEnter: () => { visible = true; void refresh().catch(fail); } });
  sdk.sidebar.registerItem("SQLmap Manager", "/sqlmap-manager", { icon: "fas fa-database" });
  sdk.navigation.onPageChange(event => { visible = event.path === "/sqlmap-manager"; if (visible) candidateUpdated = 0; });
  sdk.commands.register("sqlmap-manager-send", {
    name: "Send to SQLmap Manager", group: "SQLmap Manager",
    when: context => ["RequestRowContext", "RequestContext", "ResponseContext"].includes(context.type),
    run: async context => {
      const requests = context.type === "RequestRowContext" ? context.requests : [context.request];
      const first = requests?.find(request => request?.id !== undefined);
      if (!first) { say("Сначала сохрани/отправь запрос в Caido.", true); }
      else {
        field("requestId").value = String(first.id);
        selectedFinding = undefined;
        say("Запрос выбран. Укажи параметры и нажми «Запустить»." + (requests.length > 1 ? " Выбран первый из выделенных запросов." : ""));
      }
      sdk.navigation.goTo("/sqlmap-manager");
    }
  });
  for (const type of ["RequestRow", "Request", "Response"]) sdk.menu.registerItem({ type, commandId: "sqlmap-manager-send", leadingIcon: "fas fa-database" });
  void sdk.backend.getSettings().then(config => {
    for (const key of ["executable", "script", "python", "findingSource", "concurrency", "timeout"]) field(key).value = String(config[key]);
  }).catch(fail);
  // Poll only this page; polling reads job state and publishes already obtained evidence.
  setInterval(() => { if (visible && root.isConnected) void refresh().catch(fail); }, 1500);
}
