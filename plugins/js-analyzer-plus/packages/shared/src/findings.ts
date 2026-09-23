import type { AnalyzerMatch, CredentialField } from "./scan";

export function findingDedupeKey(url: string, kind: string, value: string): string {
  return `js-analyzer-plus:${JSON.stringify([url, kind, value])}`;
}

export function findingGroup(match: AnalyzerMatch): string | undefined {
  if (match.credential) return `credentials:${match.credential.group}`;
  if (match.analyzerKind === "apiEndpoints") return "API endpoints";
  if (match.analyzerKind === "sensitiveData") {
    if (/^\[(AST email|Email Address)\] /.test(match.value)) return "Email addresses";
    if (/^\[Internal IP[^\]]*\] /.test(match.value)) return "Internal IP addresses";
  }
  if (match.analyzerKind === "callPatterns" && match.value.startsWith("[AST cookie] ")) return "Cookie operations";
  if (match.analyzerKind === "subdomains") return "Subdomains";
  if (match.analyzerKind !== "frameworkPatterns") return undefined;
  return match.value.match(/^\[AST (.+ route)\] /)?.[1];
}

function combineCredentials<T extends AnalyzerMatch>(matches: T[]): T[] {
  const fields = matches.filter(m => m.credential);
  const groups = new Map<string, T[]>();
  for (const match of fields) {
    const key = match.credential!.group;
    groups.set(key, [...(groups.get(key) ?? []), match]);
  }
  const consumed = new Set<T>();
  const pairs: T[] = [];
  for (const group of groups.values()) {
    const passwords = group.filter(m => m.credential!.role === "password");
    const logins = group.filter(m => m.credential!.role === "login");
    if (passwords.length !== 1 || logins.length !== 1) continue;
    const password = passwords[0]!;
    const login = logins[0]!;
    const pair = [login.credential!, password.credential!];
    consumed.add(password); consumed.add(login);
    pairs.push({ ...password, credentialPair: pair,
      value: `[Hardcoded credentials] ${JSON.stringify(pair.map(f => [f.name, f.value]))}` });
  }
  const remaining = matches.filter(match => {
    if (consumed.has(match)) return false;
    if (match.credential) return true;
    // Suppress duplicate representations of the same literal, not unrelated findings.
    const email = match.value.match(/^\[(?:AST email|Email Address)\] (.*)$/)?.[1];
    if (email && fields.some(m => m.credential!.value === email)) return false;
    if (/^\[(?:Password Assignment|Generic API Key Assignment)\]/.test(match.value)) {
      return !fields.some(m => m.credential!.role !== "login" && match.value.endsWith(m.credential!.value));
    }
    return true;
  });
  return [...remaining, ...pairs];
}

// Call per source URL. Sorting keeps repeated response lists stable for deduplication.
export function groupFindings<T extends AnalyzerMatch>(matches: T[]): T[] {
  const groups = new Map<string, T[]>();
  const result: T[] = [];
  for (const match of combineCredentials(matches)) {
    const label = findingGroup(match);
    if (label === undefined || match.credential || match.findingSummary) { result.push(match); continue; }
    groups.set(label, [...(groups.get(label) ?? []), match]);
  }
  for (const [label, group] of groups) {
    const paths = [...new Set(group.map(m => m.value.replace(/^\[[^\]]+\]\s*/, "")))].sort();
    result.push({
      ...group[0]!,
      value: `[${label} summary]\n${paths.join("\n")}`,
      findingSummary: { label, paths },
      context: "Static candidates; requires review.",
    });
  }
  return result;
}

export function groupedFindingTitle(match: AnalyzerMatch): string | undefined {
  if (match.credentialPair) return "JS Analyzer Plus: Hardcoded login and password";
  if (match.credential) return `JS Analyzer Plus: Hardcoded ${match.credential.role} (${match.credential.name})`;
  const summary = match.findingSummary;
  const unit = match.analyzerKind === "apiEndpoints" ? "endpoints"
    : match.analyzerKind === "frameworkPatterns" ? "routes" : "items";
  return summary ? `JS Analyzer Plus: ${summary.label} — ${summary.paths.length} ${unit}` : undefined;
}

function inlineCode(value: string): string {
  const clean = value.replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\t/g, "\\t");
  const runs = clean.match(/`+/g) ?? [];
  const fence = "`".repeat(Math.max(0, ...runs.map(run => run.length)) + 1);
  return `${fence} ${clean} ${fence}`;
}

function fieldLine(field: CredentialField): string {
  const label = field.role === "login" ? "Login" : field.role === "password" ? "Password" : "Secret";
  const value = field.role === "login" ? inlineCode(field.value) : `**${inlineCode(field.value)}**`;
  return `- **${label}** (${inlineCode(field.name)}): ${value} — line ${field.line}, offset ${field.start}`;
}

export function groupedFindingDescription(match: AnalyzerMatch, sourceUrl: string): string | undefined {
  const source = `**Source:** ${inlineCode(sourceUrl)}`;
  if (match.credential) {
    return [source,
      match.credentialPair ? "**Hardcoded login and password**" : "**Hardcoded value**",
      (match.credentialPair ?? [match.credential]).map(fieldLine).join("\n"),
      match.credentialPair
        ? "Associated by lexical container and field-name prefix; validity has not been verified."
        : "Literal value from JavaScript; validity has not been verified.",
    ].join("\n\n");
  }
  const summary = match.findingSummary;
  if (!summary) return undefined;
  return [source,
    `**${summary.label}: ${summary.paths.length}**`,
    summary.paths.map(path => `- ${inlineCode(path)}`).join("\n"),
    match.analyzerKind === "frameworkPatterns" || match.analyzerKind === "apiEndpoints"
      ? "Static candidates from JavaScript; not verified server endpoints."
      : "Static candidates from JavaScript; not confirmed vulnerabilities.",
  ].join("\n\n");
}

export function findingDescription(match: AnalyzerMatch, sourceUrl: string): string {
  const grouped = groupedFindingDescription(match, sourceUrl);
  if (grouped !== undefined) return grouped;
  const parsed = match.value.match(/^\[([^\]]+)\]\s*([\s\S]*)$/);
  const type = parsed?.[1] ?? match.analyzerKind;
  const value = parsed?.[2] || match.value;
  const shown = inlineCode(value);
  return [
    `**Source:** ${inlineCode(sourceUrl)}`,
    `**Type:** ${inlineCode(type)}`,
    `**Value:** ${match.analyzerKind === "secrets" ? `**${shown}**` : shown}`,
    `**Confidence:** ${match.confidence} — candidate, requires review`,
    `**Source offset:** ${match.rawStartOffset ?? match.startOffset}`,
    ...(match.context ? [`**Context:** ${inlineCode(match.context)}`] : []),
  ].join("\n\n");
}
