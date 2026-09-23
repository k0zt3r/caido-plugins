# JS Analyzer Plus 1.1.5

Local derivative of https://github.com/caido-community/JS-Analyzer at commit
8551df7183c0d132d76232e42e58e5ed8e04463c, merged with our JS Source Analyzer 0.1.1.
Upstream MIT LICENSE is retained unchanged. This is a local fork, not an official Caido release.

The upstream Vue interface, 12 regex analyzers, response viewer, copy/export and Findings actions remain.
Our Acorn-based analyzer supplements them with nested route reconstruction, backtick strings, Angular hash routes,
React Router/Vue/Nuxt route objects, Next.js Pages Router registrations, prefixed password fields and email candidates.
Structural findings carry original source offsets, even when the regex analyzers run on beautified source.
Unlike the standalone plugin, this version uses the upstream response-view/context-menu interface (JS Analysis Plus).
It does not poll and rebuild a sidebar results list, so the earlier 4-second collapse bug does not apply here.

Install dist/plugin_package.zip in Caido. In HTTP History choose JS Analysis Plus in the response viewer,
or select requests → Run JS Analyzer Plus - Passive scan. Disable the original JS Analyzer and our old plugin
if you do not want duplicate analysis. The package and command IDs differ from upstream.

Hardcoded credential Findings include literal values, including passwords, as requested.
Regex findings and response previews may also contain plaintext secrets. Route candidates are not automatically requested or inserted into Sitemap.
No complete reconstruction of server routes, dynamic base paths or Next.js App Router is claimed.
Acorn limits: 6 MiB characters, depth 300, 200 findings per category; JSX/TS use the upstream regex analyzers.

Build: pnpm install --frozen-lockfile; pnpm test; pnpm typecheck; pnpm build.
Keep LICENSE with redistributed source and packages. Acorn is MIT; include its license in the release archive.
Validation: 190 tests passed, backend/shared/frontend typechecks passed, release ZIP built and checked.
Install/runtime inside live Caido has not been tested. Public publishing has not been performed.

## 1.1.1: automatic passive scanning and Findings

Intercepted JS/JSON/source-map responses now run the analyzers directly in the backend,
without waiting for a response-view tab or refetching history. New installations enable
auto scan by default; existing saved settings are preserved. Use the command palette action
`JS Analyzer Plus: Toggle automatic passive scan` to enable a previously disabled installation.
Only traffic passing through Caido is analyzed. Scope and enabled-analyzer settings are respected.
Automatic scans send no network requests and skip empty bodies and bodies above 6 MiB characters.

Automatic and manual request scans save candidates to Findings under `JS Analyzer Plus`.
The response dialog's report buttons use the same URL/category/value deduplication key,
so repeated visits and manual reports do not duplicate the same candidate.
JS MIME types without a file extension and .mjs/.cjs assets are accepted in manual scans too.

Release validation: 196 tests passed, 1 existing test skipped; backend/shared/frontend
TypeScript checks passed; ZIP built. Live Caido runtime validation remains outstanding.

## 1.1.2: focused automatic Findings

Automatic scanning now reports routes/API paths (excluding static assets), named secret
patterns and hardcoded credentials, email/internal IP/debug endpoints, and named cookie
operations. Entropy-only matches, public configuration keys, generic storage/call patterns,
DOM sinks, framework markers, cloud/subdomain hints, dependencies, chunks and source maps
remain available in the full manual scan. Manual scans still report their full results.
Cookie candidates cover document.cookie assignments with a literal name (including template
prefixes), and get/set/put/remove/delete/check on cookie/cookies/cookieService/$cookies receivers.
They are usage candidates, not proof that changing a cookie bypasses authorization.
Minified aliases without recognizable receiver names may not be identified.
Existing Findings are not deleted; this selection applies to future automatic reports.

## 1.1.3: route summaries

AST routes are grouped by source URL and route type in Findings, including Angular hash routes.
One finding contains the count and full sorted list of unique detected paths. Automatic scans,
manual request scans and dialog report actions share this grouping. Individual routes remain
visible in the analysis view. Repeated identical lists deduplicate; a changed route list creates
a new summary because the backend SDK does not expose finding updates. Existing individual
Findings are retained. The analyzer's existing discovery limits still apply.

## 1.1.4: API endpoint summaries and readable lists

API endpoints now produce one summary per source URL. Duplicate AST/regex paths are
merged and sorted. Both route and endpoint summaries show the source URL, unique count
and a complete Markdown bullet list with each path formatted as inline code. Automatic
and manual reporting use the same formatter. Existing Findings are left unchanged.
Validation: 203 tests passed, 1 existing skipped; all three typechecks passed.

## 1.1.5: credential values, conservative pairing and consistent formatting

Hardcoded AST credential fields retain the actual decoded string value, name, line and exact
source range. Findings show passwords/secrets in bold inline code. Login/password pairs are
combined only when exactly one of each shares a lexical container, receiver and field-name
prefix. Ambiguous candidates remain separate; dynamic expressions are not evaluated.
Duplicate email and generic assignment representations of extracted fields are suppressed.

Email addresses, internal IP addresses, named cookie operations and subdomains are grouped
per source URL. The automatic selection policy remains otherwise unchanged. All Findings
share one Markdown formatter for source, value, confidence and location; detected code/data
is displayed literally. Existing Findings are not rewritten.

Validation includes the testingUsername/testingPassword class-field example, object/function
boundaries, receiver separation, ambiguous logins, escaped values, dynamic expressions and
list grouping. Live Caido rendering has not been checked.
