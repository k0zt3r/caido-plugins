# JS Analyzer Plus 1.1.1

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

Our structural secret findings mask values. Upstream regex findings and response previews may contain plaintext secrets,
as in the original plugin. Route candidates are not automatically requested or inserted into Sitemap.
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
