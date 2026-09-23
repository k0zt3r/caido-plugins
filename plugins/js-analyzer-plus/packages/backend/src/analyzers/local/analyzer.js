import { credentialField } from './credentials.js';
import { parse } from 'acorn';
import { detectFrameworks, propertyName, literalValue, routeAdapter, nextAdapter } from './frameworks.js';

export const MAX_BYTES = 6 * 1024 * 1024;
const redactURL = value => value.replace(/(\/\/)[^/@]+@/, '$1[redacted]@').replace(/([?&][^=&#]+)=([^&#]*)/g, '$1=[redacted]');
export function analyze(source) {
  const result = {frameworks: detectFrameworks(source), items: [], warnings: [], parser: 'acorn', hashRouting: /useHash\s*:\s*(?:true|!0)|createHashRouter|createWebHashHistory|HashRouter/.test(source)};
  const seen = new Set(), counts = new Map();
  const add = (kind, value, offset, analyzer = 'Generic', note = '', credential = undefined) => {
    if (typeof value !== 'string' || !value || value.length > 2000) return;
    const key = kind + ':' + value;
    if (seen.has(key)) return;
    if ((counts.get(kind) || 0) >= 200) { if (!result.warnings.includes('Category limit reached: ' + kind)) result.warnings.push('Category limit reached: ' + kind); return; }
    seen.add(key); counts.set(kind, (counts.get(kind) || 0) + 1);
    result.items.push({kind, value, offset, analyzer, note, credential});
  };
  if (source.length > MAX_BYTES) { result.warnings.push('Source exceeds 6 MiB character limit'); return result; }
  const email = /[A-Z0-9._%+-]{1,64}@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b/gi;
  const emails = (text, offset) => { for (const m of text.matchAll(email)) if (!/[\w.%+@-]/.test(text[m.index - 1] || '') && !/:\/\/[^"'`\s]*$/.test(text.slice(Math.max(0,m.index-500),m.index)) && !m[0].startsWith('.') && !m[0].includes('..')) add('email', m[0], offset + m.index, 'Generic', 'possible username, not a confirmed credential'); };
  emails(source, 0);
  for (const [label, regex] of [
    ['JWT', /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g],
    ['AWS key ID', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
    ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g],
    ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g]
  ]) for (const m of source.matchAll(regex)) add('secret', label + ' [redacted] @' + m.index, m.index, 'Generic', 'candidate; inspect original response');
  const string = (value, offset) => {
    if (typeof value !== 'string' || value.length > 8192) return;
    emails(value, offset);
    if (/^(?:https?|wss?):\/\/[^\s<>]+$/i.test(value)) {
      // URLs may contain passwords/tokens: retain location, omit auth/query values.
      const cleaned = redactURL(value);
      add('url', cleaned, offset);
    }
    if (/^\/(?!\/)[^\s<>]*$/.test(value) && !/^\/(?:\*|\^)/.test(value)) add('path', value.replace(/([?&][^=&#]+)=([^&#]*)/g, '$1=[redacted]'), offset, 'Generic', 'literal path, not a verified endpoint');
    if (/^(?:\.\.?\/|\/)?[^\s<>]+\.(?:m?js|map)(?:\?[^\s]*)?$/.test(value)) add('chunk', value.replace(/\?.*$/, '?[redacted]'), offset);
  };
  let ast;
  try { ast = parse(source, {ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true, allowReturnOutsideFunction: true}); }
  catch (error) {
    result.parser = 'regex fallback';
    result.warnings.push('Syntax not parsed; routes and expressions may be missing. Offset ' + (error.pos ?? '?'));
    for (const m of source.matchAll(/(["'`])((?:\\.|(?!\1)[^\\\r\n]){1,2000})\1/g)) string(m[2], m.index);
    // No source execution, even when parsing fails.
    return result;
  }
  const ctx = {...result, source, add};
  const stack = [{node: ast, ancestors: []}];
  while (stack.length) {
    const {node, ancestors} = stack.pop();
    if (ancestors.length > 300) { if (!result.warnings.includes('AST depth limit reached')) result.warnings.push('AST depth limit reached'); continue; }
    if (node.type === 'Literal' || node.type === 'TemplateLiteral') string(literalValue(node), node.start);
    const credential = credentialField(node, ancestors, source);
    if (credential) add(credential.role === 'login' ? 'login' : 'secret',
      credential.name + ' = ' + credential.value + ' @' + credential.start,
      credential.start, 'Generic', 'hardcoded literal; validity not verified', credential);
    if (node.type === 'AssignmentExpression' && node.operator === '=' &&
        node.left.type === 'MemberExpression' && propertyName(node.left.property) === 'cookie' &&
        /^(?:document|window\.document|globalThis\.document)$/.test(source.slice(node.left.object.start, node.left.object.end))) {
      let rhs = node.right;
      while (rhs.type === 'BinaryExpression' && rhs.operator === '+') rhs = rhs.left;
      const prefix = literalValue(rhs) ?? (rhs.type === 'TemplateLiteral' ? rhs.quasis[0]?.value.cooked : undefined);
      const name = typeof prefix === 'string' ? prefix.match(/^\s*([^=;\s]+)=/)?.[1] : undefined;
      if (name) add('cookie', 'write ' + name, node.start, 'Generic', 'document.cookie assignment; inspect value and flags; not a confirmed vulnerability');
    }
    if (node.type === 'CallExpression') {
      const method = propertyName(node.callee.property || node.callee);
      const receiver = node.callee.object;
      const receiverName = receiver ? propertyName(receiver.property || receiver) : '';
      if (/^(?:cookies?|cookieService|\$cookies)$/i.test(receiverName || '') && /^(?:get|set|put|remove|delete|check)$/.test(method || '')) {
        const name = literalValue(node.arguments[0]);
        if (name) add('cookie', method + ' ' + name, node.start, 'Generic', 'cookie API candidate with a literal name; inspect usage; not a confirmed vulnerability');
      }
      if (/^(?:fetch|get|post|put|patch|delete|head|options)$/.test(method || '') && node.arguments[0]) {
        const arg = node.arguments[0], value = literalValue(arg);
        if (value !== undefined) add('http', method.toUpperCase() + ' ' + redactURL(value), arg.start, 'Generic', 'call candidate; method names can be unrelated to HTTP');
        else if (['BinaryExpression','TemplateLiteral'].includes(arg.type)) add('http-expression', method.toUpperCase() + ' dynamic URL @' + arg.start, arg.start, 'Generic', 'unresolved expression; inspect response at offset');
      }
      if (/^(?:getItem|setItem)$/.test(method || '') && /(?:localStorage|sessionStorage)/.test(source.slice(node.callee.start, node.callee.end))) {
        const key = literalValue(node.arguments[0]);
        if (key && /token|auth|secret|password|email/i.test(key)) add('storage', key, node.start, 'Generic', 'storage key, not credential');
      }
    }
    routeAdapter(node, ancestors, ctx);
    nextAdapter(node, ancestors, ctx);
    const next = [...ancestors, node];
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) { for (let i = value.length - 1; i >= 0; i--) if (value[i]?.type) stack.push({node: value[i], ancestors: next}); }
      else if (value?.type) stack.push({node: value, ancestors: next});
    }
  }
  for (const m of source.matchAll(/[#@]\s*sourceMappingURL\s*=\s*([^\s]+)/g)) add('sourcemap', m[1].startsWith('data:') ? '[inline map]' : m[1], m.index);
  return result;
}
