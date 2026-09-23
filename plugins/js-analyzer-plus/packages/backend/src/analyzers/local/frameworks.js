// Detection enables annotations, never gates generic analysis.
export const adapters = [
  {name: 'Angular', detect: s => /ɵ(?:cmp|fac|prov)|@angular\//.test(s)},
  {name: 'Next.js', detect: s => /__NEXT_DATA__|__NEXT_P|__BUILD_MANIFEST|next\/dist|\/_next\//.test(s)},
  {name: 'Nuxt', detect: s => /__NUXT__|__NUXT_DATA__|\/_nuxt\/|defineNuxt/.test(s)},
  {name: 'React Router', detect: s => /react-router|createBrowserRouter|createHashRouter|BrowserRouter|HashRouter/.test(s)},
  {name: 'React', detect: s => /react\.production|react\.element|react\.transitional\.element|react\/jsx-runtime|React\.createElement/.test(s)},
  {name: 'Vue Router', detect: s => /vue-router|createWebHistory|createWebHashHistory/.test(s)},
  {name: 'Vue', detect: s => /__v_isVNode|__VUE__|createVNode|defineComponent|vue\/dist/.test(s)}
];

export function detectFrameworks(source) {
  return adapters.filter(a => a.detect(source)).map(a => a.name);
}

export function propertyName(node) {
  if (!node) return undefined;
  return node.type === 'Identifier' ? node.name : node.type === 'Literal' ? String(node.value) : undefined;
}

export function literalValue(node, depth = 0) {
  if (!node || depth > 16) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const a = literalValue(node.left, depth + 1), b = literalValue(node.right, depth + 1);
    if (a !== undefined && b !== undefined && a.length + b.length < 8192) return a + b;
  }
  return undefined;
}

export function routeAdapter(node, ancestors, ctx) {
  if (node.type !== 'ObjectExpression') return;
  const prop = (obj, name) => obj.properties.find(p => propertyName(p.key) === name);
  const path = prop(node, 'path');
  if (!path) return;
  const fragment = literalValue(path.value);
  if (fragment === undefined) return;
  // A random object's path isn't necessarily a frontend route.
  if (!['component','components','element','Component','loadComponent','loadChildren','children','redirect','redirectTo','loader','lazy'].some(k => prop(node, k))) return;
  let route = fragment;
  let child = node;
  for (let i = ancestors.length - 1; i >= 0 && !route.startsWith('/'); i--) {
    const parent = ancestors[i];
    if (parent.type === 'ObjectExpression') {
      const children = prop(parent, 'children');
      // Only join literal nested children; don't guess through references.
      if (children && children.value.start <= child.start && children.value.end >= child.end) {
        const base = literalValue(prop(parent, 'path')?.value);
        if (base !== undefined) route = base.replace(/\/$/, '') + '/' + route;
      }
      child = parent;
    }
  }
  route = '/' + route.replace(/^\/+/, '');
  const framework = ctx.frameworks.find(f => ['Angular','Next.js','Nuxt','React Router','Vue Router'].includes(f)) || 'Router config';
  ctx.add('route', route, path.value.start, framework, ctx.hashRouting ? 'hash route; base path unknown' : 'route template; base path unknown');
}

export function nextAdapter(node, ancestors, ctx) {
  if (!ctx.frameworks.includes('Next.js')) return;
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && propertyName(node.callee.property) === 'push') {
    const owner = node.callee.object.type === 'AssignmentExpression' ? node.callee.object.left : node.callee.object;
    if (propertyName(owner.property || owner) === '__NEXT_P') {
      const route = literalValue(node.arguments[0]?.elements?.[0]);
      if (route) ctx.add('route', route, node.start, 'Next.js', 'Pages Router registration');
    }
  }
  if (node.type === 'Property') {
    const key = propertyName(node.key);
    const assignment = [...ancestors].reverse().find(n => n.type === 'AssignmentExpression');
    if (key?.startsWith('/') && assignment && ctx.source.slice(assignment.left.start, assignment.left.end).endsWith('__BUILD_MANIFEST')) {
      ctx.add('route', key, node.start, 'Next.js', 'build manifest route');
    }
  }
}
