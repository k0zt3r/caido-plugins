import { literalValue, propertyName } from './frameworks.js';

// Associate fields only inside the same lexical container, receiver and name prefix.
// A literal is read from the AST; expressions with runtime values are never executed.
export function credentialField(node, ancestors, source) {
  let name, valueNode, owner = '';
  if (node.type === 'Property' || node.type === 'PropertyDefinition') {
    if (node.computed && node.key.type !== 'Literal') return;
    name = propertyName(node.key); valueNode = node.value;
    if (node.static) owner = 'static';
  } else if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
    name = node.id.name; valueNode = node.init;
  } else if (node.type === 'AssignmentExpression' && node.operator === '=') {
    if (node.left.type === 'MemberExpression') {
      if (node.left.computed && node.left.property.type !== 'Literal') return;
      owner = source.slice(node.left.object.start, node.left.object.end);
    }
    name = propertyName(node.left.property || node.left); valueNode = node.right;
  } else return;
  const suffix = name?.match(/(password|passwd|username|user|login|email|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)$/i);
  const value = literalValue(valueNode);
  if (!suffix || typeof value !== 'string' || !value || value.length > 8192) return;
  const role = /^(password|passwd)$/i.test(suffix[1]) ? 'password'
    : /^(username|user|login|email)$/i.test(suffix[1]) ? 'login' : 'secret';
  const container = [...ancestors].reverse().find(n =>
    ['ObjectExpression', 'ClassBody', 'BlockStatement', 'Program'].includes(n.type));
  const prefix = name.slice(0, -suffix[1].length).replace(/[_-]+$/, '').toLowerCase();
  return { name, value, role, group: `${container?.start ?? 0}:${owner}:${prefix}`,
    start: valueNode.start, end: valueNode.end,
    line: source.slice(0, valueNode.start).split('\n').length };
}
