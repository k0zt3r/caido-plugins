import { describe, expect, it } from "vitest";
import { ALL_ANALYZER_KINDS, findingDescription, groupFindings, groupedFindingTitle } from "shared";
import { scanSingleFile } from "../analyzers/runPassiveScan";
import { isAutomaticFinding } from "./automaticFindings";

function findings(content: string) {
  return groupFindings(scanSingleFile({ content, requestId: '1', url: 'https://app.test/main.js' }, ALL_ANALYZER_KINDS, false).filter(isAutomaticFinding));
}

describe('hardcoded credential Findings', () => {
  it('pairs the Juice Shop class fields and displays the actual password in bold', () => {
    const source = 'class Login {\n testingUsername = `testing@juice-sh.op`;\n testingPassword = `IamUsedForTesting`;\n ngOnInit() {}\n}';
    const matches = findings(source);
    expect(matches).toHaveLength(1);
    const pair = matches[0]!;
    expect(groupedFindingTitle(pair)).toContain('login and password');
    const description = findingDescription(pair, 'https://app.test/main.js');
    expect(description).toContain('testingUsername');
    expect(description).toContain('testing@juice-sh.op');
    expect(description).toContain('testingPassword');
    expect(description).toContain('**` IamUsedForTesting `**');
    expect(description).toContain('line 3');
    expect(source.slice(pair.credential!.start, pair.credential!.end)).toBe('`IamUsedForTesting`');
  });

  it.each([
    'const x = {username:"alice", password:"local-password-value"};',
    'const testingUsername = "alice", testingPassword = "local-password-value";',
    'function f() { this.username = "alice"; this.password = "local-password-value"; }',
  ])('pairs literal credentials: %s', source => {
    const result = findings(source);
    expect(result.filter(m => m.credentialPair)).toHaveLength(1);
    expect(result.filter(m => m.credential)).toHaveLength(1);
  });

  it.each([
    'const a={username:"alice"};const b={password:"local-password-value"};',
    'let adminUsername="alice";let testingPassword="local-password-value";',
    'function a(){let username="alice";} function b(){let password="local-password-value";}',
    'a.username="alice";b.password="local-password-value";',
    'let username="alice";let email="alice@company.internal";let password="local-password-value";',
    'class C { static username="alice";password="local-password-value"; }',
  ])('does not invent a pair across scopes, owners or ambiguous logins: %s', source => {
    expect(findings(source).some(m => m.credentialPair)).toBe(false);
  });

  it('does not evaluate dynamic values and preserves decoded literal values', () => {
    const matches = findings('const username="alice";const password=getPassword();const apiKey="abc"+"def";');
    expect(matches.some(m => m.credential?.name === 'password')).toBe(false);
    expect(matches.find(m => m.credential?.name === 'apiKey')?.credential?.value).toBe('abcdef');
  });

  it('keeps Markdown-looking credential data literal', () => {
    const match = findings('const password="a`**<tag>**\\nend";').find(m => m.credential)!;
    const description = findingDescription(match, 'https://app.test/main.js');
    expect(description).toContain('**`` a`**<tag>**\\nend ``**');
  });

  it('groups independent emails, internal IPs and cookie operations', () => {
    const matches = findings(`
      const contacts=['alice@corp.internal','bob@corp.internal'];
      const hosts=['10.1.2.3','192.168.1.4'];
      Cookies.get('mode');Cookies.set('mode','preview');
    `);
    expect(matches.find(m => m.findingSummary?.label === 'Email addresses')?.findingSummary?.paths).toHaveLength(2);
    expect(matches.find(m => m.findingSummary?.label === 'Internal IP addresses')?.findingSummary?.paths).toHaveLength(2);
    expect(matches.find(m => m.findingSummary?.label === 'Cookie operations')?.findingSummary?.paths).toHaveLength(2);
  });
});
