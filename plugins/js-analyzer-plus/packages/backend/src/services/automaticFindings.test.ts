import { describe, expect, it } from "vitest";
import { ALL_ANALYZER_KINDS } from "shared";
import { scanSingleFile } from "../analyzers/runPassiveScan";
import { isAutomaticFinding } from "./automaticFindings";

function scan(content: string) {
  return scanSingleFile({ requestId: "1", url: "https://app.test/main.js", content }, ALL_ANALYZER_KINDS, false);
}

describe("automatic Findings selection", () => {
  it("keeps routes, hardcoded credentials and named cookies from a bundle", () => {
    const matches = scan(`
      const routes = [{path: 'admin', component: Admin}];
      fetch('/api/users');
      const backupPassword = 'correct-horse-battery-staple';
      const email = 'security.person@internal.company';
      document.cookie = 'role=' + role + '; path=/';
      this.cookieService.get('continueCode');
      Cookies.set('sessionMode', 'preview');
    `).filter(isAutomaticFinding);
    for (const value of ['admin', '/api/users', 'backupPassword', 'security.person@internal.company', 'write role', 'get continueCode', 'set sessionMode']) {
      expect(matches.some(m => m.value.includes(value)), value).toBe(true);
    }
    expect(matches.find(m => m.value.includes('get continueCode'))?.context).toContain('not a confirmed vulnerability');
  });

  it("leaves entropy, sinks, generic calls, assets and framework markers for manual scans", () => {
    const all = scan(`
      const hash = 'aK9mZ3xQ7vB2nL5wR8jT4uY1cF6hG0eD';
      element.innerHTML = data;
      window.postMessage(data);
      localStorage.getItem('auth');
      window.__INITIAL_STATE__;
      const asset = '/assets/app.js';
      const contact = 'test@example.com';
    `);
    expect(all.some(m => m.value.startsWith('[High Entropy String]'))).toBe(true);
    expect(all.some(m => m.analyzerKind === 'securitySinks')).toBe(true);
    expect(all.filter(isAutomaticFinding)).toEqual([]);
  });

  it("extracts cookie names from templates and bracket access without reporting unrelated methods", () => {
    const matches = scan('document["cookie"] = `feature=${enabled}`; this.cookieService["set"]("mode", value); cache.set("other", value);').filter(isAutomaticFinding);
    expect(matches.some(m => m.value === '[AST cookie] write feature')).toBe(true);
    expect(matches.some(m => m.value === '[AST cookie] set mode')).toBe(true);
    expect(matches.some(m => m.value.includes('other'))).toBe(false);
  });
});
