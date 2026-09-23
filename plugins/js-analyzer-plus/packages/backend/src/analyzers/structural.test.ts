import { readFileSync, existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { mapBeautifiedOffsetsToRaw } from "../services/offsetMapper";
import { scanSingleFile } from "./runPassiveScan";
import { analyzeStructural } from "./structural";

describe("merged structural analysis", () => {
  const source = 'C.ɵcmp=x;let cfg={useHash:!0};let r=[{path:`privacy`,component:A,children:[{path:`policy`,component:B}]}];let testingUsername=`testing@juice-sh.op`;let testingPassword=`IamUsedForTesting`;';
  it("preserves nested Angular hash routes and original offsets", () => {
    const results = scanSingleFile({content:source,url:"http://localhost/main.js",requestId:"1"},["frameworkPatterns"],true);
    const route = results.find(m => m.value.endsWith("#/privacy/policy"));
    expect(route).toBeDefined();
    expect(source.slice(route!.rawStartOffset,route!.rawEndOffset)).toBe('`policy`');
    expect(mapBeautifiedOffsetsToRaw(source,[route!])[0]).toEqual(route);
  });
  it("finds prefixed credentials with their literal values and email", () => {
    const r=analyzeStructural(source,["secrets","sensitiveData"]);
    expect(r.some(m=>m.value.includes("testingPassword"))).toBe(true);
    expect(r.some(m=>m.value.includes("testing@juice-sh.op"))).toBe(true);
    expect(r.find(m => m.credential?.name === "testingPassword")?.credential?.value).toBe("IamUsedForTesting");
  });
  it("covers React Router, Vue/Nuxt, and Next.js Pages Router", () => {
    for(const source of [
      'createBrowserRouter([{path:"/a",Component:X,children:[{path:"b",element:Y}]}]);',
      '__NUXT__;createWebHistory();const r=[{path:"/a",component:X,children:[{path:"b",component:Y}]}];',
    ]) expect(analyzeStructural(source,["frameworkPatterns"]).some(m=>m.value.endsWith("/a/b"))).toBe(true);
    expect(analyzeStructural('(self.__NEXT_P=self.__NEXT_P||[]).push(["/a/[id]",()=>{}]);',["frameworkPatterns"]).some(m=>m.value.endsWith("/a/[id]"))).toBe(true);
  });
  it("retains upstream analyzers and JSX regex fallback", () => {
    const content='<Route path="/dashboard" element={<Dashboard/>}/>;eval(input);';
    const r=scanSingleFile({content,url:"http://localhost/a.js",requestId:"1"},["frameworkPatterns","securitySinks"],false);
    expect(r.some(m=>m.value.includes("/dashboard"))).toBe(true);
    expect(r.some(m=>m.analyzerKind==="securitySinks")).toBe(true);
  });
  it("honors selected analyzer kinds", () => expect(analyzeStructural(source,["cloudUrls"])).toEqual([]));
  it.skipIf(!existsSync("/tmp/caido-source-main.js"))("handles actual minified main.js", () => {
    const r=analyzeStructural(readFileSync("/tmp/caido-source-main.js","utf8"),["frameworkPatterns","secrets","sensitiveData"]);
    expect(r.some(m=>m.value.endsWith("#/privacy-security/privacy-policy"))).toBe(true);
    expect(r.some(m=>m.value.includes("testingPassword"))).toBe(true);
  });
});
