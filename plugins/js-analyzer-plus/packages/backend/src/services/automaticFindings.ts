import type { AnalyzerMatch } from "shared";
import { isLikelyFalseEmail } from "../analyzers/patterns/sensitiveDataPatterns";

// Automatic Findings are a short triage list. Manual scans retain every analyzer.
export function isAutomaticFinding(match: AnalyzerMatch): boolean {
  if (match.credential) return true;
  const value = match.value;
  switch (match.analyzerKind) {
    case "secrets":
      return !/^\[(?:High Entropy String|Stripe Publishable Key|Firebase Key|Sentry DSN)\]/.test(value);
    case "apiEndpoints": {
      const path = value.replace(/^\[[^\]]+\]\s*/, "").split(/[?#]/)[0] ?? "";
      return !/\.(?:[cm]?js|css|map|json|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp[34]|webm|pdf|tsx?|jsx|vue|scss|less)$/i.test(path);
    }
    case "frameworkPatterns":
      return /^\[AST .* route\]/.test(value) ||
        /^\[(?:react|angular|vue|express)\] [^:]+: .+/.test(value);
    case "sensitiveData":
      if (value.startsWith("[AST email] ")) {
        return !isLikelyFalseEmail(value.slice("[AST email] ".length));
      }
      return /^\[(?:Email Address|Internal IP[^\]]*|Debug Endpoint|Admin Endpoint|Internal Endpoint|Swagger\/OpenAPI|GraphQL Playground\/Explorer|Actuator\/Health Endpoint)\]/.test(value);
    case "callPatterns":
      return value.startsWith("[AST cookie] ");
    default:
      return false;
  }
}
