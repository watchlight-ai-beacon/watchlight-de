// Strip PII from a document's text before an agent reads it.
//
// Real usage: extract text from the document first (PDF/docx → text), then
// sanitize — never hand the agent the original file (its hidden layers leak).
//
//   import { govern } from "@watchlight/sdk";
//   const text = await extractPdfText("statement.pdf");   // your extractor
//   const { text: safe, report } = govern.sanitize(text, { resource: "statement.pdf" });
//   await agent.read(safe);   // the agent sees <ACCOUNT_1>, not the real number
//
// This script uses inline text so it runs offline.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { govern } = require("@watchlight/sdk");

const statement = `
ACME BANK — Statement
Account holder: contact jane.doe@example.com
Card on file: 4111 1111 1111 1111
SSN: 123-45-6789   Phone: (415) 555-0132
`;

const { text, report } = govern.sanitize(statement, { intent: "read", resource: "statement.pdf" });

console.log("=== what the agent sees ===");
console.log(text.trim());
console.log("\n=== value-free report (safe to log/audit) ===");
console.log(JSON.stringify(report));
console.log("\nThe agent never saw the real email, card, SSN, or phone — and the audit records only counts.");
