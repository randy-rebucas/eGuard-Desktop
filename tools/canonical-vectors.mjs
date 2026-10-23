// Writes fixtures/canonical-vectors.json: inputs and the exact bytes the eGuard server signs for them, made by the same
// algorithm as canonicalJson in ~/eguard/src/lib/browser-policy.ts (keys sorted at every level, then JSON.stringify).
// The Rust canonicalizer must reproduce every output byte for byte.
//
//   node tools/canonical-vectors.mjs
import { writeFileSync } from "node:fs";

function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === "object" && !(v instanceof Date)) {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  }
  return v;
}
const canonicalJson = (v) => JSON.stringify(canonical(v));

// Inputs are JSON text, parsed here as the server's response would be parsed by the agent
const inputs = [
  // The vector the server and the browser extension share
  '{"b":[3,{"z":1,"a":"x"}],"a":null,"c":{"y":true,"x":"é"}}',
  // Key order is UTF-16 code units: "😀" (D83D…) sorts before "！" (FF01), unlike UTF-8 byte order
  '{"！":1,"😀":2,"Z":3,"a":4,"_":5,"":6}',
  // Escapes: quote, backslash, the short forms, other control characters as \\u00xx, nothing else
  '{"s":"q\\"b\\\\s\\/ \\b\\f\\n\\r\\t \\u0000\\u001f\\u007f \\u2028 é ✓ 😀"}',
  // Numbers the way JavaScript prints them
  "[0,-0,1,-1,1.5,0.1,100,1e21,1e-7,0.000001,123456789012345,1792733730702,2.5e-8,1.7976931348623157e308,5e-324,0.30000000000000004,1e300,12.0,-3.25e2]",
  '{"nested":{"deep":{"z":[{"b":1,"a":[]}],"a":{}}},"empty":[]}',
];

const vectors = inputs.map((json) => ({ input: json, output: canonicalJson(JSON.parse(json)) }));
writeFileSync(new URL("../fixtures/canonical-vectors.json", import.meta.url), JSON.stringify(vectors, null, 2) + "\n");
console.log(vectors.map((v) => v.output).join("\n"));
