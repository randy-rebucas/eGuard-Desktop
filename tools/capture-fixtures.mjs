// Captures real responses from a running eGuard server (~/eguard) into fixtures/server/, for the core crate's
// serde and signature tests. Walks the desktop agent's whole wire flow as a test family, then deletes that family.
//
//   node tools/capture-fixtures.mjs            (server at http://localhost:3000, Mailpit at :8025)
//   EGUARD_URL=http://localhost:3217 node tools/capture-fixtures.mjs
//
// Needs ~/eguard's dev database (npm run db:up there) and a dev server, which sends mail only to Mailpit.
import { createRequire } from "node:module";
import { writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const SERVER_REPO = process.env.EGUARD_REPO ?? join(homedir(), "eguard");
const require = createRequire(join(SERVER_REPO, "package.json"));
const { PrismaClient } = require("@prisma/client");
process.loadEnvFile?.(join(SERVER_REPO, ".env"));

const BASE = process.env.EGUARD_URL ?? "http://localhost:3000";
const MAILPIT = process.env.MAILPIT_URL ?? "http://localhost:8025";
const OUT = new URL("../fixtures/server/", import.meta.url);
const RUN = `d${Date.now().toString(36)}`;
const EMAIL = `fixtures.${RUN}@desktop-fixture.example`;
const PASSWORD = "CorrectHorse123!";
const db = new PrismaClient();

mkdirSync(OUT, { recursive: true });
const save = (name, data) => writeFileSync(new URL(name, OUT), JSON.stringify(data, null, 2) + "\n");

async function call(method, path, { token, body } = {}) {
  const headers = { "x-eguard-client": "ios" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const url = path.startsWith("http") ? path : `${BASE}/api/mobile/v1${path}`;
  const res = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const data = (res.headers.get("content-type") ?? "").includes("json") ? await res.json() : null;
  return { status: res.status, data };
}
const expect = (r, status, what) => {
  if (r.status !== status) throw new Error(`${what}: expected ${status}, got ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
};

async function signupCode(to, after) {
  for (let i = 0; i < 50; i++) {
    const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`).then((r) => r.json());
    const msg = (r.messages ?? []).find((m) => Date.parse(m.Created) >= after && /^\d{6} is your eGuard sign-up code$/.test(m.Subject));
    if (msg) return msg.Subject.slice(0, 6);
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no sign-up email reached ${to} (is Mailpit running?)`);
}

try {
  const after = Date.now() - 5000;
  const form = expect(await call("POST", "/auth/register", { body: { name: "Fixture Parent", email: EMAIL, password: PASSWORD, guardian: true } }), 202, "register");
  const reg = expect(await call("POST", "/auth/register/verify", { body: { signup: form.signup, code: await signupCode(EMAIL, after) } }), 201, "verify");
  const token = reg.token;
  await db.user.update({ where: { id: reg.user.id }, data: { emailVerifiedAt: new Date() } });
  await db.family.update({ where: { id: reg.user.family.id }, data: { plan: "eGuard Plus", deviceLimit: 10 } });
  const childId = expect(await call("POST", "/children", { token, body: { name: "Mia", age: 12 } }), 201, "child").id;
  await db.childCategoryLimit.create({ data: { childId, category: "GAMES", dailyLimitMinutes: 60 } });

  const code = expect(await call("POST", `/children/${childId}/pairing-code`, { token }), 201, "pairing code").code;
  const pairBody = { code, platform: "WINDOWS", name: "Mia's Gaming PC", model: "Custom build", osVersion: "Windows 11 24H2", appVersion: "0.1.0" };
  const pair = expect(await call("POST", `${BASE}/api/device/v1/pair`, { body: pairBody }), 201, "pair");
  save("pair-request.json", pairBody);
  save("pair-response.json", pair);
  const pc = (path, body = {}) => call("POST", `${BASE}/api/device/v1${path}`, { token: pair.token, body });

  save("sync-first.json", expect(await pc("/sync", { osVersion: "Windows 11 24H2", appVersion: "0.1.0" }), 200, "first sync"));

  const appsFound = { type: "APPS_FOUND", eventId: "fixture-apps-found-0001", apps: [
    { app: "Counter-Strike 2", ids: [{ kind: "STEAM", value: "730" }], source: "CATALOG", category: "GAMES" },
    { app: "Roblox", ids: [{ kind: "EXE", value: "roblox corporation|roblox" }], source: "CATALOG", category: "GAMES" },
    { app: "Pixel Quest", ids: [{ kind: "EXE", value: "|pixel quest" }], source: "UNKNOWN_PUBLISHER", category: "GAMES" },
  ] };
  save("events-apps-found-request.json", appsFound);
  save("events-apps-found-response.json", expect(await pc("/events", appsFound), 200, "APPS_FOUND"));
  save("events-duplicate-response.json", expect(await pc("/events", appsFound), 200, "APPS_FOUND again"));

  const today = new Date().toISOString().slice(0, 10);
  const usage = { date: today, totalMinutes: 50, apps: [
    { name: "cs2.exe", minutes: 30, ids: [{ kind: "STEAM", value: "730" }] },
    { name: "Counter-Strike 2", minutes: 15, ids: [{ kind: "STEAM", value: "730" }] },
  ], hourly: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,20,30,0,0,0,0,0,0,0] };
  save("usage-request.json", usage);
  save("usage-response.json", expect(await pc("/usage", usage), 200, "usage"));

  const report = { full: true, appVersion: "0.1.0", protections: [
    { key: "SCREEN_TIME", config: { dailyMinutes: 120, weekendMinutes: 180 } },
    { key: "BEDTIME", config: { enabled: true, start: "21:00", end: "07:00", days: "SCHOOL_NIGHTS" } },
    { key: "APP_APPROVAL", config: { enabled: true } },
    { key: "DOWNLOADS", config: { requireApproval: true } },
    { key: "UNINSTALL_PROTECTION", config: { enabled: false }, error: "Your child's account is an administrator." },
    { key: "WEB", config: { mode: "OFF", blockedSites: 0 }, error: "eGuard's extension isn't connected in every browser yet." },
  ] };
  save("report-request.json", report);
  save("report-response.json", expect(await pc("/report", report), 200, "report"));

  const tamper = { type: "TAMPER", kind: "CLOCK_CHANGED", eventId: "fixture-tamper-clock-0001" };
  save("events-tamper-request.json", tamper);
  save("events-tamper-response.json", expect(await pc("/events", tamper), 200, "tamper"));
  save("events-uninstall-ack-409.json", { status: 409, body: expect(await pc("/events", { type: "UNINSTALL_ACK" }), 409, "early ack") });

  save("sync-computer.json", expect(await pc("/sync"), 200, "sync with apps"));

  const catalog = expect(await call("GET", `${BASE}/api/device/v1/catalog`, { token: pair.token }), 200, "catalog");
  save("catalog.json", catalog);
  save("catalog-unchanged.json", expect(await call("GET", `${BASE}/api/device/v1/catalog?since=${catalog.catalog.version}`, { token: pair.token }), 200, "catalog since"));

  expect(await call("DELETE", `/devices/${pair.deviceId}`, { token, body: { password: PASSWORD } }), 200, "remove");
  save("sync-removal.json", expect(await pc("/sync"), 200, "sync while removing"));
  const device = expect(await call("GET", `/devices/${pair.deviceId}`, { token }), 200, "device");
  save("removal-code.json", { deviceId: pair.deviceId, removalSecret: pair.removalSecret, capturedAtMs: Date.now(), removalCode: device.removalCode });

  expect(await call("POST", `/devices/${pair.deviceId}/keep`, { token }), 200, "keep");
  save("sync-kept.json", expect(await pc("/sync"), 200, "sync after keep"));

  // The device is removed for good with a code; afterwards its token is refused
  save("events-uninstall-ack-code-response.json", expect(await pc("/events", { type: "UNINSTALL_ACK", code: device.removalCode.code }), 200, "ack with code"));
  save("sync-401.json", { status: 401, body: expect(await pc("/sync"), 401, "sync after removal") });

  console.log(`captured fixtures for ${EMAIL} into ${OUT.pathname}`);
} finally {
  await db.family.deleteMany({ where: { users: { some: { email: EMAIL } } } });
  await db.signupRequest.deleteMany({ where: { email: EMAIL } });
  await db.$disconnect();
}
