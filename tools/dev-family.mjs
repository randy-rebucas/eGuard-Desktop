// A throwaway family on the local eGuard server, for pairing this PC's agent by hand (Phase 2's check).
//
//   node tools/dev-family.mjs create    register a test parent and child; prints a pairing code
//   node tools/dev-family.mjs code      a fresh pairing code for the same child
//   node tools/dev-family.mjs show      the paired computer as the parent's app sees it (device page data)
//   node tools/dev-family.mjs delete    delete the test family and everything in it
//
// Like capture-fixtures.mjs it needs ~/eguard's dev database and a dev server (mail goes to Mailpit). The family's
// login is kept in target/dev-family.json (ignored by git) between commands.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const SERVER_REPO = process.env.EGUARD_REPO ?? join(homedir(), "eguard");
const require = createRequire(join(SERVER_REPO, "package.json"));
const { PrismaClient } = require("@prisma/client");
process.loadEnvFile?.(join(SERVER_REPO, ".env"));

const BASE = process.env.EGUARD_URL ?? "http://localhost:3000";
const MAILPIT = process.env.MAILPIT_URL ?? "http://localhost:8025";
const STATE = new URL("../target/dev-family.json", import.meta.url);
const PASSWORD = "CorrectHorse123!";

async function call(method, path, { token, body } = {}) {
  const headers = { "x-eguard-client": "ios" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(`${BASE}/api/mobile/v1${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const data = (res.headers.get("content-type") ?? "").includes("json") ? await res.json() : null;
  return { status: res.status, data };
}
const expect = (r, status, what) => {
  if (r.status !== status) throw new Error(`${what}: expected ${status}, got ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
};
const load = () => JSON.parse(readFileSync(STATE, "utf8"));

async function signupCode(to, after) {
  for (let i = 0; i < 50; i++) {
    const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`).then((r) => r.json());
    const msg = (r.messages ?? []).find((m) => Date.parse(m.Created) >= after && /^\d{6} is your eGuard sign-up code$/.test(m.Subject));
    if (msg) return msg.Subject.slice(0, 6);
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no sign-up email reached ${to} (is Mailpit running?)`);
}

async function pairingCode({ token, childId }) {
  return expect(await call("POST", `/children/${childId}/pairing-code`, { token }), 201, "pairing code").code;
}

const commands = {
  async create(db) {
    const email = `desktop.${Date.now().toString(36)}@desktop-dev.example`;
    const after = Date.now() - 5000;
    const form = expect(await call("POST", "/auth/register", { body: { name: "Desktop Dev Parent", email, password: PASSWORD, guardian: true } }), 202, "register");
    const reg = expect(await call("POST", "/auth/register/verify", { body: { signup: form.signup, code: await signupCode(email, after) } }), 201, "verify");
    await db.user.update({ where: { id: reg.user.id }, data: { emailVerifiedAt: new Date() } });
    await db.family.update({ where: { id: reg.user.family.id }, data: { plan: "eGuard Plus", deviceLimit: 10 } });
    const childId = expect(await call("POST", "/children", { token: reg.token, body: { name: "Mia", age: 12 } }), 201, "child").id;
    const state = { email, token: reg.token, childId };
    mkdirSync(new URL("../target/", import.meta.url), { recursive: true });
    writeFileSync(STATE, JSON.stringify(state, null, 2));
    console.log(`family for ${email} created; pairing code: ${await pairingCode(state)}`);
  },
  async code() {
    console.log(`pairing code: ${await pairingCode(load())}`);
  },
  async show() {
    const { token } = load();
    const list = expect(await call("GET", "/devices", { token }), 200, "devices");
    const devices = (list.devices ?? list).filter((d) => d.platform === "WINDOWS");
    if (!devices.length) return console.log("no Windows computer paired yet");
    for (const d of devices) console.log(JSON.stringify(expect(await call("GET", `/devices/${d.id}`, { token }), 200, "device"), null, 2));
  },
  async delete(db) {
    const { email } = load();
    await db.family.deleteMany({ where: { users: { some: { email } } } });
    await db.signupRequest.deleteMany({ where: { email } });
    rmSync(STATE);
    console.log(`deleted the family for ${email}`);
  },
};

const run = commands[process.argv[2]];
if (!run) {
  console.error("usage: node tools/dev-family.mjs create | code | show | delete");
  process.exit(1);
}
const db = new PrismaClient();
try {
  await run(db);
} finally {
  await db.$disconnect();
}
