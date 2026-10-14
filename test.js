'use strict';
const test = require('node:test'), assert = require('node:assert');
const { decide } = require('./decide');
const { SCENARIOS, NOW } = require('./scenarios');
for (const sc of SCENARIOS) test(`${sc.id} ${sc.title} → ${sc.expected}`, () => assert.strictEqual(decide(sc.input, NOW).decision, sc.expected));
test('misma entrada → misma decisión y mismo hash (reproducible)', () => {
  const a = decide(SCENARIOS[3].input, NOW), b = decide(SCENARIOS[3].input, NOW);
  assert.deepStrictEqual(a, b);
});
test('la decisión no modifica la entrada', () => {
  const inp = SCENARIOS[1].input, before = JSON.stringify(inp); decide(inp, NOW); assert.strictEqual(JSON.stringify(inp), before);
});
test('entrada nula → REJECT', () => assert.strictEqual(decide(null, NOW).decision, 'REJECT'));
// --- Ataques encontrados en la revisión de ChatGPT (11-oct-2026). Ninguno debe dar CONTINUE. ---
const { signDecision, verifyDecision } = require('./decide');
const crypto2 = require('crypto');
const mk = f => { const p = JSON.parse(JSON.stringify(SCENARIOS[0].input)); f(p); return p; };
const attacks = [
  ['vencimiento con texto inválido', p => { p.authorization.valid_until = 'mañana'; }],
  ['estado fechado en 2099', p => { p.current_state.observed_at = '2099-01-01T00:00:00Z'; }],
  ['condiciones de la autorización vacías y riesgo actual alto', p => { p.authorization.conditions_at_grant = {}; p.current_state.risk_level = 'high'; }],
  ['falta destino', p => { delete p.action.destination; }],
  ['falta moneda', p => { delete p.action.currency; }],
  ['falta request_id', p => { delete p.request_id; }],
  ['condiciones con booleanos iguales en ambos estados', p => { for (const k of ['approver_status','amount_limit','account_status','risk_level']) { p.authorization.conditions_at_grant[k] = true; p.current_state[k] = true; } }],
  ['estado actual con valor fuera de dominio', p => { p.current_state.risk_level = 'muy bajo'; }],
  ['autorización otorgada en el futuro', p => { p.authorization.granted_at = '2099-01-01T00:00:00Z'; }],
  ['monto infinito', p => { p.action.amount = Infinity; }],
];
for (const [name, f] of attacks) test(`ataque: ${name} → no CONTINUE`, () => assert.notStrictEqual(decide(mk(f), NOW).decision, 'CONTINUE'));

test('hash: distinto monto o destinatario con los mismos IDs → hash distinto', () => {
  const a = decide(SCENARIOS[0].input, NOW);
  const b = decide(mk(p => { p.action.amount = 3999; }), NOW);
  const c = decide(mk(p => { p.action.destination = 'acct-otra'; }), NOW);
  assert.notStrictEqual(a.decision_hash, b.decision_hash);
  assert.notStrictEqual(a.decision_hash, c.decision_hash);
});
test('firma: una decisión alterada y con hash recalculado no verifica', () => {
  const { privateKey, publicKey } = crypto2.generateKeyPairSync('ed25519');
  const rec = decide(SCENARIOS[3].input, NOW), sig = signDecision(rec, privateKey);
  assert.strictEqual(verifyDecision(rec, sig, publicKey), true);
  const forged = JSON.parse(JSON.stringify(rec)); forged.decision = 'CONTINUE';
  const { decision_hash, ...rest } = forged; forged.decision_hash = require('./decide').sha256(require('./decide').canonical(rest));
  assert.strictEqual(verifyDecision(forged, sig, publicKey), false);
});

// --- Escalación v0.3: ataques de la segunda revisión de ChatGPT (11-oct-2026) ---
const { TicketStore, resolveEscalation, signApproval } = require('./escalation');
const kp = () => crypto2.generateKeyPairSync('ed25519');
const officer = kp(), clerk = kp(), stranger = kp();
const REG = {
  'risk-officer-3': { kind: 'human', status: 'active', can_approve_escalations: true, max_amount: 20000, public_key: officer.publicKey },
  'clerk-9': { kind: 'human', status: 'active', can_approve_escalations: false, max_amount: 20000, public_key: clerk.publicKey },
};
function setup(idx = 3) {
  const store = new TicketStore(), inp = SCENARIOS[idx].input, d = decide(inp, NOW);
  const t = store.open(inp, d, NOW); return { store, inp, t };
}
const approve = (t, inp, id, key) => ({ approved: true, approver: id, signature: signApproval(t, inp, id, key) });

test('escalación: aprobación válida (directorio + firma) → nueva autorización → se vuelve a decidir → CONTINUE', () => {
  const { store, inp, t } = setup();
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'risk-officer-3', officer.privateKey), NOW, REG).outcome, 'CONTINUE');
});
test('escalación: nombre inventado declarado "humano", sin estar en el directorio → REJECT', () => {
  const { store, inp, t } = setup();
  const r = resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'cualquiera', stranger.privateKey), NOW, REG);
  assert.strictEqual(r.outcome, 'REJECT'); assert.strictEqual(r.reason, 'APPROVER_NOT_IN_DIRECTORY');
});
test('escalación: persona del directorio sin permiso para aprobar escalaciones → REJECT', () => {
  const { store, inp, t } = setup();
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'clerk-9', clerk.privateKey), NOW, REG).reason, 'APPROVER_LACKS_ESCALATION_AUTHORITY');
});
test('escalación: nombre válido pero firma con otra clave → REJECT', () => {
  const { store, inp, t } = setup();
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'risk-officer-3', stranger.privateKey), NOW, REG).reason, 'APPROVAL_SIGNATURE_INVALID');
});
test('escalación: ticket usado con otra solicitud (otro monto/destino) → REJECT', () => {
  const { store, inp, t } = setup();
  const other = JSON.parse(JSON.stringify(inp)); other.action.destination = 'acct-atacante';
  assert.strictEqual(resolveEscalation(store, t.ticket_id, other, approve(t, other, 'risk-officer-3', officer.privateKey), NOW, REG).reason, 'TICKET_REQUEST_MISMATCH');
});
test('escalación: ticket ya cerrado / reutilizado → REJECT', () => {
  const { store, inp, t } = setup();
  const ok = approve(t, inp, 'risk-officer-3', officer.privateKey);
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, ok, NOW, REG).outcome, 'CONTINUE');
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, ok, NOW, REG).reason, 'TICKET_ALREADY_CLOSED');
});
test('escalación: ticket con fecha límite inválida → REJECT', () => {
  const { store, inp, t } = setup(); store.get(t.ticket_id).deadline = 'pronto';
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'risk-officer-3', officer.privateKey), NOW, REG).reason, 'TICKET_DEADLINE_INVALID');
});
test('escalación: sin respuesta dentro del plazo → REJECT', () => {
  const { store, inp, t } = setup();
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, null, new Date(NOW.getTime() + 901000), REG).reason, 'ESCALATION_TIMEOUT');
});
test('escalación: ticket inexistente → REJECT', () => {
  const { store, inp } = setup();
  assert.strictEqual(resolveEscalation(store, 'no-existe', inp, null, NOW, REG).reason, 'TICKET_NOT_FOUND');
});
test('escalación: "execute_as_human" ya no existe; el ejecutor no cambia y S7 solo pasa con aprobación firmada', () => {
  const { store, inp, t } = setup(6); // S7: agente de IA, irreversible, 8000
  const resp = { ...approve(t, inp, 'risk-officer-3', officer.privateKey), execute_as_human: true };
  const r = resolveEscalation(store, t.ticket_id, inp, resp, NOW, REG);
  assert.strictEqual(r.outcome, 'CONTINUE');
  assert.strictEqual(r.recheck.decision, 'CONTINUE');
});
test('decide(): una "human_approval" escrita en la entrada sin verificador se ignora → sigue ESCALATE', () => {
  const inp = JSON.parse(JSON.stringify(SCENARIOS[6].input));
  inp.authorization.human_approval = { approver: 'risk-officer-3', ticket_id: 'x', request_id: inp.request_id, signature: 'AAAA' };
  assert.strictEqual(decide(inp, NOW).decision, 'ESCALATE');
});
test('escalación: aprobador con tope menor al monto → REJECT', () => {
  const reg = { ...REG, 'risk-officer-3': { ...REG['risk-officer-3'], max_amount: 1000 } };
  const { store, inp, t } = setup();
  assert.strictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'risk-officer-3', officer.privateKey), NOW, reg).reason, 'APPROVER_AMOUNT_EXCEEDED');
});

// --- v0.4: aprobación que tarda (observación de la tercera revisión de ChatGPT) ---
test('aprobación 6 minutos después, con estado actualizado y sin cambios → CONTINUE', () => {
  const { store, inp, t } = setup();
  const later = new Date(NOW.getTime() + 360000);
  const fresh = JSON.parse(JSON.stringify(inp)); fresh.current_state.observed_at = new Date(later.getTime() - 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  assert.strictEqual(resolveEscalation(store, t.ticket_id, fresh, approve(t, fresh, 'risk-officer-3', officer.privateKey), later, REG).outcome, 'CONTINUE');
});
test('aprobación que tarda, pero el estado fresco muestra que el límite bajó por debajo del monto → REJECT', () => {
  const { store, inp, t } = setup();
  const later = new Date(NOW.getTime() + 360000);
  const fresh = JSON.parse(JSON.stringify(inp)); fresh.current_state.observed_at = new Date(later.getTime() - 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  fresh.current_state.amount_limit = 1000;
  assert.strictEqual(resolveEscalation(store, t.ticket_id, fresh, approve(t, fresh, 'risk-officer-3', officer.privateKey), later, REG).outcome, 'REJECT');
});
test('aprobación que tarda sin refrescar el estado → no continúa (estado viejo)', () => {
  const { store, inp, t } = setup();
  const later = new Date(NOW.getTime() + 360000);
  assert.notStrictEqual(resolveEscalation(store, t.ticket_id, inp, approve(t, inp, 'risk-officer-3', officer.privateKey), later, REG).outcome, 'CONTINUE');
});
