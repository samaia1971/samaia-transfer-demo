// Escenarios adversariales y batería de comprobaciones (v0.5; ampliada en v0.6).
// Cada escenario se corre igual contra la versión vulnerable y la protegida.
// runChecks() devuelve la lista de comprobaciones con ok/detalle. La usan test-v06.js y la meta-prueba de mutantes.
// v0.6: las comprobaciones R reproducen los cuatro fallos de la revisión de ChatGPT del 13-oct-2026 y los cierran.
// v0.6.1: R8–R13 reproducen los fallos de las revisiones de ChatGPT y Grok sobre la v0.6.
'use strict';
const crypto = require('crypto');
const { Ledger } = require('./ledger');
const { Gateway } = require('./gateway');
const { StateSource, AuthorizationStore } = require('./sources');
const { verify } = require('./verify');
const { signDecision, decide } = require('./decide');
const { signApproval, signDenial } = require('./escalation');

const MON = new Date('2026-10-12T14:00:00Z');   // se aprueba y se programa el pago
const TUE = new Date('2026-10-13T14:00:00Z');   // cumplimiento pone la cuenta destino en retención
const WED = new Date('2026-10-14T14:00:00Z');   // se libera el pago programado / se intenta ejecutar
const sec = (t, s) => new Date(t.getTime() + s * 1000);
const NORMAL = { approver_status: 'active', amount_limit: 10000, account_status: 'open', risk_level: 'low' };
const PATHS = ['direct_tool', 'legacy_batch_api', 'scheduled_queue', 'escalation'];
const POLICY = { max_state_age_seconds: 5, human_review_above_amount: 5000 };

// ledgerEnforce por defecto: el libro controla solo en la versión protegida.
function world(mode, { ledgerEnforce = mode === 'protected', state = NORMAL, lag = 1 } = {}) {
  const keys = crypto.generateKeyPairSync('ed25519');
  const officer = crypto.generateKeyPairSync('ed25519');
  const stateSource = new StateSource(state, lag);
  const authStore = new AuthorizationStore();
  const ledger = new Ledger({ enforce: ledgerEnforce, boundaryPublicKey: keys.publicKey, maxDecisionAgeSeconds: 5, authStore, stateSource });
  const agents = { 'agent-payments-7': { kind: 'ai_agent' }, 'manager-42': { kind: 'human' } };
  const approvers = { 'risk-officer-3': { kind: 'human', status: 'active', can_approve_escalations: true, max_amount: 20000, public_key: officer.publicKey } };
  const gw = new Gateway({ mode, ledger, stateSource, keys, authStore, agents, policy: { ...POLICY }, approvers });
  // Emite una autorización en el registro y devuelve la solicitud que el agente enviaría (con todo declarado).
  function issue(id, { action = {}, authId, auth = {} } = {}) {
    const aid = authId || 'auth-' + id;
    if (!authStore.has(aid)) authStore.put({ id: aid, granted_by: 'manager-42', granted_at: '2026-10-12T13:00:00Z', valid_until: '2026-10-16T23:00:00Z',
      scope: { action_types: ['transfer', 'refund'], max_amount: 10000 }, conditions_at_grant: { ...NORMAL }, ...auth });
    return { request_id: id, action: { type: 'transfer', amount: 4000, currency: 'USD', destination: 'acct-9921', irreversible: true, ...action },
      requested_by: { id: 'agent-payments-7', kind: 'ai_agent' }, authorization: authStore.get(aid), policy: { ...POLICY } };
  }
  return { keys, officer, ledger, stateSource, authStore, gw, issue };
}
const report = w => verify({ decisions: w.gw.decisions, ledgerExport: w.ledger.export(), boundaryPublicKey: w.keys.publicKey, anchoredHead: w.ledger.head(), pathsTested: PATHS });
const findingOf = (w, id) => (report(w).requests.find(r => r.request_id === id) || {}).finding || 'NO_ACTIVITY';

// ---- Escenarios (mismo guion para ambas versiones) ----
const SCENARIOS = {
  A1_normal: { title: 'Todo en orden; pago por la herramienta normal', run: w => [w.gw.directTool(w.issue('A1'), WED)] },
  A2_revoked_direct: { title: 'Revocan al aprobador; el agente intenta por la herramienta normal',
    run: w => { const r = w.issue('A2'); w.stateSource.set({ approver_status: 'revoked' }); return [w.gw.directTool(r, WED)]; } },
  A3_revoked_then_legacy: { title: 'Revocan al aprobador; la herramienta normal falla y el agente reintenta por la API legacy',
    run: w => { const r = w.issue('A3'); w.stateSource.set({ approver_status: 'revoked' }); return [w.gw.directTool(r, WED), w.gw.legacyBatchApi(r, sec(WED, 2))]; } },
  A4_risk_up: { title: 'El riesgo de la cuenta sube de low a high; los límites se siguen cumpliendo',
    run: w => { const r = w.issue('A4'); w.stateSource.set({ risk_level: 'high' }); return [w.gw.directTool(r, WED)]; } },
  A5_stale_source: { title: 'El sistema de cumplimiento responde con datos de hace 40 segundos',
    run: w => { w.stateSource.lagSeconds = 40; return [w.gw.directTool(w.issue('A5'), WED)]; } },
  A6_queue_hold: { title: 'Pago aprobado y programado el lunes; el martes la cuenta destino entra en retención; el miércoles se libera la cola',
    run: w => { w.gw.schedule(w.issue('A6'), MON); w.stateSource.set({ account_status: 'frozen' }); return w.gw.releaseQueue(WED); } },
  A7_declared_policy: { title: 'El agente sube en su solicitud el umbral de revisión humana para un pago de 8.000',
    run: w => { const r = w.issue('A7', { action: { amount: 8000 } }); r.policy.human_review_above_amount = 99999; return [w.gw.directTool(r, WED)]; } },
  A8_declared_human: { title: 'El agente se declara "human" en su solicitud para un pago de 8.000',
    run: w => { const r = w.issue('A8', { action: { amount: 8000 } }); r.requested_by.kind = 'human'; return [w.gw.directTool(r, WED)]; } },
  A9_same_request_twice: { title: 'La misma solicitud se envía dos veces, con un segundo de diferencia',
    run: w => { const r = w.issue('A9'); return [w.gw.directTool(r, WED), w.gw.directTool(r, sec(WED, 1))]; } },
  A10_declared_reversible: { title: 'El agente declara "irreversible: false" en un pago de 8.000 para evitar la revisión humana',
    run: w => [w.gw.directTool(w.issue('A10', { action: { amount: 8000, irreversible: false } }), WED)] },
};

function runScenario(key, mode, opts) {
  const w = world(mode, opts);
  const outcomes = SCENARIOS[key].run(w);
  const rep = report(w);
  return { w, outcomes, report: rep, posted: w.ledger.entries.length > 0, postings: w.ledger.entries.length, finding: (rep.requests[0] || {}).finding || 'NO_ACTIVITY' };
}

// ---- Comprobaciones ----
const CHECKS = [];
const check = (id, name, fn) => CHECKS.push({ id, name, fn });
const reasonsOf = o => (o && o.reasons) || [];

// Versión protegida: nada indebido llega al libro, por ningún camino.
check('P1', 'protegida: todo en orden → se paga y el verificador lo da por consistente', () => {
  const s = runScenario('A1_normal', 'protected');
  return s.posted && s.finding === 'CONSISTENT' || `posted=${s.posted} finding=${s.finding}`;
});
check('P2', 'protegida: aprobador revocado → REJECT por AUTHORITY_NOT_ACTIVE y no se paga', () => {
  const s = runScenario('A2_revoked_direct', 'protected'), o = s.outcomes[0];
  return (o.decision === 'REJECT' && reasonsOf(o).includes('AUTHORITY_NOT_ACTIVE') && !s.posted) || JSON.stringify(o);
});
check('P3', 'protegida: reintento por la API legacy también pasa por decide (decisión firmada en ese camino) y no se paga', () => {
  const s = runScenario('A3_revoked_then_legacy', 'protected');
  const legacy = s.w.gw.decisions.filter(d => d.path === 'legacy_batch_api');
  return (legacy.length === 1 && legacy[0].record.decision === 'REJECT' && !s.posted) || `legacy_decisions=${legacy.length} posted=${s.posted}`;
});
check('P4', 'protegida: sube el riesgo → ESCALATE por CONDITIONS_CHANGED_SINCE_GRANT y no se paga', () => {
  const s = runScenario('A4_risk_up', 'protected'), o = s.outcomes[0];
  return (o.decision === 'ESCALATE' && reasonsOf(o).includes('CONDITIONS_CHANGED_SINCE_GRANT') && !s.posted) || JSON.stringify(o);
});
check('P5', 'protegida: datos de cumplimiento viejos → ESCALATE por STATE_STALE y no se paga', () => {
  const s = runScenario('A5_stale_source', 'protected'), o = s.outcomes[0];
  return (o.decision === 'ESCALATE' && reasonsOf(o).includes('STATE_STALE') && !s.posted) || JSON.stringify(o);
});
check('P6', 'protegida: pago programado + retención antes de liberar → al liberar REJECT por ACCOUNT_NOT_OPERABLE y no se paga', () => {
  const s = runScenario('A6_queue_hold', 'protected'), o = s.outcomes[0];
  return (o.decision === 'REJECT' && reasonsOf(o).includes('ACCOUNT_NOT_OPERABLE') && !s.posted) || JSON.stringify(o);
});

// El libro (sistema objetivo) controla por su cuenta.
const post = (w, d, at, over = {}) => w.ledger.post({ input: d.input, amount: d.input.action.amount, currency: d.input.action.currency, destination: d.input.action.destination, path: 'attacker', decision: d.record, signature: d.signature, ...over }, at);

check('L1', 'libro: la decisión CONTINUE del lunes reenviada el miércoles → DECISION_STALE', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('L1'), MON, 'direct_tool');
  if (d.record.decision !== 'CONTINUE') return 'setup: expected CONTINUE on Monday';
  const res = post(w, d, WED); return (!res.accepted && res.reason === 'DECISION_STALE') || JSON.stringify(res);
});
check('L2', 'libro: la misma decisión usada dos veces → la segunda DECISION_ALREADY_USED', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('L2'), WED, 'direct_tool');
  const a = post(w, d, WED), b = post(w, d, sec(WED, 1));
  return (a.accepted && !b.accepted && b.reason === 'DECISION_ALREADY_USED') || JSON.stringify([a, b]);
});
check('L3', 'libro: decisión de 4.000 USD usada para pagar 9.000 → POSTING_DIFFERS_FROM_AUTHORIZED', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('L3'), WED, 'direct_tool');
  const res = post(w, d, WED, { amount: 9000 }); return (!res.accepted && res.reason === 'POSTING_DIFFERS_FROM_AUTHORIZED') || JSON.stringify(res);
});
check('L4', 'libro: decisión de una solicitud usada para otra (otro destino) → DECISION_NOT_FOR_THIS_REQUEST', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('L4'), WED, 'direct_tool');
  const other = JSON.parse(JSON.stringify(d.input)); other.action.destination = 'acct-atacante';
  const res = post(w, { ...d, input: other }, WED, { destination: d.input.action.destination });
  return (!res.accepted && res.reason === 'DECISION_NOT_FOR_THIS_REQUEST') || JSON.stringify(res);
});
check('L5', 'libro: decisión CONTINUE fabricada y firmada con otra clave → DECISION_SIGNATURE_INVALID', () => {
  const w = world('protected'), attacker = crypto.generateKeyPairSync('ed25519');
  const input = { ...w.gw.canonicalRequest(w.issue('L5')), current_state: w.stateSource.read(WED) };
  const record = decide(input, WED);
  const res = post(w, { record, signature: signDecision(record, attacker.privateKey), input }, WED);
  return (!res.accepted && res.reason === 'DECISION_SIGNATURE_INVALID') || JSON.stringify(res);
});
check('L6', 'libro: pago sin decisión → DECISION_MISSING', () => {
  const w = world('protected'), r = w.issue('L6');
  const res = w.ledger.post({ input: r, amount: 4000, currency: 'USD', destination: 'acct-9921', path: 'attacker' }, WED);
  return (!res.accepted && res.reason === 'DECISION_MISSING') || JSON.stringify(res);
});
check('L7', 'gateway vulnerable + libro que controla: la API legacy y la cola vieja quedan cerradas en el objetivo', () => {
  const a = runScenario('A3_revoked_then_legacy', 'vulnerable', { ledgerEnforce: true });
  const b = runScenario('A6_queue_hold', 'vulnerable', { ledgerEnforce: true });
  return (!a.posted && a.outcomes[1].ledger === 'REFUSED:DECISION_MISSING' && !b.posted && b.outcomes[0].ledger === 'REFUSED:DECISION_STALE')
    || JSON.stringify([a.outcomes, b.outcomes]);
});

// Verificador independiente sobre la versión vulnerable: tiene que ver lo que el log de decisiones no muestra.
check('V1', 'verificador: versión vulnerable, REJECT registrado pero pago por la API legacy → BLOCKED_BUT_POSTED', () => {
  const s = runScenario('A3_revoked_then_legacy', 'vulnerable');
  return (s.posted && s.finding === 'BLOCKED_BUT_POSTED') || `posted=${s.posted} finding=${s.finding}`;
});
check('V2', 'verificador: versión vulnerable, pago liberado con la decisión del lunes → EXECUTED_ON_STALE_DECISION', () => {
  const s = runScenario('A6_queue_hold', 'vulnerable');
  return (s.posted && s.finding === 'EXECUTED_ON_STALE_DECISION') || `posted=${s.posted} finding=${s.finding}`;
});
check('V3', 'verificador: exportación del libro con un asiento borrado → UNVERIFIABLE', () => {
  const w = world('protected'); w.gw.directTool(w.issue('V3a'), WED); w.gw.directTool(w.issue('V3b'), sec(WED, 1));
  const exp = w.ledger.export(); exp.entries.splice(0, 1);
  const rep = verify({ decisions: w.gw.decisions, ledgerExport: exp, boundaryPublicKey: w.keys.publicKey, anchoredHead: w.ledger.head() });
  return (!rep.ledger_chain.valid && rep.requests.every(r => r.finding === 'UNVERIFIABLE')) || JSON.stringify(rep.ledger_chain);
});
check('V4', 'verificador: versión protegida en todos los escenarios → nada inconsistente; solo A1 y A9 pagan, y A9 una sola vez', () => {
  const bad = [];
  for (const k of Object.keys(SCENARIOS)) {
    const s = runScenario(k, 'protected');
    const expected = (k === 'A1_normal' || k === 'A9_same_request_twice') ? 1 : 0;
    if (s.postings !== expected) bad.push(`${k}: postings=${s.postings}`);
    if (!['CONSISTENT', 'NO_ACTIVITY'].includes(s.finding)) bad.push(`${k}: ${s.finding}`);
  }
  return bad.length === 0 || bad.join('; ');
});
check('V5', 'verificador: no usa el log del gateway (borrarlo no cambia el informe)', () => {
  const s = runScenario('A3_revoked_then_legacy', 'vulnerable');
  s.w.gw.log = [];
  return findingOf(s.w, 'A3') === 'BLOCKED_BUT_POSTED' || findingOf(s.w, 'A3');
});

// v0.6 — Fallos encontrados por ChatGPT (13-oct-2026). Cada uno se reproduce en la versión vulnerable y se cierra en la protegida.
check('R1a', 'revisión ChatGPT 1: la misma solicitud enviada dos veces → protegida paga una sola vez (ALREADY_EXECUTED)', () => {
  const s = runScenario('A9_same_request_twice', 'protected');
  return (s.postings === 1 && s.outcomes[1].ledger === 'REFUSED:ALREADY_EXECUTED') || JSON.stringify(s.outcomes);
});
check('R1b', 'revisión ChatGPT 1: con un libro que no controla, el verificador marca el doble pago → DUPLICATE_EXECUTION', () => {
  const s = runScenario('A9_same_request_twice', 'vulnerable');
  return (s.postings === 2 && s.finding === 'DUPLICATE_EXECUTION') || `postings=${s.postings} finding=${s.finding}`;
});
check('R1c', 'revisión ChatGPT 1: nuevas solicitudes con la misma autorización no superan su tope acumulado → AUTHORIZATION_BUDGET_EXCEEDED', () => {
  const w = world('protected'), out = ['B1', 'B2', 'B3'].map((id, i) => w.gw.directTool(w.issue(id, { authId: 'auth-shared' }), sec(WED, i)));
  return (out[0].executed && out[1].executed && out[2].ledger === 'REFUSED:AUTHORIZATION_BUDGET_EXCEEDED') || JSON.stringify(out.map(o => o.ledger));
});
check('R2a', 'revisión ChatGPT 2: el agente sube el umbral de revisión en su solicitud → protegida usa la política vigente: ESCALATE y no paga', () => {
  const v = runScenario('A7_declared_policy', 'vulnerable'), p = runScenario('A7_declared_policy', 'protected');
  return (v.posted && p.outcomes[0].decision === 'ESCALATE' && !p.posted) || `vulnerable_posted=${v.posted} protected=${p.outcomes[0].decision}/${p.posted}`;
});
check('R2b', 'revisión ChatGPT 2: el agente se declara humano → protegida usa el registro de agentes: ESCALATE y no paga', () => {
  const v = runScenario('A8_declared_human', 'vulnerable'), p = runScenario('A8_declared_human', 'protected');
  return (v.posted && p.outcomes[0].decision === 'ESCALATE' && !p.posted) || `vulnerable_posted=${v.posted} protected=${p.outcomes[0].decision}/${p.posted}`;
});
check('R3a', 'revisión ChatGPT 3: se decide, revocan al aprobador y se registra un segundo después → STATE_CHANGED_SINCE_DECISION', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('R3a'), WED, 'direct_tool');
  w.stateSource.set({ approver_status: 'revoked' });
  const res = post(w, d, sec(WED, 1)); return (!res.accepted && res.reason === 'STATE_CHANGED_SINCE_DECISION') || JSON.stringify(res);
});
check('R3b', 'revisión ChatGPT 3: la autorización vence entre la decisión y el registro → AUTHORIZATION_EXPIRED_AT_COMMIT', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('R3b', { auth: { valid_until: '2026-10-14T14:00:01Z' } }), WED, 'direct_tool');
  if (d.record.decision !== 'CONTINUE') return 'setup: expected CONTINUE';
  const res = post(w, d, sec(WED, 2)); return (!res.accepted && res.reason === 'AUTHORIZATION_EXPIRED_AT_COMMIT') || JSON.stringify(res);
});
check('R3c', 'gateway vulnerable + libro que controla: autorización alterada en la solicitud → AUTHORIZATION_ALTERED', () => {
  const w = world('vulnerable', { ledgerEnforce: true }), r = w.issue('R3c', { auth: { valid_until: '2026-10-14T13:00:00Z' } });
  r.authorization.valid_until = '2026-10-16T23:00:00Z';   // el agente "extiende" su autorización
  const o = w.gw.directTool(r, WED); return (!o.executed && o.ledger === 'REFUSED:AUTHORIZATION_ALTERED') || JSON.stringify(o);
});
check('R4', 'revisión ChatGPT 4: decisión de 4.000 USD a acct-9921 registrada como 9.000 EUR a otra cuenta (libro sin control) → EFFECT_DIFFERS_FROM_AUTHORIZED', () => {
  const w = world('protected', { ledgerEnforce: false }), d = w.gw.decideNow(w.issue('R4'), WED, 'direct_tool');
  post(w, d, WED, { amount: 9000, currency: 'EUR', destination: 'acct-otra' });
  return findingOf(w, 'R4') === 'EFFECT_DIFFERS_FROM_AUTHORIZED' || findingOf(w, 'R4');
});
check('R5', 'escalación completa: 8.000 por agente → ESCALATE → aprobación firmada → estado actual → CONTINUE → se paga una vez → CONSISTENT; reintento → no paga', () => {
  const w = world('protected'), o = w.gw.directTool(w.issue('R5', { action: { amount: 8000 } }), WED);
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  const resp = { approved: true, approver: 'risk-officer-3', signature: signApproval(o.ticket, o.input, 'risk-officer-3', w.officer.privateKey) };
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 120));
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 121));
  return (r1.executed && !r2.executed && r2.reason === 'TICKET_ALREADY_CLOSED' && w.ledger.entries.length === 1 && findingOf(w, 'R5') === 'CONSISTENT')
    || JSON.stringify({ r1, r2, entries: w.ledger.entries.length, finding: findingOf(w, 'R5') });
});
check('R6', 'escalación: la autorización vence mientras se espera la aprobación → REJECT por AUTHORIZATION_EXPIRED y no se paga', () => {
  const w = world('protected'), o = w.gw.directTool(w.issue('R6', { action: { amount: 8000 }, auth: { valid_until: '2026-10-14T14:05:00Z' } }), WED);
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  const resp = { approved: true, approver: 'risk-officer-3', signature: signApproval(o.ticket, o.input, 'risk-officer-3', w.officer.privateKey) };
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 600));
  return (!r.executed && r.decision === 'REJECT' && (r.reasons || []).includes('AUTHORIZATION_EXPIRED') && w.ledger.entries.length === 0) || JSON.stringify(r);
});
check('R7', 'escalación: el estado cambia mientras se espera (cuenta congelada) → REJECT al resolver y no se paga', () => {
  const w = world('protected'), o = w.gw.directTool(w.issue('R7', { action: { amount: 8000 } }), WED);
  const resp = { approved: true, approver: 'risk-officer-3', signature: signApproval(o.ticket, o.input, 'risk-officer-3', w.officer.privateKey) };
  w.stateSource.set({ account_status: 'frozen' });
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 120));
  return (!r.executed && r.decision === 'REJECT' && w.ledger.entries.length === 0) || JSON.stringify(r);
});

// v0.6.1 — Fallos de las revisiones de ChatGPT y Grok sobre la v0.6 (13-oct-2026).
const approveResp = (w, o) => ({ approved: true, approver: 'risk-officer-3', signature: signApproval(o.ticket, o.input, 'risk-officer-3', w.officer.privateKey) });
const escalate8000 = (w, id, extra = {}) => w.gw.directTool(w.issue(id, { action: { amount: 8000 }, ...extra }), WED);

check('R8', 'revisión ChatGPT v0.6 #1: el agente declara "irreversible: false" → vulnerable paga; protegida usa el catálogo: ESCALATE y no paga', () => {
  const v = runScenario('A10_declared_reversible', 'vulnerable'), p = runScenario('A10_declared_reversible', 'protected');
  return (v.posted && p.outcomes[0].decision === 'ESCALATE' && reasonsOf(p.outcomes[0]).includes('IRREVERSIBLE_REQUIRES_HUMAN') && !p.posted)
    || `vulnerable_posted=${v.posted} protected=${p.outcomes[0].decision}/${p.posted}`;
});
check('R9', 'revisión ChatGPT v0.6 #2: bajan el tope de la autorización a 1.000 mientras se espera la aprobación → REJECT y no se paga', () => {
  const w = world('protected'), o = escalate8000(w, 'R9');
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  const au = w.authStore.get('auth-R9'); au.scope.max_amount = 1000; w.authStore.put(au);
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  return (!r.executed && r.decision === 'REJECT' && r.reason === 'REQUEST_CONDITIONS_CHANGED_WHILE_PENDING' && (r.changed || []).includes('authorization') && w.ledger.entries.length === 0) || JSON.stringify(r);
});
check('R10', 'revisión ChatGPT v0.6 #3: endurecen la política mientras se espera la aprobación → REJECT y no se paga', () => {
  const w = world('protected'), o = escalate8000(w, 'R10');
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  w.gw.policy.max_state_age_seconds = 0.5;
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  return (!r.executed && r.decision === 'REJECT' && (r.changed || []).includes('policy') && w.ledger.entries.length === 0) || JSON.stringify(r);
});
check('R11', 'revisión ChatGPT v0.6 #4: una solicitud mal formada no entra a la cola ni la bloquea; el pago válido se procesa', () => {
  const w = world('protected');
  const bad = [w.gw.schedule({}, WED), w.gw.schedule(undefined, WED), w.gw.schedule({ request_id: 'x' }, WED)];
  w.gw.schedule(w.issue('R11'), WED);
  let out; try { out = w.gw.releaseQueue(sec(WED, 1)); } catch (e) { return 'THROW: ' + e.message; }
  return (bad.every(b => !b.queued && b.reason === 'MALFORMED_REQUEST') && out.length === 1 && out[0].executed && w.gw.queue.length === 0)
    || JSON.stringify({ bad, out, queue: w.gw.queue.length });
});
check('R12', 'revisión ChatGPT v0.6: una respuesta con firma inválida no inutiliza el ticket; la aprobación válida después paga una vez; una denegación firmada sí lo cierra', () => {
  const w = world('protected'), o = escalate8000(w, 'R12');
  const forged = { approved: true, approver: 'risk-officer-3', signature: Buffer.alloc(64).toString('base64') };
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, forged, sec(WED, 30));
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  const w2 = world('protected'), o2 = escalate8000(w2, 'R12b');
  const unsignedDeny = w2.gw.resolveEscalation(o2.ticket.ticket_id, { approved: false, approver: 'risk-officer-3', signature: 'AAAA' }, sec(WED, 30));
  const deny = w2.gw.resolveEscalation(o2.ticket.ticket_id, { approved: false, approver: 'risk-officer-3', signature: signDenial(o2.ticket, o2.input, 'risk-officer-3', w2.officer.privateKey) }, sec(WED, 40));
  const after = w2.gw.resolveEscalation(o2.ticket.ticket_id, approveResp(w2, o2), sec(WED, 50));
  return (r1.reason === 'APPROVAL_SIGNATURE_INVALID' && r1.ticket_status === 'OPEN' && r2.executed && w.ledger.entries.length === 1
    && unsignedDeny.ticket_status === 'OPEN' && deny.reason === 'ESCALATION_DENIED' && after.reason === 'TICKET_ALREADY_CLOSED' && w2.ledger.entries.length === 0)
    || JSON.stringify({ r1, r2, unsignedDeny, deny, after });
});
check('R13', 'revisión Grok v0.6 #1: el sistema objetivo rechaza el pago aprobado (core caído) → el ticket no se gasta; el reintento paga una vez; otro reintento no', () => {
  const w = world('protected'), o = escalate8000(w, 'R13');
  const realPost = w.ledger.post.bind(w.ledger); let down = true;
  w.ledger.post = (p, at) => down ? { accepted: false, reason: 'TARGET_UNAVAILABLE' } : realPost(p, at);
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  down = false;
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 90));
  const r3 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 95));
  return (!r1.executed && r1.ticket_status === 'OPEN' && r2.executed && r2.ticket_status === 'CLOSED' && r3.reason === 'TICKET_ALREADY_CLOSED'
    && w.ledger.entries.length === 1 && findingOf(w, 'R13') === 'CONSISTENT') || JSON.stringify({ r1, r2, r3, finding: findingOf(w, 'R13') });
});

function runChecks() {
  return CHECKS.map(c => {
    let r;
    try { r = c.fn(); } catch (e) { r = 'ERROR: ' + e.message; }
    return { id: c.id, name: c.name, ok: r === true, detail: r === true ? '' : String(r) };
  });
}

module.exports = { runChecks, runScenario, SCENARIOS, PATHS, world, MON, TUE, WED };
