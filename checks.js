// Escenarios adversariales y batería de comprobaciones (v0.5; ampliada en v0.6).
// Cada escenario se corre igual contra la versión vulnerable y la protegida.
// runChecks() devuelve la lista de comprobaciones con ok/detalle. La usan test-v06.js y la meta-prueba de mutantes.
// v0.6: las comprobaciones R reproducen los cuatro fallos de la revisión de ChatGPT del 13-oct-2026 y los cierran.
// v0.6.1: R8–R13 reproducen los fallos de las revisiones de ChatGPT y Grok sobre la v0.6.
// v0.6.4: R22–R27 cubren los hallazgos F1–F3 de la revisión asistida por IA (ChatGPT) del 16-oct-2026 sobre la v0.6.3.
// v0.6.3: R14–R21 cubren los hallazgos de la revisión asistida por IA (ChatGPT) del 14-oct-2026 sobre la v0.6.2,
//   la confirmación perdida y el cambio de datos del beneficiario (escenarios A11 y A12).
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
// beneficiary_record: versión de los datos del beneficiario en el maestro de proveedores (condición opcional, v0.6.3).
const NORMAL = { approver_status: 'active', amount_limit: 10000, account_status: 'open', risk_level: 'low', beneficiary_record: 'v1' };
const PATHS = ['direct_tool', 'legacy_batch_api', 'scheduled_queue', 'escalation'];
const POLICY = { max_state_age_seconds: 5, human_review_above_amount: 5000 };

// ledgerEnforce por defecto: el libro controla solo en la versión protegida.
function world(mode, { ledgerEnforce = mode === 'protected', state = NORMAL, lag = 1 } = {}) {
  const keys = crypto.generateKeyPairSync('ed25519');
  const officer = crypto.generateKeyPairSync('ed25519');
  const stateSource = new StateSource(state, lag);
  const authStore = new AuthorizationStore();
  const policy = { ...POLICY };   // política vigente (fuente controlada); el libro la consulta al registrar
  const ledger = new Ledger({ enforce: ledgerEnforce, boundaryPublicKey: keys.publicKey, maxDecisionAgeSeconds: 5, authStore, stateSource, policySource: () => gw.policy });
  const agents = { 'agent-payments-7': { kind: 'ai_agent' }, 'manager-42': { kind: 'human' } };
  const approvers = { 'risk-officer-3': { kind: 'human', status: 'active', can_approve_escalations: true, max_amount: 20000, public_key: officer.publicKey } };
  const gw = new Gateway({ mode, ledger, stateSource, keys, authStore, agents, policy, approvers });
  // Emite una autorización en el registro y devuelve la solicitud que el agente enviaría (con todo declarado).
  function issue(id, { action = {}, authId, auth = {} } = {}) {
    const aid = authId || 'auth-' + id;
    if (!authStore.has(aid)) authStore.put({ id: aid, granted_by: 'manager-42', granted_at: '2026-10-12T13:00:00Z', valid_until: '2026-10-16T23:00:00Z',
      scope: { action_types: ['transfer', 'refund'], max_amount: 10000, destinations: ['acct-9921'] }, conditions_at_grant: { ...NORMAL }, ...auth });
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
  // v0.6.3 — caso planteado en LinkedIn el 15-oct-2026 (pago aprobado y luego cambian los datos bancarios del beneficiario)
  A11_beneficiary_changed: { title: 'Pago aprobado; luego cambian los datos bancarios del beneficiario en el maestro; el agente paga a la cuenta aprobada',
    run: w => { const r = w.issue('A11'); w.stateSource.set({ beneficiary_record: 'v2' }); return [w.gw.directTool(r, WED)]; } },
  A12_new_account_old_approval: { title: 'El agente paga a la cuenta NUEVA del beneficiario con la aprobación de la cuenta vieja (y borra el destino de la autorización que declara)',
    run: w => { const r = w.issue('A12', { action: { destination: 'acct-5507' } }); delete r.authorization.scope.destinations; w.stateSource.set({ beneficiary_record: 'v2' });
      r.authorization.conditions_at_grant.beneficiary_record = 'v2'; return [w.gw.directTool(r, WED)]; } },
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

// v0.6.3 — Revisión asistida por IA (ChatGPT) del 14-oct-2026 sobre la v0.6.2, confirmación perdida y beneficiario.
check('R14', 'revisión 14-oct #1: el riesgo sube mientras se espera la aprobación → la aprobación no lo absorbe: REJECT por CONDITIONS_CHANGED_SINCE_REVIEW y no se paga', () => {
  const w = world('protected'), o = escalate8000(w, 'R14');
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  const resp = approveResp(w, o);            // el aprobador firma lo que vio: riesgo bajo
  w.stateSource.set({ risk_level: 'high' });  // después sube el riesgo
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 60));
  return (!r.executed && r.decision === 'REJECT' && r.reason === 'CONDITIONS_CHANGED_SINCE_REVIEW' && (r.changed || []).some(c => c.startsWith('risk_level')) && w.ledger.entries.length === 0)
    || JSON.stringify(r);
});
check('R14b', 'revisión 14-oct #1: la firma del aprobador cubre las condiciones revisadas; si alguien las cambia en el ticket, la firma deja de valer', () => {
  const w = world('protected'), o = escalate8000(w, 'R14b');
  const resp = approveResp(w, o);
  w.gw.tickets.get(o.ticket.ticket_id).reviewed_conditions.risk_level = 'high';
  w.stateSource.set({ risk_level: 'high' });
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, resp, sec(WED, 60));
  return (!r.executed && r.reason === 'APPROVAL_SIGNATURE_INVALID' && w.ledger.entries.length === 0) || JSON.stringify(r);
});
check('R15', 'revisión 14-oct #2: la política cambia entre decidir y registrar → el libro rechaza: POLICY_CHANGED_SINCE_DECISION', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('R15'), WED, 'direct_tool');
  if (d.record.decision !== 'CONTINUE') return 'setup: expected CONTINUE';
  w.gw.policy.human_review_above_amount = 1000;
  const res = post(w, d, WED); return (!res.accepted && res.reason === 'POLICY_CHANGED_SINCE_DECISION') || JSON.stringify(res);
});
check('R16', 'revisión 14-oct #3: cinco respuestas falsas no cierran el ticket; la aprobación legítima después paga una sola vez', () => {
  const w = world('protected'), o = escalate8000(w, 'R16');
  const forged = { approved: true, approver: 'risk-officer-3', signature: Buffer.alloc(64).toString('base64') };
  const fakes = [1, 2, 3, 4, 5].map(i => w.gw.resolveEscalation(o.ticket.ticket_id, forged, sec(WED, i)));
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  return (fakes.every(f => f.ticket_status === 'OPEN' && f.reason === 'APPROVAL_SIGNATURE_INVALID') && r.executed && w.ledger.entries.length === 1)
    || JSON.stringify({ fakes: fakes.map(f => f.reason + '/' + f.ticket_status), r });
});
check('R17', 'revisión 14-oct #4: evidencia mal formada (registro nulo, sin bound_to, basura) → el verificador no se cae, la cuenta aparte y mantiene los demás resultados', () => {
  const w = world('protected'); w.gw.directTool(w.issue('R17'), WED);
  let rep;
  try {
    rep = verify({ decisions: [...w.gw.decisions, { record: null, signature: 'x' }, { record: { decision: 'CONTINUE' }, signature: 'y' }, null, 42],
      ledgerExport: w.ledger.export(), boundaryPublicKey: w.keys.publicKey, anchoredHead: w.ledger.head() });
  } catch (e) { return 'THROW: ' + e.message; }
  const r = rep.requests.find(x => x.request_id === 'R17');
  return (rep.malformed_evidence.decisions === 4 && r && r.finding === 'CONSISTENT') || JSON.stringify({ malformed: rep.malformed_evidence, r });
});
check('R18', 'confirmación perdida: el libro registra el pago pero la respuesta no llega; el reintento no paga otra vez y dice que ya estaba pagado', () => {
  const w = world('protected');
  const realPost = w.ledger.post.bind(w.ledger); let lose = true;
  w.ledger.post = (p, at) => { const res = realPost(p, at); if (lose && res.accepted) { lose = false; return { accepted: false, reason: 'CONFIRMATION_LOST' }; } return res; };
  const r = w.issue('R18');
  const o1 = w.gw.directTool(r, WED), o2 = w.gw.directTool(r, sec(WED, 2));
  return (!o1.executed && o1.ledger === 'REFUSED:CONFIRMATION_LOST' && o2.already_posted === true && o2.posted_entry === 1 && w.ledger.entries.length === 1 && findingOf(w, 'R18') === 'CONSISTENT')
    || JSON.stringify({ o1, o2, entries: w.ledger.entries.length, finding: findingOf(w, 'R18') });
});
check('R19', 'confirmación perdida en la escalación: el pago aprobado se registra pero la respuesta se pierde; el reintento cierra el ticket sin pagar otra vez', () => {
  const w = world('protected'), o = escalate8000(w, 'R19');
  const realPost = w.ledger.post.bind(w.ledger); let lose = true;
  w.ledger.post = (p, at) => { const res = realPost(p, at); if (lose && res.accepted) { lose = false; return { accepted: false, reason: 'CONFIRMATION_LOST' }; } return res; };
  // v0.6.4: en la primera llamada tampoco responde la consulta de estado del libro (si respondiera, el ticket se cerraría ya ahí).
  const realStatus = w.ledger.status.bind(w.ledger); let statusDown = true;
  w.ledger.status = id => statusDown ? { executed: false } : realStatus(id);
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60));
  statusDown = false;
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 62));
  const r3 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 64));
  return (!r1.executed && r1.ticket_status === 'OPEN' && r2.already_posted === true && r2.ticket_status === 'CLOSED' && r3.reason === 'TICKET_ALREADY_CLOSED' && w.ledger.entries.length === 1)
    || JSON.stringify({ r1, r2, r3, entries: w.ledger.entries.length });
});
check('R20', 'beneficiario (A11): cambian sus datos bancarios después de aprobar → ESCALATE por CONDITIONS_CHANGED_SINCE_GRANT y no se paga', () => {
  const s = runScenario('A11_beneficiary_changed', 'protected'), o = s.outcomes[0];
  return (o.decision === 'ESCALATE' && reasonsOf(o).includes('CONDITIONS_CHANGED_SINCE_GRANT') && !s.posted) || JSON.stringify(o);
});
check('R21', 'beneficiario (A12): pago a la cuenta nueva con la aprobación de la vieja → vulnerable paga; protegida REJECT por OUT_OF_SCOPE_DESTINATION', () => {
  const v = runScenario('A12_new_account_old_approval', 'vulnerable'), p = runScenario('A12_new_account_old_approval', 'protected');
  return (v.posted && p.outcomes[0].decision === 'REJECT' && reasonsOf(p.outcomes[0]).includes('OUT_OF_SCOPE_DESTINATION') && !p.posted)
    || `vulnerable_posted=${v.posted} protected=${p.outcomes[0].decision}/${JSON.stringify(reasonsOf(p.outcomes[0]))}/${p.posted}`;
});

// v0.6.4 — Revisión adversarial asistida por IA (ChatGPT) del 16-oct-2026 sobre la v0.6.3 (F1–F3), reproducida antes de corregir.
const { canonical, sha256 } = require('./decide');
const { derivedAuthorizationId } = require('./escalation');
const loseFirstConfirmation = w => {
  const realPost = w.ledger.post.bind(w.ledger); let lose = true;
  w.ledger.post = (p, at) => { const res = realPost(p, at); if (lose && res.accepted) { lose = false; return { accepted: false, reason: 'CONFIRMATION_LOST' }; } return res; };
};
// Escalación de 4.000 por subida de riesgo (bajo el umbral de revisión humana: el permiso derivado bastaría para pagar).
const escalateRiskUp = (w, id) => { const r = w.issue(id); w.stateSource.set({ risk_level: 'high' }); return w.gw.directTool(r, WED); };
const rehash = entries => { let prev = 'GENESIS'; const out = [];
  const { GENESIS } = require('./ledger'); prev = GENESIS;
  for (const e0 of entries) { const { entry_hash, ...rest } = e0; rest.prev_hash = prev; const e = { ...rest, entry_hash: sha256(canonical(rest)) }; out.push(e); prev = e.entry_hash; }
  return { entries: out, head: prev }; };

check('R22', 'revisión 16-oct F1: la aprobación de una solicitud no sirve como permiso para otra (el agente cita la autorización derivada) → REJECT y no se paga', () => {
  const w = world('protected'), o = escalateRiskUp(w, 'R22');
  if (o.decision !== 'ESCALATE' || !o.ticket) return 'setup: expected ESCALATE with ticket';
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 2));
  const derived = derivedAuthorizationId('auth-R22', o.ticket.ticket_id);
  const second = w.gw.directTool({ ...w.issue('R22b', { authId: 'auth-R22' }), authorization: { id: derived } }, sec(WED, 3));
  const control = w.gw.directTool(w.issue('R22c', { authId: 'auth-R22' }), sec(WED, 4));
  return (r1.executed && second.decision === 'REJECT' && !second.executed && control.decision === 'ESCALATE' && w.ledger.entries.length === 1)
    || JSON.stringify({ r1: r1.ledger, second: second.decision + '/' + second.ledger, control: control.decision, entries: w.ledger.entries.length });
});
check('R23', 'revisión 16-oct F1: el core falla, luego el aprobador DENIEGA → la autorización derivada se retira y nada puede pagar con ella', () => {
  const w = world('protected'), o = escalateRiskUp(w, 'R23');
  const realPost = w.ledger.post.bind(w.ledger);
  w.ledger.post = () => ({ accepted: false, reason: 'TARGET_UNAVAILABLE' });
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 2));
  const deny = w.gw.resolveEscalation(o.ticket.ticket_id, { approved: false, approver: 'risk-officer-3', signature: signDenial(o.ticket, o.input, 'risk-officer-3', w.officer.privateKey) }, sec(WED, 3));
  w.ledger.post = realPost;
  const derived = derivedAuthorizationId('auth-R23', o.ticket.ticket_id);
  const retry = w.gw.directTool({ ...w.issue('R23', { authId: 'auth-R23' }), authorization: { id: derived } }, sec(WED, 4));
  return (!r1.executed && deny.ticket_status === 'CLOSED' && !w.authStore.has(derived) && !retry.executed && w.ledger.entries.length === 0)
    || JSON.stringify({ r1: r1.ledger, deny: deny.reason + '/' + deny.ticket_status, stillStored: w.authStore.has(derived), retry: retry.decision + '/' + retry.ledger });
});
check('R24', 'revisión 16-oct F1 (defensa en el libro): aun con una decisión firmada, la autorización derivada no vale para otra solicitud, otra acción, ni si la madre cambió', () => {
  const w = world('protected'), o = escalateRiskUp(w, 'R24');
  const realPost = w.ledger.post.bind(w.ledger); let captured = null;
  w.ledger.post = p => { captured = p.input.authorization; return { accepted: false, reason: 'TARGET_UNAVAILABLE' }; };
  w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 2));
  w.ledger.post = realPost;
  if (!captured || w.authStore.has(captured.id)) return 'setup: derived authorization must be withdrawn after the ledger refused';
  // Se simula que la derivada sigue en el registro (por ejemplo, un fallo entre registrarla y retirarla): el libro igual la acota.
  w.authStore.put(captured, { budget_key: 'auth-R24' });
  const derived = w.authStore.get(captured.id);
  const at = sec(WED, 3);
  // mientras el ticket sigue abierto, una solicitud ordinaria que cita la autorización derivada no la obtiene del gateway
  const viaGateway = w.gw.directTool({ ...w.issue('R24-gw', { authId: 'auth-R24' }), authorization: { id: derived.id } }, at);
  const signedPost = (rid, action = {}) => {   // simula un gateway comprometido que firma con la autorización derivada
    const input = { ...w.gw.canonicalRequest(w.issue(rid, { authId: 'auth-R24', action })), authorization: w.authStore.get(derived.id), current_state: w.stateSource.read(at) };
    const record = decide(input, at); if (record.decision !== 'CONTINUE') return 'setup:' + record.decision;
    return w.ledger.post({ input, amount: input.action.amount, currency: input.action.currency, destination: input.action.destination, path: 'attacker', decision: record, signature: signDecision(record, w.keys.privateKey) }, at);
  };
  const other = signedPost('R24-other'), bigger = signedPost('R24', { amount: 3000 });
  const parent = w.authStore.get('auth-R24'); parent.scope.max_amount = 1000; w.authStore.put(parent);
  const afterParent = signedPost('R24');
  return (viaGateway.decision === 'REJECT' && !viaGateway.executed && other.reason === 'DERIVED_AUTHORIZATION_NOT_FOR_THIS_REQUEST' && bigger.reason === 'DERIVED_AUTHORIZATION_NOT_FOR_THIS_REQUEST'
    && afterParent.reason === 'PARENT_AUTHORIZATION_CHANGED' && w.ledger.entries.length === 0)
    || JSON.stringify({ viaGateway: viaGateway.decision + '/' + viaGateway.ledger, other, bigger, afterParent, entries: w.ledger.entries.length });
});
check('R25', 'revisión 16-oct F2: fechas imposibles o inválidas en el libro → TIMING_INVALID (no CONSISTENT) y el verificador no se cae', () => {
  const w = world('protected', { ledgerEnforce: false }), d = w.gw.decideNow(w.issue('R25'), WED, 'direct_tool');
  post(w, d, sec(WED, -100));   // asiento ANTERIOR al estado en que se basó la decisión
  const backwards = findingOf(w, 'R25');
  const w2 = world('protected'); w2.gw.directTool(w2.issue('R25b'), WED);
  const forged = posted_at => { const exp = rehash(w2.ledger.export().entries.map(e => ({ ...e, posted_at }))); 
    return verify({ decisions: w2.gw.decisions, ledgerExport: exp, boundaryPublicKey: w2.keys.publicKey, anchoredHead: exp.head }).requests.find(r => r.request_id === 'R25b').finding; };
  let notDate, nullDate, weird;
  try { notDate = forged('not-a-date'); nullDate = forged(null); weird = forged({ toString: null }); } catch (e) { return 'THROW: ' + e.message; }
  return (backwards === 'TIMING_INVALID' && notDate === 'TIMING_INVALID' && nullDate === 'TIMING_INVALID' && weird === 'TIMING_INVALID')
    || JSON.stringify({ backwards, notDate, nullDate, weird });
});
check('R26', 'revisión 16-oct F3: confirmación perdida y reintento 100 ms después (misma decisión) → informa que ya estaba pagado; no paga otra vez', () => {
  const w = world('protected'); loseFirstConfirmation(w);
  const r = w.issue('R26');
  const o1 = w.gw.directTool(r, WED), o2 = w.gw.directTool(r, new Date(WED.getTime() + 100));
  return (!o1.executed && o2.already_posted === true && o2.posted_entry === 1 && w.ledger.entries.length === 1) || JSON.stringify({ o1, o2 });
});
check('R27', 'revisión 16-oct F3: confirmación perdida y luego congelan la cuenta → el reintento (directo o por escalación) informa el pago ya hecho en vez de "no se pagó"', () => {
  const w = world('protected'); loseFirstConfirmation(w);
  const r = w.issue('R27');
  w.gw.directTool(r, WED); w.stateSource.set({ account_status: 'frozen' });
  const o2 = w.gw.directTool(r, sec(WED, 2));
  const we = world('protected'), oe = escalate8000(we, 'R27e'); loseFirstConfirmation(we);
  const realStatus = we.ledger.status.bind(we.ledger); let statusDown = true;   // la consulta de estado tampoco responde en el primer intento
  we.ledger.status = id => statusDown ? { executed: false } : realStatus(id);
  const e1 = we.gw.resolveEscalation(oe.ticket.ticket_id, approveResp(we, oe), sec(WED, 60));
  statusDown = false;
  we.stateSource.set({ account_status: 'frozen' });
  const e2 = we.gw.resolveEscalation(oe.ticket.ticket_id, approveResp(we, oe), sec(WED, 62));
  return (o2.decision === 'REJECT' && o2.already_posted === true && !o2.ticket && w.ledger.entries.length === 1
    && !e1.executed && e2.already_posted === true && e2.ticket_status === 'CLOSED' && e2.reason === 'ALREADY_POSTED_EARLIER' && we.ledger.entries.length === 1)
    || JSON.stringify({ o2, e1: e1.ledger, e2 });
});

// v0.6.4 — segunda revisión asistida por IA (ChatGPT) de la v0.6.4 ANTES de publicar (16-oct-2026).
check('R28', 'revisión previa v0.6.4 #1: confirmación perdida y estado del libro caído; luego cambia la política (o la autorización) → el reintento informa el pago ya hecho, no "condiciones cambiadas"; un reintento posterior también lo informa', () => {
  const run = change => {
    const w = world('protected'), o = escalate8000(w, 'R28'); loseFirstConfirmation(w);
    const realStatus = w.ledger.status.bind(w.ledger); let down = true;
    w.ledger.status = id => down ? { executed: false } : realStatus(id);
    const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60)); down = false;
    change(w);
    const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 62));
    const r3 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 64));
    return { ok: !r1.executed && r2.reason === 'ALREADY_POSTED_EARLIER' && r2.already_posted === true && r2.ticket_status === 'CLOSED'
      && r3.reason === 'TICKET_ALREADY_CLOSED' && r3.already_posted === true && w.ledger.entries.length === 1, r2: r2.reason, r3: r3.reason + '/' + r3.already_posted };
  };
  const pol = run(w => { w.gw.policy.human_review_above_amount = 6000; });
  const auth = run(w => { const a = w.authStore.get('auth-R28'); a.valid_until = '2026-10-16T22:00:00Z'; w.authStore.put(a); });
  return (pol.ok && auth.ok) || JSON.stringify({ pol, auth });
});
check('R29', 'revisión previa v0.6.4 #2: el mismo identificador se usa para otra operación → conflicto explícito, nunca "ya pagado"', () => {
  const w = world('protected'), o = escalate8000(w, 'R29');
  const other = w.gw.directTool(w.issue('R29', { action: { amount: 4000 } }), sec(WED, 1));    // 4.000 con el mismo identificador
  const r = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 3));      // se resuelve el ticket de 8.000
  const w2 = world('protected'); w2.gw.directTool(w2.issue('R29b'), WED);                     // 4.000 pagados
  const d = w2.gw.directTool(w2.issue('R29b', { action: { amount: 3000 } }), sec(WED, 2));   // 3.000 con el mismo identificador
  return (other.executed && r.decision === 'REJECT' && r.reason === 'REQUEST_ID_CONFLICT' && r.request_id_conflict === true && !r.already_posted && r.ticket_status === 'CLOSED'
    && !d.executed && d.request_id_conflict === true && !d.already_posted && w.ledger.entries.length === 1 && w2.ledger.entries.length === 1)
    || JSON.stringify({ other: other.ledger, r, d });
});

check('R30', 'revisión previa v0.6.4 (Grok): si el libro no acepta el pago aprobado, la autorización derivada no queda guardada; el reintento del ticket paga una vez', () => {
  const w = world('protected'), o = escalateRiskUp(w, 'R30');
  const realPost = w.ledger.post.bind(w.ledger); let derivedId = null;
  w.ledger.post = p => { derivedId = p.input.authorization.id; return { accepted: false, reason: 'TARGET_UNAVAILABLE' }; };
  const r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 2));
  w.ledger.post = realPost;
  const storedAfterRefusal = w.authStore.has(derivedId);
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 4));
  return (!r1.executed && r1.ticket_status === 'OPEN' && !storedAfterRefusal && r2.executed && r2.ticket_status === 'CLOSED' && !w.authStore.has(derivedId) && w.ledger.entries.length === 1)
    || JSON.stringify({ r1: r1.ledger + '/' + r1.ticket_status, storedAfterRefusal, r2: r2.ledger + '/' + r2.ticket_status });
});

// v0.6.4 — revisión previa (ChatGPT) de la r3: errores y evidencia mal formada.
check('R31', 'revisión previa r3 #1: el sistema objetivo lanza una excepción al registrar el pago aprobado → resultado explícito, la autorización derivada se retira; si en realidad se registró, se informa', () => {
  const w = world('protected'), o = escalateRiskUp(w, 'R31');
  const realPost = w.ledger.post.bind(w.ledger); let id = null;
  w.ledger.post = p => { id = p.input.authorization.id; throw new Error('TARGET_UNAVAILABLE'); };
  let r1; try { r1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 2)); } catch (e) { return 'THROW: ' + e.message; }
  const stored = w.authStore.has(id);
  w.ledger.post = (p, at) => { realPost(p, at); throw new Error('TIMEOUT_AFTER_POSTING'); };   // registra y después falla
  const r2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 4));
  return (!r1.executed && r1.ledger === 'REFUSED:TARGET_ERROR' && r1.ticket_status === 'OPEN' && !stored
    && r2.already_posted === true && r2.ticket_status === 'CLOSED' && w.ledger.entries.length === 1)
    || JSON.stringify({ r1: r1.ledger + '/' + r1.ticket_status, stored, r2 });
});
check('R32', 'revisión previa r3 #2: un asiento mal formado (sin request_id) no se vuelve evidencia de ausencia: MALFORMED_POSTING si cita la decisión; si no se puede atribuir, nada sale CONSISTENT', () => {
  const w = world('protected', { ledgerEnforce: false }), d = w.gw.decideNow(w.issue('R32'), WED, 'direct_tool');
  post(w, d, WED); post(w, d, WED, { input: { ...d.input, request_id: null } });
  const a = findingOf(w, 'R32');
  const w2 = world('protected', { ledgerEnforce: false }), d2 = w2.gw.decideNow(w2.issue('R32b'), WED, 'direct_tool');
  post(w2, d2, WED, { input: { ...d2.input, request_id: null } });             // solo el asiento sin identificador
  const b = report(w2).requests.find(r => r.request_id === 'R32b');
  const w3 = world('protected', { ledgerEnforce: false }), d3 = w3.gw.decideNow(w3.issue('R32c'), WED, 'direct_tool');
  post(w3, d3, WED); post(w3, d3, sec(WED, 1), { input: { ...d3.input, request_id: null }, decision: null, signature: null });   // asiento sin decisión ni identificador
  const c = report(w3).requests.find(r => r.request_id === 'R32c');
  return (a === 'MALFORMED_POSTING' && b.finding === 'MALFORMED_POSTING' && b.target_effect === 'UNKNOWN'
    && c.finding === 'INCONCLUSIVE_MALFORMED_EVIDENCE' && c.target_effect === 'UNKNOWN')
    || JSON.stringify({ a, b: b.finding + '/' + b.target_effect, c: c.finding + '/' + c.target_effect });
});
check('R33', 'revisión previa r3 #3: un posting con camino inválido (objeto anidado) se rechaza sin tocar presupuesto ni "ejecutado"; el pago normal después funciona', () => {
  const w = world('protected'), d = w.gw.decideNow(w.issue('R33'), WED, 'direct_tool');
  let deep = {}; for (let i = 0; i < 3000; i++) deep = { n: deep };
  let r; try { r = post(w, d, WED, { path: deep }); } catch (e) { return 'THROW: ' + e.message; }
  const clean = !w.ledger.executed.has('R33') && !w.ledger.used.has(d.record.decision_hash) && (w.ledger.consumed.get('auth-R33') || 0) === 0;
  const retry = w.gw.directTool(w.issue('R33'), sec(WED, 1));
  let deeper = {}; for (let i = 0; i < 200000; i++) deeper = { n: deeper };   // tan profundo que no se puede serializar
  const wv = world('vulnerable');                                           // libro sin control: el asiento no serializable tampoco toca el estado
  let rv; try { rv = wv.ledger.post({ input: wv.issue('R33v'), amount: 4000, currency: 'USD', destination: 'acct-9921', path: deeper }, WED); } catch (e) { return 'THROW(v): ' + e.message; }
  return (r.reason === 'POSTING_MALFORMED' && clean && retry.executed && w.ledger.entries.length === 1
    && rv.reason === 'POSTING_NOT_SERIALIZABLE' && !wv.ledger.executed.has('R33v') && wv.ledger.entries.length === 0)
    || JSON.stringify({ r, clean, retry: retry.ledger, rv: rv.reason || ('accepted=' + rv.accepted) });
});
check('R34', 'revisión previa r3 #4: tipo de acción u otros identificadores que no son texto ({toString:null}, "constructor") → REJECT, sin excepción y sin pago', () => {
  const w = world('protected');
  const bad = w.issue('R34'); bad.action.type = { toString: null };
  const bad2 = w.issue('R34b'); bad2.requested_by = { id: { toString: null } };
  const bad3 = w.issue('R34c', { action: { type: 'constructor', amount: 8000 } });
  let o1, o2, o3; try { o1 = w.gw.directTool(bad, WED); o2 = w.gw.directTool(bad2, WED); o3 = w.gw.directTool(bad3, WED); } catch (e) { return 'THROW: ' + e.message; }
  const cat = w.gw.canonicalRequest(bad3).action.irreversible;              // "constructor" no es una operación del catálogo: cuenta como irreversible
  return ([o1, o2, o3].every(o => o.decision === 'REJECT' && !o.executed) && cat === true && w.ledger.entries.length === 0)
    || JSON.stringify({ o1: o1.decision, o2: o2.decision, o3: o3.decision, cat });
});

// v0.6.4 — revisión previa (ChatGPT) de la r4: combinaciones de fallos.
check('R35', 'revisión previa r4 #1: una copia de la decisión con firma inválida (otro request_id) no desvía la atribución del asiento mal formado, sin importar el orden', () => {
  const w = world('protected', { ledgerEnforce: false }), d = w.gw.decideNow(w.issue('R35'), WED, 'direct_tool');
  post(w, d, WED); post(w, d, WED, { input: { ...d.input, request_id: null } });
  const decoy = { ...w.gw.decisions[0], record: { ...d.record, bound_to: { ...d.record.bound_to, request_id: 'decoy' } } };
  const run = list => verify({ decisions: list, ledgerExport: w.ledger.export(), boundaryPublicKey: w.keys.publicKey, anchoredHead: w.ledger.head() }).requests.find(r => r.request_id === 'R35');
  const after = run([...w.gw.decisions, decoy]), before = run([decoy, ...w.gw.decisions]);
  return (after.finding === 'MALFORMED_POSTING' && before.finding === 'MALFORMED_POSTING' && after.target_effect === 'UNKNOWN')
    || JSON.stringify({ after: after.finding + '/' + after.target_effect, before: before.finding });
});
check('R36', 'revisión previa r4 #2: el libro registra, la confirmación falla con excepción y la consulta de estado también falla → resultado DESCONOCIDO (no "no enviado"), en los cuatro caminos; al volver la consulta, se reconoce el pago sin duplicarlo', () => {
  const setup = (id, extra) => {
    const w = world('protected'), realPost = w.ledger.post.bind(w.ledger), realStatus = w.ledger.status.bind(w.ledger);
    let broken = true;
    w.ledger.post = (p, at) => { const r = realPost(p, at); if (broken && r.accepted) throw new Error('LOST_CONFIRMATION'); return r; };
    w.ledger.status = rid => { if (broken) throw new Error('STATUS_UNAVAILABLE'); return realStatus(rid); };
    return { w, heal: () => { broken = false; } };
  };
  const out = {};
  for (const path of ['directTool', 'legacyBatchApi']) {
    const { w, heal } = setup('R36'); const r = w.issue('R36-' + path);
    let o; try { o = w.gw[path](r, WED); } catch (e) { return path + ' THROW: ' + e.message; }
    heal(); const o2 = w.gw[path](r, sec(WED, 2));
    out[path] = { ok: o.ledger === 'OUTCOME_UNKNOWN' && o.ledger_status_unknown === true && o2.already_posted === true && w.ledger.entries.length === 1, o: o.ledger, o2: o2.ledger };
  }
  { const { w, heal } = setup('R36q'); const r = w.issue('R36-queue');
    w.gw.schedule(r, sec(WED, -60)); let res; try { res = w.gw.releaseQueue(WED); } catch (e) { return 'queue THROW: ' + e.message; }
    const o = res[0]; heal();
    out.queue = { ok: o.ledger === 'OUTCOME_UNKNOWN' && !o.executed && w.ledger.entries.length === 1 && w.gw.ledgerStatus('R36-queue', r.action).already_posted === true, o: o.ledger }; }
  { const { w, heal } = setup('R36e'); const o = escalate8000(w, 'R36-esc');
    let e1; try { e1 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 60)); } catch (e) { return 'escalation THROW: ' + e.message; }
    heal(); const e2 = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 62));
    out.escalation = { ok: e1.ledger === 'OUTCOME_UNKNOWN' && e1.ticket_status === 'OPEN' && e2.already_posted === true && e2.ticket_status === 'CLOSED' && w.ledger.entries.length === 1, e1: e1.ledger, e2: e2.reason }; }
  return Object.values(out).every(x => x.ok) || JSON.stringify(out);
});
check('R37', 'revisión previa r4 #3: un campo anidado miles de niveles (tipo, monto, moneda o destino) → REJECT por INPUT_INVALID, sin excepción y sin pago', () => {
  const w = world('protected');
  let nested = {}; for (let i = 0; i < 3000; i++) nested = { nested };
  const res = [];
  for (const k of ['type', 'amount', 'currency', 'destination']) {
    const r = JSON.parse(JSON.stringify(w.issue('R37-' + k))); r.action[k] = JSON.parse(JSON.stringify(nested));
    try { res.push(w.gw.directTool(r, WED)); } catch (e) { return k + ' THROW: ' + e.message; }
  }
  // La comprobación no depende del tamaño de pila de cada versión de Node: con 100 niveles (muy por debajo de cualquier límite de pila)
  // la entrada debe rechazarse POR su profundidad, no por otro motivo. Y con 3000 niveles, sin excepción.
  let n100 = {}; for (let i = 0; i < 100; i++) n100 = { n100 };
  const d100 = decide({ request_id: 'R37-100', action: n100 }, WED);
  if (!(d100.decision === 'REJECT' && JSON.stringify(d100.reasons).includes('nested deeper than 32 levels'))) return 'a 100 niveles no se rechazó por profundidad: ' + JSON.stringify(d100.reasons);
  let direct; try { direct = decide({ request_id: 'R37-direct', action: nested }, WED); } catch (e) { return 'decide THROW: ' + e.message; }
  return (res.every(o => o.decision === 'REJECT' && o.reasons.includes('INPUT_INVALID') && !o.executed) && direct.decision === 'REJECT' && w.ledger.entries.length === 0)
    || JSON.stringify(res.map(o => o.decision + '/' + o.reasons.join(',')));
});

// v0.6.4 — revisión previa (ChatGPT) de la r5: continuidad del resultado con fallos combinados.
check('R38', 'revisión previa r5 #1: resultado desconocido, luego congelan la cuenta y la consulta sigue caída → el nuevo intento es REJECT pero conserva ledger_status_unknown (directo, legacy y cola)', () => {
  const out = {};
  for (const path of ['directTool', 'legacyBatchApi', 'queue']) {
    const w = world('protected'), realPost = w.ledger.post.bind(w.ledger);
    w.ledger.post = (p, at) => { const r = realPost(p, at); if (r.accepted) throw new Error('LOST_CONFIRMATION'); return r; };
    w.ledger.status = () => { throw new Error('STATUS_UNAVAILABLE'); };
    const r = w.issue('R38-' + path);
    const run = at => { if (path !== 'queue') return w.gw[path](r, at); w.gw.schedule(r, sec(at, -60)); return w.gw.releaseQueue(at)[0]; };
    let o1, o2; try { o1 = run(WED); w.stateSource.set({ account_status: 'frozen' }); o2 = run(sec(WED, 120)); } catch (e) { return path + ' THROW: ' + e.message; }
    out[path] = { ok: o1.ledger === 'OUTCOME_UNKNOWN' && o2.decision === 'REJECT' && o2.ledger_status_unknown === true && !o2.executed && w.ledger.entries.length === 1, o1: o1.ledger, o2: o2.decision + '/' + o2.ledger + '/' + o2.ledger_status_unknown };
  }
  return Object.values(out).every(x => x.ok) || JSON.stringify(out);
});
check('R39', 'revisión previa r5 #2: la consulta de estado responde "ejecutado" sin asiento → estado desconocido explícito, sin excepción; la cola sigue con el siguiente elemento', () => {
  const w = world('protected'), realPost = w.ledger.post.bind(w.ledger);
  const a = w.issue('R39a'), b = w.issue('R39b');
  w.ledger.post = (p, at) => { const r = realPost(p, at); if (r.accepted && p.input.request_id === 'R39a') throw new Error('LOST_CONFIRMATION'); return r; };
  const realStatus = w.ledger.status.bind(w.ledger);
  w.ledger.status = id => id === 'R39a' ? { executed: true, entry: null } : realStatus(id);
  w.gw.schedule(a, sec(WED, -60)); w.gw.schedule(b, sec(WED, -60));
  let res; try { res = w.gw.releaseQueue(WED); } catch (e) { return 'THROW: ' + e.message; }
  return (res.length === 2 && res[0].ledger === 'OUTCOME_UNKNOWN' && res[0].ledger_status_unknown === true && res[1].executed === true && w.ledger.entries.length === 2)
    || JSON.stringify(res.map(o => o.ledger + '/' + o.ledger_status_unknown));
});
check('R40', 'revisión previa r5 #3: una solicitud anidada 10.000 niveles no tumba el encolado ni el camino vulnerable: rechazo explícito', () => {
  const deep = JSON.parse('{"n":'.repeat(10000) + '{}' + '}'.repeat(10000));
  const res = [];
  for (const mode of ['protected', 'vulnerable']) {
    const w = world(mode); const r = w.issue('R40-' + mode); r.action.type = deep;
    try { res.push(w.gw.schedule(r, WED)); res.push(w.gw.directTool(r, WED)); } catch (e) { return mode + ' THROW: ' + e.message; }
  }
  return (res[0].queued === false && res[2].queued === false && [res[1], res[3]].every(o => !o.executed)) || JSON.stringify(res.map(o => o.queued === undefined ? o.decision + '/' + o.executed : 'queued=' + o.queued));
});

// v0.6.5 — límite conocido de la v0.6.4 publicada (revisión de ChatGPT, 16-oct-2026): asiento con seq pero sin datos de la operación.
check('R41', 'v0.6.5: el libro responde "ejecutado" con un asiento sin monto, moneda o destino válidos → estado desconocido (OUTCOME_UNKNOWN / ledger_status_unknown), nunca REQUEST_ID_CONFLICT; el ticket no se cierra por eso; no hay segundo pago', () => {
  // Los asientos traen el request_id correcto: lo que falta o es inválido son los datos de la operación (el request_id ajeno lo cubre R42).
  const partial = [e => ({ seq: e.seq, request_id: e.request_id }), e => ({ seq: e.seq, request_id: e.request_id, amount: e.amount }),
    e => ({ seq: e.seq, request_id: e.request_id, amount: NaN, currency: e.currency, destination: e.destination }),
    e => ({ seq: e.seq, request_id: e.request_id, amount: e.amount, currency: e.currency, destination: { id: e.destination } })];
  const out = [];
  for (const [i, strip] of partial.entries()) {
    // directo: el envío registra y la confirmación se pierde con una excepción
    const w = world('protected'), realPost = w.ledger.post.bind(w.ledger); let first = true;
    w.ledger.post = (p, at) => { const r = realPost(p, at); if (first) { first = false; throw new Error('LOST'); } return r; };
    const realStatus = w.ledger.status.bind(w.ledger);
    w.ledger.status = id => { const st = realStatus(id); return st.executed ? { executed: true, entry: strip(st.entry) } : st; };
    const r = w.issue('R41-' + i);
    let o1, o2; try { o1 = w.gw.directTool(r, WED); o2 = w.gw.directTool(r, sec(WED, 2)); } catch (e) { return 'direct THROW: ' + e.message; }
    const directOk = o1.ledger === 'OUTCOME_UNKNOWN' && o1.ledger_status_unknown === true && !o1.request_id_conflict
      && !o2.executed && o2.ledger_status_unknown === true && !o2.request_id_conflict && w.ledger.entries.length === 1;
    // escalación: pagada con confirmación perdida; la consulta devuelve el asiento incompleto; luego responde bien
    const we = world('protected'), oe = escalate8000(we, 'R41e-' + i); loseFirstConfirmation(we);
    const realStatusE = we.ledger.status.bind(we.ledger); let broken = true;
    we.ledger.status = id => { const st = realStatusE(id); return broken && st.executed ? { executed: true, entry: strip(st.entry) } : st; };
    let e1, e2; try { e1 = we.gw.resolveEscalation(oe.ticket.ticket_id, approveResp(we, oe), sec(WED, 60)); broken = false;
      e2 = we.gw.resolveEscalation(oe.ticket.ticket_id, approveResp(we, oe), sec(WED, 62)); } catch (e) { return 'escalation THROW: ' + e.message; }
    const escOk = !e1.executed && !e1.request_id_conflict && e1.reason !== 'REQUEST_ID_CONFLICT' && e1.ticket_status !== 'CLOSED'
      && e2.already_posted === true && e2.reason === 'ALREADY_POSTED_EARLIER' && e2.ticket_status === 'CLOSED' && we.ledger.entries.length === 1;
    out.push({ i, directOk, escOk, o1: o1.ledger + '/' + o1.request_id_conflict, e1: e1.ledger + '/' + e1.reason + '/' + e1.ticket_status, e2: e2.reason });
  }
  return out.every(x => x.directOk && x.escOk) || JSON.stringify(out.filter(x => !x.directOk || !x.escOk));
});

check('R42', 'v0.6.5 revisión previa (ChatGPT): la consulta de estado devuelve el asiento de OTRA solicitud → estado desconocido, nunca "ya pagado" ni REQUEST_ID_CONFLICT; la solicitud consultada se resuelve por su cuenta y no hay doble pago', () => {
  const out = [];
  for (const amtB of [4000, 3000]) {   // B igual a A (monto, moneda, destino) o distinta
    const w = world('protected'); w.gw.directTool(w.issue('R42B', { action: { amount: amtB } }), WED);
    const o = escalateRiskUp(w, 'R42A');
    const realStatus = w.ledger.status.bind(w.ledger); w.ledger.status = () => realStatus('R42B');
    let r; try { r = w.gw.resolveEscalation(o.ticket.ticket_id, approveResp(w, o), sec(WED, 3)); } catch (e) { return 'THROW: ' + e.message; }
    out.push({ amtB, ok: !r.already_posted && !r.request_id_conflict && r.reason !== 'ALREADY_POSTED_EARLIER' && r.reason !== 'REQUEST_ID_CONFLICT'
      && r.executed === true && w.ledger.entries.length === 2 && w.ledger.entries.filter(e => e.request_id === 'R42A').length === 1, r: r.reason + '/' + r.ledger + '/' + r.ticket_status });
  }
  // camino directo: A se rechaza (cuenta congelada) y la consulta devuelve el asiento de B, o un asiento sin request_id
  for (const strip of [e => e, e => { const { request_id, ...rest } = e; return rest; }]) {
    const w = world('protected'); w.gw.directTool(w.issue('R42B2'), WED);
    w.stateSource.set({ account_status: 'frozen' });
    const realStatus = w.ledger.status.bind(w.ledger); w.ledger.status = () => { const st = realStatus('R42B2'); return { ...st, entry: strip(st.entry) }; };
    let d; try { d = w.gw.directTool(w.issue('R42A2'), sec(WED, 2)); } catch (e) { return 'THROW: ' + e.message; }
    out.push({ direct: true, ok: d.decision === 'REJECT' && !d.executed && !d.already_posted && !d.request_id_conflict && d.ledger_status_unknown === true && w.ledger.entries.length === 1,
      d: d.decision + '/' + d.already_posted + '/' + d.request_id_conflict + '/' + d.ledger_status_unknown });
  }
  return out.every(x => x.ok) || JSON.stringify(out.filter(x => !x.ok));
});

check('R43', 'v0.6.5 revisión previa r2 (ChatGPT): solicitud sin identificador válido (ausente, null, vacío, número) y el libro responde "ejecutado" con el mismo identificador o sin él → REJECT INPUT_INVALID sin "ya pagado", sin conflicto y sin estado desconocido', () => {
  const out = [];
  for (const [label, set] of [['ausente', r => { delete r.request_id; }], ['null', r => { r.request_id = null; }], ['vacío', r => { r.request_id = ''; }], ['42', r => { r.request_id = 42; }]]) {
    for (const withId of [true, false]) {
      const w = world('protected'), r = w.issue('R43'); set(r);
      const entry = { seq: 1, amount: r.action.amount, currency: r.action.currency, destination: r.action.destination };
      if (withId) entry.request_id = r.request_id;
      w.ledger.status = () => ({ executed: true, entry });
      let o; try { o = w.gw.directTool(r, WED); } catch (e) { return label + ' THROW: ' + e.message; }
      out.push({ label, withId, ok: o.decision === 'REJECT' && o.reasons.includes('INPUT_INVALID') && !o.executed && !o.already_posted && !o.request_id_conflict
        && !o.ledger_status_unknown && w.ledger.entries.length === 0, o: o.decision + '/' + o.already_posted + '/' + o.request_id_conflict + '/' + o.ledger_status_unknown });
    }
  }
  return out.every(x => x.ok) || JSON.stringify(out.filter(x => !x.ok));
});

function runChecks() {
  return CHECKS.map(c => {
    let r;
    try { r = c.fn(); } catch (e) { r = 'ERROR: ' + e.message; }
    return { id: c.id, name: c.name, ok: r === true, detail: r === true ? '' : String(r) };
  });
}

module.exports = { runChecks, runScenario, SCENARIOS, PATHS, world, MON, TUE, WED };
