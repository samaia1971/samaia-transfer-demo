// SAMAIA — Determinación de admisibilidad en el Execution Boundary
// Caso: agente de IA que ejecuta una transferencia / reembolso ya autorizado.
// PROPUESTA EXPERIMENTAL para este caso (reglas de la v0.4, 11-oct-2026; el registro incluye la acción autorizada desde la v0.6
// y el hash de la política desde la v0.6.3). No es una regla validada para todo SAMAIA.
// v0.6.3: destino dentro del alcance de la autorización (scope.destinations) y condición opcional beneficiary_record
// (versión de los datos del beneficiario en el maestro de proveedores).
// Salida: CONTINUE | ESCALATE | REJECT. No ejecuta la transferencia: el sistema transaccional debe respetar la decisión.
'use strict';
const crypto = require('crypto');

const CONDITION_KEYS = ['approver_status', 'amount_limit', 'account_status', 'risk_level'];
// Condiciones opcionales: solo se exigen y comparan si la autorización las fijó al otorgarse.
const OPTIONAL_CONDITION_KEYS = ['beneficiary_record'];
const conditionKeysOf = au => CONDITION_KEYS.concat(OPTIONAL_CONDITION_KEYS.filter(k => isObj(au && au.conditions_at_grant) && k in au.conditions_at_grant));
const DOMAINS = {
  approver_status: ['active', 'suspended', 'revoked'],
  account_status: ['open', 'under_review', 'frozen', 'closed'],
  risk_level: ['low', 'medium', 'high'],
};
const MAX_CLOCK_SKEW_SECONDS = 2;

const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const isStr = x => typeof x === 'string' && x.length > 0;
const isDate = x => isStr(x) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(x) && !Number.isNaN(Date.parse(x));
// Un valor de condición es válido si pertenece a su dominio; 'unknown' solo se admite en el estado actual.
function validCondition(k, v, allowUnknown) {
  if (allowUnknown && v === 'unknown') return true;
  if (k === 'amount_limit') return typeof v === 'number' && Number.isFinite(v) && v >= 0;
  if (k === 'beneficiary_record') return isStr(v) && v !== 'unknown';
  return DOMAINS[k].includes(v);
}

// Forma canónica (claves ordenadas) para que el hash no dependa del orden de los campos.
function canonical(x) {
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (isObj(x)) return '{' + Object.keys(x).sort().map(k => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
  return JSON.stringify(x);
}
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
// v0.6.4: profundidad máxima de la entrada, medida sin recursión.
const MAX_INPUT_DEPTH = 32;
function tooDeep(x, max) {
  const stack = [[x, 0]];
  while (stack.length) {
    const [v, depth] = stack.pop();
    if (v === null || typeof v !== 'object') continue;
    if (depth >= max) return true;
    for (const k of Object.keys(v)) stack.push([v[k], depth + 1]);
  }
  return false;
}

function validate(p, now) {
  const e = [];
  if (!isObj(p)) return ['input is not an object'];
  if (!isStr(p.request_id)) e.push('request_id');
  const a = p.action, r = p.requested_by, au = p.authorization, s = p.current_state, pol = p.policy;
  if (!isObj(a) || !isStr(a.type) || typeof a.amount !== 'number' || !Number.isFinite(a.amount) || !(a.amount > 0)
      || !isStr(a.currency) || !isStr(a.destination) || typeof a.irreversible !== 'boolean') e.push('action');
  if (!isObj(r) || !isStr(r.id) || !['human', 'ai_agent', 'rule_engine'].includes(r.kind)) e.push('requested_by');
  if (!isObj(au) || !isStr(au.id) || !isStr(au.granted_by) || !isDate(au.granted_at) || !isDate(au.valid_until)
      || !isObj(au.scope) || typeof au.scope.max_amount !== 'number' || !Array.isArray(au.scope.action_types)
      || ('destinations' in au.scope && !(Array.isArray(au.scope.destinations) && au.scope.destinations.length > 0 && au.scope.destinations.every(isStr)))) e.push('authorization');
  else {
    if (!isObj(au.conditions_at_grant) || conditionKeysOf(au).some(k => !validCondition(k, au.conditions_at_grant[k], false)))
      e.push('authorization.conditions_at_grant (all four conditions must be present and known)');
    if (Date.parse(au.granted_at) > now.getTime() + MAX_CLOCK_SKEW_SECONDS * 1000) e.push('authorization.granted_at is in the future');
  }
  if (!isObj(s) || !isDate(s.observed_at)) e.push('current_state.observed_at');
  else {
    if (Date.parse(s.observed_at) > now.getTime() + MAX_CLOCK_SKEW_SECONDS * 1000) e.push('current_state.observed_at is in the future');
    const bad = CONDITION_KEYS.concat(OPTIONAL_CONDITION_KEYS).filter(k => k in s && s[k] !== undefined && s[k] !== null && !validCondition(k, s[k], true));
    if (bad.length) e.push('current_state values out of domain: ' + bad.join(', '));
  }
  if (!isObj(pol) || typeof pol.max_state_age_seconds !== 'number' || !(pol.max_state_age_seconds > 0)
      || typeof pol.human_review_above_amount !== 'number') e.push('policy');
  return e;
}

function decide(input, now = new Date(), opts = {}) {
  let p;
  try { p = JSON.parse(JSON.stringify(input)); } catch { p = null; }   // lectura única (lección N-8)
  // v0.6.4: una entrada anidada de más se rechaza ANTES de recorrerla para el hash (el recorrido recursivo se caería).
  // El registro de rechazo no vuelve a tocar el objeto peligroso: solo guarda el request_id si es texto.
  if (tooDeep(p, MAX_INPUT_DEPTH)) {
    const safe = { request_id: isObj(p) && isStr(p.request_id) ? p.request_id : null };
    return finish(safe, sha256('INPUT_TOO_DEEP'), sha256('INPUT_TOO_DEEP'), 'REJECT', [{ code: 'INPUT_INVALID', detail: `input nested deeper than ${MAX_INPUT_DEPTH} levels` }]);
  }
  const inputHash = sha256(canonical(p));
  const requestHash = requestHashOf(p);
  const errors = validate(p, now);
  if (errors.length) return finish(p, inputHash, requestHash, 'REJECT', [{ code: 'INPUT_INVALID', detail: errors.join('; ') }]);

  const { action: a, requested_by: r, authorization: au, current_state: s, policy: pol } = p;
  const reasons = [];
  // --- REJECT ---
  if (Date.parse(au.valid_until) <= now.getTime()) reasons.push({ code: 'AUTHORIZATION_EXPIRED' });
  if (!au.scope.action_types.includes(a.type)) reasons.push({ code: 'OUT_OF_SCOPE_ACTION' });
  if (a.amount > au.scope.max_amount) reasons.push({ code: 'OUT_OF_SCOPE_AMOUNT' });
  if (Array.isArray(au.scope.destinations) && !au.scope.destinations.includes(a.destination)) reasons.push({ code: 'OUT_OF_SCOPE_DESTINATION', detail: `${a.destination} not in authorized destinations` });
  if (s.approver_status === 'revoked' || s.approver_status === 'suspended') reasons.push({ code: 'AUTHORITY_NOT_ACTIVE', detail: `${au.granted_by} is ${s.approver_status}` });
  if (typeof s.amount_limit === 'number' && a.amount > s.amount_limit) reasons.push({ code: 'LIMIT_EXCEEDED_NOW', detail: `amount ${a.amount} > current limit ${s.amount_limit}` });
  if (s.account_status === 'closed' || s.account_status === 'frozen') reasons.push({ code: 'ACCOUNT_NOT_OPERABLE', detail: s.account_status });
  if (reasons.length) return finish(p, inputHash, requestHash, 'REJECT', reasons);
  // --- ESCALATE ---
  const keys = conditionKeysOf(au);
  const unknown = keys.filter(k => s[k] === undefined || s[k] === null || s[k] === 'unknown');
  if (unknown.length) reasons.push({ code: 'STATE_UNKNOWN', detail: unknown.join(', ') });
  const age = (now.getTime() - Date.parse(s.observed_at)) / 1000;
  if (age > pol.max_state_age_seconds) reasons.push({ code: 'STATE_STALE', detail: `state is ${Math.round(age)}s old (max ${pol.max_state_age_seconds}s)` });
  const changed = keys.filter(k => !unknown.includes(k) && au.conditions_at_grant[k] !== s[k]);
  if (changed.length) reasons.push({ code: 'CONDITIONS_CHANGED_SINCE_GRANT', detail: changed.map(k => `${k}: ${au.conditions_at_grant[k]} -> ${s[k]}`).join('; ') });
  const humanApproved = typeof opts.verifyHumanApproval === 'function' && opts.verifyHumanApproval(p) === true;
  if (a.irreversible && r.kind !== 'human' && a.amount > pol.human_review_above_amount && !humanApproved) reasons.push({ code: 'IRREVERSIBLE_REQUIRES_HUMAN', detail: `${r.kind} executing irreversible amount ${a.amount}` });
  if (reasons.length) return finish(p, inputHash, requestHash, 'ESCALATE', reasons);
  return finish(p, inputHash, requestHash, 'CONTINUE', [{ code: 'ADMISSIBLE_NOW', detail: 'all checks of this version passed' }]);
}

// Registro de decisión: incluye el hash de la ENTRADA COMPLETA (acción, autorización, estado y política).
// decision_hash detecta cambios accidentales y liga la decisión a esa entrada exacta.
// No prueba autenticidad: cualquiera podría recalcularlo. Para eso está signDecision().
// Hash de la solicitud: qué se quiere hacer, quién, con qué autorización original y bajo qué política.
// Excluye el estado actual (que debe poder refrescarse) y cualquier aprobación adjunta.
function requestHashOf(p) {
  if (!isObj(p)) return sha256('null');
  const au = isObj(p.authorization) ? { ...p.authorization } : p.authorization;
  if (isObj(au)) { delete au.human_approval; }
  return sha256(canonical({ request_id: p.request_id, action: p.action, requested_by: p.requested_by, authorization: au, policy: p.policy }));
}

function finish(p, inputHash, requestHash, decision, reasons) {
  const record = {
    version: 'samaia-transfer-demo/0.6.5',
    decision, reasons,
    bound_to: {
      request_id: p && p.request_id || null,
      authorization_id: p && p.authorization && p.authorization.id || null,
      state_observed_at: p && p.current_state && p.current_state.observed_at || null,
      input_hash: inputHash,
      request_hash: requestHash,
      policy_hash: p && isObj(p.policy) ? sha256(canonical(p.policy)) : null,
      action: p && isObj(p.action) ? { type: p.action.type, amount: p.action.amount, currency: p.action.currency, destination: p.action.destination } : null,
    },
  };
  record.decision_hash = sha256(canonical(record));
  return record;
}

// Firma Ed25519 del registro: con la clave pública del evaluador se puede comprobar que la decisión
// la emitió quien tiene la clave privada y que no se alteró después.
function signDecision(record, privateKey) {
  return crypto.sign(null, Buffer.from(canonical(record)), privateKey).toString('base64');
}
function verifyDecision(record, signature, publicKey) {
  const { decision_hash, ...rest } = record;
  if (sha256(canonical(rest)) !== decision_hash) return false;
  return crypto.verify(null, Buffer.from(canonical(record)), publicKey, Buffer.from(signature, 'base64'));
}

module.exports = { tooDeep, MAX_INPUT_DEPTH, decide, requestHashOf, signDecision, verifyDecision, canonical, sha256, CONDITION_KEYS, OPTIONAL_CONDITION_KEYS, conditionKeysOf };
