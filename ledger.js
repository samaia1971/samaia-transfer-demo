// Sistema objetivo SIMULADO: el libro contable del banco (v0.5, endurecido en v0.6).
// Es donde el pago ocurre de verdad. Tiene su propio registro, separado del registro de decisiones.
//  - Cada asiento queda encadenado por hash al anterior (para detectar asientos borrados o alterados en una exportación).
//  - Con enforce=true, el libro solo registra un pago si, EN EL MOMENTO DE REGISTRARLO:
//      trae una decisión CONTINUE firmada por el Execution Boundary, ligada a esa entrada exacta;
//      el pago coincide con la acción autorizada (monto, moneda, destino);
//      la decisión es reciente y no se usó antes;
//      la autorización existe en el registro, no fue alterada y no venció;
//      el estado relevante no cambió desde que se decidió (versión del estado);
//      esa operación no se ejecutó ya (una sola ejecución por request_id);
//      el acumulado de la autorización no supera su tope.
//    Todo esto se comprueba y se registra en un solo paso (en esta simulación, sin concurrencia real).
//  - Con enforce=false, acepta cualquier pago (así son muchos sistemas reales: confían en quien los llama).
// SIMULADO: en producción sería el core bancario o el sistema de pagos, con una transacción que verifique la versión.
'use strict';
const { canonical, sha256, verifyDecision } = require('./decide');
const { iso } = require('./sources');

const GENESIS = sha256('samaia-ledger-genesis');

class Ledger {
  constructor({ enforce = true, boundaryPublicKey = null, maxDecisionAgeSeconds = 5, authStore = null, stateSource = null } = {}) {
    this.enforce = enforce; this.pub = boundaryPublicKey; this.maxAge = maxDecisionAgeSeconds;
    this.auths = authStore; this.state = stateSource;
    this.entries = []; this.refusals = []; this.used = new Set(); this.executed = new Set(); this.consumed = new Map();
  }
  head() { return this.entries.length ? this.entries[this.entries.length - 1].entry_hash : GENESIS; }

  // Devuelve null si el pago es aceptable, o el motivo del rechazo.
  check(posting, now) {
    const input = posting && posting.input, a = input && input.action;
    if (!input || !a) return 'POSTING_MALFORMED';
    if (!posting.decision || !posting.signature) return 'DECISION_MISSING';
    let ok = false;
    try { ok = verifyDecision(posting.decision, posting.signature, this.pub); } catch { ok = false; }
    if (!ok) return 'DECISION_SIGNATURE_INVALID';
    const d = posting.decision, act = d.bound_to.action || {};
    if (d.decision !== 'CONTINUE') return 'DECISION_NOT_CONTINUE';
    if (d.bound_to.input_hash !== sha256(canonical(input)) || d.bound_to.request_id !== input.request_id) return 'DECISION_NOT_FOR_THIS_REQUEST';
    if (posting.amount !== act.amount || posting.currency !== act.currency || posting.destination !== act.destination) return 'POSTING_DIFFERS_FROM_AUTHORIZED';
    const age = (now.getTime() - Date.parse(d.bound_to.state_observed_at)) / 1000;
    if (!(age >= 0 && age <= this.maxAge)) return 'DECISION_STALE';
    const stored = this.auths && this.auths.get(input.authorization && input.authorization.id);
    if (!stored) return 'AUTHORIZATION_NOT_ON_RECORD';
    if (canonical(stored) !== canonical(input.authorization)) return 'AUTHORIZATION_ALTERED';
    if (!(Date.parse(stored.valid_until) > now.getTime())) return 'AUTHORIZATION_EXPIRED_AT_COMMIT';
    if (!this.state || input.current_state.version !== this.state.version) return 'STATE_CHANGED_SINCE_DECISION';
    if (this.used.has(d.decision_hash)) return 'DECISION_ALREADY_USED';
    if (this.executed.has(input.request_id)) return 'ALREADY_EXECUTED';
    const key = this.auths.budgetKey(stored.id);
    if ((this.consumed.get(key) || 0) + posting.amount > stored.scope.max_amount) return 'AUTHORIZATION_BUDGET_EXCEEDED';
    return null;
  }

  post(posting, now) {
    if (this.enforce) {
      const r = this.check(posting, now);
      if (r) {
        this.refusals.push({ request_id: posting && posting.input && posting.input.request_id || null, path: posting && posting.path || null, reason: r, at: iso(now) });
        return { accepted: false, reason: r };
      }
    }
    const input = posting.input;
    if (posting.decision) this.used.add(posting.decision.decision_hash);
    this.executed.add(input.request_id);
    if (this.auths && input.authorization && input.authorization.id) {
      const key = this.auths.budgetKey(input.authorization.id);
      this.consumed.set(key, (this.consumed.get(key) || 0) + posting.amount);
    }
    const e = { seq: this.entries.length + 1, request_id: input.request_id, amount: posting.amount, currency: posting.currency,
      destination: posting.destination, path: posting.path, posted_at: iso(now),
      decision_hash: posting.decision ? posting.decision.decision_hash : null, prev_hash: this.head() };
    e.entry_hash = sha256(canonical(e));
    this.entries.push(e);
    return { accepted: true, entry: { ...e } };
  }

  export() { return { entries: JSON.parse(JSON.stringify(this.entries)), head: this.head() }; }
}

// Comprueba la cadena de una exportación del libro. anchoredHead: la cabeza publicada por separado
// (sin ella, borrar las últimas entradas y recalcular la cabeza no se detecta).
function verifyChain(exp, anchoredHead) {
  if (!exp || !Array.isArray(exp.entries)) return { valid: false, reason: 'export malformed' };
  let prev = GENESIS;
  for (let i = 0; i < exp.entries.length; i++) {
    const { entry_hash, ...rest } = exp.entries[i];
    if (rest.prev_hash !== prev) return { valid: false, reason: `entry ${i + 1}: prev_hash mismatch (entry missing or reordered)` };
    if (sha256(canonical(rest)) !== entry_hash) return { valid: false, reason: `entry ${i + 1}: content altered` };
    prev = entry_hash;
  }
  if (exp.head !== prev) return { valid: false, reason: 'head does not match last entry' };
  if (anchoredHead && anchoredHead !== prev) return { valid: false, reason: 'head does not match anchored head (entries missing at the end or ledger rewritten)' };
  return { valid: true, entries: exp.entries.length };
}

module.exports = { Ledger, verifyChain, GENESIS, iso };
