// Sistema objetivo SIMULADO: el libro contable del banco (v0.5, endurecido en v0.6 y v0.6.3).
// Es donde el pago ocurre de verdad. Tiene su propio registro, separado del registro de decisiones.
//  - Cada asiento queda encadenado por hash al anterior (para detectar asientos borrados o alterados en una exportación).
//  - Con enforce=true, el libro solo registra un pago si, EN EL MOMENTO DE REGISTRARLO:
//      trae una decisión CONTINUE firmada por el Execution Boundary, ligada a esa entrada exacta;
//      el pago coincide con la acción autorizada (monto, moneda, destino);
//      la decisión es reciente y no se usó antes;
//      la autorización existe en el registro, no fue alterada y no venció;
//      el estado relevante no cambió desde que se decidió (versión del estado);
//      la política vigente es la misma con la que se decidió (v0.6.3; antes solo se comparaba el estado);
//      esa operación no se ejecutó ya (una sola ejecución por request_id);
//      el acumulado de la autorización no supera su tope.
//    Todo esto se comprueba y se registra en un solo paso síncrono, sin esperas entre comprobar y registrar.
//    v0.6.3: test-concurrency.js lo prueba con varios procesos reales enviando a la vez a un mismo libro, y muestra
//    que un libro que espera entre comprobar y registrar paga de más. No prueba un libro repartido en varias máquinas.
//  - status(request_id) dice si una operación ya quedó registrada: sirve cuando el pago se registró pero la
//    confirmación se perdió por el camino (v0.6.3).
//  - Con enforce=false, acepta cualquier pago (así son muchos sistemas reales: confían en quien los llama).
// SIMULADO: en producción sería el core bancario o el sistema de pagos, con una transacción que verifique la versión.
'use strict';
const { canonical, sha256, verifyDecision } = require('./decide');
const { iso } = require('./sources');

const GENESIS = sha256('samaia-ledger-genesis');

class Ledger {
  constructor({ enforce = true, boundaryPublicKey = null, maxDecisionAgeSeconds = 5, authStore = null, stateSource = null, policySource = null } = {}) {
    this.enforce = enforce; this.pub = boundaryPublicKey; this.maxAge = maxDecisionAgeSeconds;
    this.auths = authStore; this.state = stateSource; this.policy = policySource;
    this.entries = []; this.refusals = []; this.used = new Set(); this.executed = new Set(); this.consumed = new Map();
  }
  head() { return this.entries.length ? this.entries[this.entries.length - 1].entry_hash : GENESIS; }

  // Devuelve null si el pago es aceptable, o el motivo del rechazo.
  check(posting, now) {
    const input = posting && posting.input, a = input && input.action;
    if (!input || !a) return 'POSTING_MALFORMED';
    if (typeof posting.path !== 'string' || posting.path.length > 64) return 'POSTING_MALFORMED';   // v0.6.4: el camino es un texto corto
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
    // v0.6.4: una autorización derivada de una escalación solo vale para su solicitud y su acción, y solo si la madre no cambió.
    if (stored.derived_from !== undefined) {
      const parent = this.auths.get(stored.derived_from);
      if (!parent || sha256(canonical(parent)) !== stored.parent_hash) return 'PARENT_AUTHORIZATION_CHANGED';
      const b = stored.bound_action || {};
      if (stored.bound_request_id !== input.request_id || b.amount !== a.amount || b.currency !== a.currency || b.destination !== a.destination) return 'DERIVED_AUTHORIZATION_NOT_FOR_THIS_REQUEST';
    }
    if (!(Date.parse(stored.valid_until) > now.getTime())) return 'AUTHORIZATION_EXPIRED_AT_COMMIT';
    if (!this.state || input.current_state.version !== this.state.version) return 'STATE_CHANGED_SINCE_DECISION';
    if (typeof this.policy !== 'function' || canonical(this.policy()) !== canonical(input.policy) || d.bound_to.policy_hash !== sha256(canonical(input.policy))) return 'POLICY_CHANGED_SINCE_DECISION';
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
    // v0.6.4: primero se arma el asiento (lo que puede fallar); solo si sale bien se toca el estado del libro.
    const e = { seq: this.entries.length + 1, request_id: input.request_id, amount: posting.amount, currency: posting.currency,
      destination: posting.destination, path: posting.path, posted_at: iso(now),
      decision_hash: posting.decision ? posting.decision.decision_hash : null, prev_hash: this.head() };
    try { e.entry_hash = sha256(canonical(e)); } catch {
      this.refusals.push({ request_id: null, path: null, reason: 'POSTING_NOT_SERIALIZABLE', at: iso(now) });
      return { accepted: false, reason: 'POSTING_NOT_SERIALIZABLE' };
    }
    if (posting.decision) this.used.add(posting.decision.decision_hash);
    this.executed.add(input.request_id);
    if (this.auths && input.authorization && input.authorization.id) {
      const key = this.auths.budgetKey(input.authorization.id);
      this.consumed.set(key, (this.consumed.get(key) || 0) + posting.amount);
    }
    this.entries.push(e);
    return { accepted: true, entry: { ...e } };
  }

  status(requestId) {
    const e = this.entries.find(x => x.request_id === requestId);
    return e ? { executed: true, entry: { ...e } } : { executed: false };
  }

  export() { return { entries: JSON.parse(JSON.stringify(this.entries)), head: this.head() }; }
}

// Comprueba la cadena de una exportación del libro. anchoredHead: la cabeza publicada por separado
// (sin ella, borrar las últimas entradas y recalcular la cabeza no se detecta).
function verifyChain(exp, anchoredHead) {
  if (!exp || !Array.isArray(exp.entries)) return { valid: false, reason: 'export malformed' };
  let prev = GENESIS;
  for (let i = 0; i < exp.entries.length; i++) {
    if (!exp.entries[i] || typeof exp.entries[i] !== 'object') return { valid: false, reason: `entry ${i + 1}: malformed` };
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
