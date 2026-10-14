// v0.6 — Fuentes CONTROLADAS (simuladas). El agente no las puede modificar.
// En producción serían: el IAM (quién es quién), el registro de autorizaciones, la política vigente
// y los sistemas de estado (aprobadores, límites, retenciones de cumplimiento, riesgo).
'use strict';
const iso = d => d.toISOString().replace(/\.\d+Z$/, 'Z');
const clone = x => JSON.parse(JSON.stringify(x));

// Estado actual. version sube con cada cambio: permite saber si algo cambió entre decidir y registrar el pago.
class StateSource {
  constructor(state, lagSeconds = 1) { this.state = { ...state }; this.lagSeconds = lagSeconds; this.version = 1; }
  set(patch) { Object.assign(this.state, patch); this.version++; }
  read(now) { return { observed_at: iso(new Date(now.getTime() - this.lagSeconds * 1000)), version: this.version, ...this.state }; }
}

// Registro de autorizaciones emitidas. budget_key agrupa autorizaciones derivadas (por ejemplo, de una escalación)
// para que compartan el mismo tope acumulado.
class AuthorizationStore {
  constructor() { this.items = new Map(); this.meta = new Map(); }
  put(auth, meta = {}) { this.items.set(auth.id, clone(auth)); this.meta.set(auth.id, { budget_key: meta.budget_key || auth.id }); }
  has(id) { return this.items.has(id); }
  get(id) { return this.items.has(id) ? clone(this.items.get(id)) : null; }
  budgetKey(id) { return (this.meta.get(id) || {}).budget_key || id; }
}

module.exports = { StateSource, AuthorizationStore, iso, clone };
