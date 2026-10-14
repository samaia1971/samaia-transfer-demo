// Capa de ejecución del agente (v0.5, endurecida en v0.6 y v0.6.1), en dos versiones, con CUATRO caminos hacia el pago:
//   direct_tool       la herramienta normal del agente
//   legacy_batch_api  una API vieja de pagos por lote que sigue conectada
//   scheduled_queue   pagos programados: se encolan un día y se liberan otro
//   escalation        (versión protegida) aprobación humana firmada → nueva decisión con fuentes vigentes → pago
//
// mode='vulnerable': confía en lo que declara la solicitud (quién ejecuta, autorización, política);
//   el camino principal pasa por decide(), pero la API legacy escribe directo en el libro y la cola
//   decide al ENCOLAR y libera días después con esa decisión vieja.
// mode='protected': arma la entrada desde FUENTES CONTROLADAS (registro de agentes, registro de autorizaciones,
//   política vigente, catálogo de operaciones, estado actual). De la solicitud solo toma request_id, tipo, monto,
//   moneda, destino y los identificadores. Si la operación es irreversible lo dice el catálogo, no el agente (v0.6.1).
//   Los cuatro caminos pasan por la misma decisión firmada antes de enviar al libro.
'use strict';
const { decide, signDecision } = require('./decide');
const { TicketStore, resolveEscalation } = require('./escalation');
const { requestHashOf } = require('./decide');
const { iso, clone } = require('./sources');

// Catálogo de operaciones (fuente controlada): qué operaciones son irreversibles. Tipo desconocido → irreversible.
const DEFAULT_CATALOG = { transfer: { irreversible: true }, refund: { irreversible: true } };
const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);

class Gateway {
  constructor({ mode, ledger, stateSource, keys, authStore, agents = {}, policy, approvers = {}, actionCatalog = DEFAULT_CATALOG }) {
    if (!['vulnerable', 'protected'].includes(mode)) throw new Error('mode must be vulnerable or protected');
    this.mode = mode; this.ledger = ledger; this.state = stateSource; this.keys = keys;
    this.auths = authStore; this.agents = agents; this.policy = policy; this.approvers = approvers;
    this.catalog = actionCatalog;
    this.decisions = [];  // registros firmados (lo que el verificador puede revisar)
    this.log = [];        // log operativo del gateway (el verificador NO lo usa)
    this.queue = [];
    this.tickets = new TicketStore(); this.pending = new Map();
  }

  // Qué se decide: en la versión protegida, nada de identidad, autorización ni política sale de la solicitud.
  canonicalRequest(request) {
    if (this.mode === 'vulnerable') return request === undefined ? null : clone(request);
    const rq = isObj(request) ? request : {};
    const rid = isObj(rq.requested_by) ? rq.requested_by.id : undefined;
    const who = this.agents[rid];
    const auth = this.auths.get(isObj(rq.authorization) ? rq.authorization.id : undefined);
    const a = isObj(rq.action) ? rq.action : {};
    const cat = this.catalog[a.type];
    return {
      request_id: rq.request_id,
      action: { type: a.type, amount: a.amount, currency: a.currency, destination: a.destination,
        irreversible: cat ? cat.irreversible === true : true },
      requested_by: { id: String(rid), kind: who ? who.kind : 'unregistered' },
      authorization: auth || { id: 'not-on-record' },
      policy: clone(this.policy),
    };
  }

  decideNow(request, now, path) {
    const input = { ...this.canonicalRequest(request), current_state: this.state.read(now) };
    const record = decide(input, now);
    const signature = signDecision(record, this.keys.privateKey);
    this.decisions.push({ record, signature, path, at: iso(now) });
    this.log.push({ path, request_id: isObj(request) ? request.request_id : null, decision: record.decision, reasons: record.reasons.map(r => r.code), at: iso(now) });
    return { record, signature, input };
  }

  send(input, now, path, d) {
    const a = input.action;
    return this.ledger.post({ input: clone(input), amount: a.amount, currency: a.currency, destination: a.destination, path,
      decision: d ? d.record : null, signature: d ? d.signature : null }, now);
  }

  // Único punto de paso en la versión protegida: decidir con fuentes controladas y, solo si CONTINUE, enviar.
  commit(request, now, path, pre) {
    const d = pre || this.decideNow(request, now, path);
    const base = { path, decision: d.record.decision, reasons: d.record.reasons.map(r => r.code) };
    if (d.record.decision === 'ESCALATE' && this.mode === 'protected') {
      const t = this.tickets.open(d.input, d.record, now);
      const { current_state, ...req } = d.input;
      this.pending.set(t.ticket_id, req);
      return { ...base, executed: false, ledger: 'NOT_SENT', ticket: t, input: d.input };
    }
    if (d.record.decision !== 'CONTINUE') return { ...base, executed: false, ledger: 'NOT_SENT' };
    const r = this.send(d.input, now, path, d);
    return { ...base, executed: r.accepted, ledger: r.accepted ? 'POSTED' : 'REFUSED:' + r.reason };
  }

  directTool(request, now) { return this.commit(request, now, 'direct_tool'); }

  legacyBatchApi(request, now) {
    if (this.mode === 'protected') return this.commit(request, now, 'legacy_batch_api');
    const r = this.send(clone(request), now, 'legacy_batch_api', null);   // vulnerable: directo al libro
    return { path: 'legacy_batch_api', executed: r.accepted, decision: 'NONE', reasons: [], ledger: r.accepted ? 'POSTED' : 'REFUSED:' + r.reason };
  }

  schedule(request, now) {
    // v0.6.1: una solicitud sin forma mínima no entra a la cola (resultado explícito, no excepción).
    if (this.mode === 'protected' && !(isObj(request) && typeof request.request_id === 'string' && isObj(request.action)))
      return { queued: false, decision_at_enqueue: 'REJECT', reason: 'MALFORMED_REQUEST' };
    if (this.mode === 'vulnerable') {
      const d = this.decideNow(request, now, 'scheduled_queue');   // decide al encolar
      this.queue.push({ request: clone(request), d });
      return { queued: true, decision_at_enqueue: d.record.decision };
    }
    this.queue.push({ request: clone(request) });                  // protegido: no decide todavía
    return { queued: true, decision_at_enqueue: 'DEFERRED' };
  }

  releaseQueue(now) {
    // v0.6.1: un elemento que falla no detiene la cola; queda un resultado explícito para él.
    const out = this.queue.map(q => {
      try {
        if (this.mode === 'vulnerable') {
          if (q.d.record.decision !== 'CONTINUE') return { path: 'scheduled_queue', executed: false, decision: q.d.record.decision, reasons: [], ledger: 'NOT_SENT' };
          return this.commit(q.request, now, 'scheduled_queue', q.d);  // usa la decisión del día en que se encoló
        }
        return this.commit(q.request, now, 'scheduled_queue');         // decide de nuevo al liberar
      } catch (e) {
        return { path: 'scheduled_queue', executed: false, decision: 'REJECT', reasons: ['ITEM_ERROR'], error: e.message, ledger: 'NOT_SENT' };
      }
    });
    this.queue = [];
    return out;
  }

  // Recorrido completo de una escalación: aprobación firmada → fuentes VIGENTES → nueva decisión → pago una sola vez.
  // v0.6.1: al resolver se vuelve a armar la solicitud desde las fuentes controladas (autorización, política,
  // registro de agentes, catálogo) y no desde lo guardado al abrir el ticket. Si alguna cambió, la aprobación
  // ya no corresponde a lo que se aprobó: REJECT y hace falta una solicitud nueva.
  resolveEscalation(ticketId, response, now) {
    const req = this.pending.get(ticketId), t = this.tickets.get(ticketId);
    if (!req || !t) return { path: 'escalation', executed: false, decision: 'REJECT', reason: 'TICKET_NOT_FOUND', ledger: 'NOT_SENT' };
    const fresh = this.canonicalRequest(req);
    if (t.status === 'OPEN' && requestHashOf(fresh) !== t.request_hash) {
      const changed = ['authorization', 'policy', 'requested_by', 'action'].filter(k => JSON.stringify(fresh[k]) !== JSON.stringify(req[k]));
      t.status = 'CLOSED'; t.closed_at = now.toISOString(); t.close_reason = 'REQUEST_CONDITIONS_CHANGED_WHILE_PENDING';
      return { path: 'escalation', executed: false, decision: 'REJECT', reason: 'REQUEST_CONDITIONS_CHANGED_WHILE_PENDING', changed, ledger: 'NOT_SENT' };
    }
    const input = { ...fresh, current_state: this.state.read(now) };
    const commit = (recheck, re) => {   // solo con CONTINUE: firmar, registrar la autorización derivada y enviar al libro
      const signature = signDecision(recheck, this.keys.privateKey);
      this.decisions.push({ record: recheck, signature, path: 'escalation', at: iso(now) });
      this.auths.put(re.authorization, { budget_key: this.auths.budgetKey(req.authorization.id) });
      return this.send(re, now, 'escalation', { record: recheck, signature });
    };
    const r = resolveEscalation(this.tickets, ticketId, input, response, now, this.approvers, { commit });
    if (r.commit) {
      const res = r.commit;
      return { path: 'escalation', executed: res.accepted, decision: 'CONTINUE', reason: r.reason, ticket_status: r.status, ledger: res.accepted ? 'POSTED' : 'REFUSED:' + res.reason };
    }
    if (r.recheck) {
      const signature = signDecision(r.recheck, this.keys.privateKey);
      this.decisions.push({ record: r.recheck, signature, path: 'escalation', at: iso(now) });
    }
    return { path: 'escalation', executed: false, decision: r.outcome, reason: r.reason, ticket_status: r.status, reasons: r.recheck ? r.recheck.reasons.map(x => x.code) : [], ledger: 'NOT_SENT' };
  }
}

module.exports = { Gateway, DEFAULT_CATALOG };
