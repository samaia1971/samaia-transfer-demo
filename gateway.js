// Capa de ejecución del agente (v0.5, endurecida en v0.6, v0.6.1 y v0.6.3), en dos versiones, con CUATRO caminos hacia el pago:
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
const { decide, signDecision, tooDeep, MAX_INPUT_DEPTH } = require('./decide');
const { TicketStore, resolveEscalation, derivedAuthorizationId } = require('./escalation');
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
    if (this.mode === 'vulnerable') return request === undefined || tooDeep(request, MAX_INPUT_DEPTH) ? null : clone(request);
    const rq = isObj(request) ? request : {};
    // v0.6.4: los valores se usan como claves solo si son texto y propios (no heredados): un objeto o "constructor" no rompe ni engaña.
    const own = (table, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(table, k) ? table[k] : undefined;
    const rid = isObj(rq.requested_by) && typeof rq.requested_by.id === 'string' ? rq.requested_by.id : undefined;
    const who = own(this.agents, rid);
    const stored = this.auths.get(isObj(rq.authorization) && typeof rq.authorization.id === 'string' ? rq.authorization.id : undefined);
    // v0.6.4: una autorización derivada de una escalación no se acepta en solicitudes ordinarias (solo la usa la escalación).
    const auth = stored && stored.derived_from === undefined ? stored : null;
    const a = isObj(rq.action) ? rq.action : {};
    const cat = own(this.catalog, a.type);
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

  // v0.6.4: si el sistema objetivo lanza una excepción, se trata como un rechazo (TARGET_ERROR); después se concilia con el libro.
  send(input, now, path, d) {
    const a = input.action;
    try {
      return this.ledger.post({ input: clone(input), amount: a.amount, currency: a.currency, destination: a.destination, path,
        decision: d ? d.record : null, signature: d ? d.signature : null }, now);
    } catch (e) { return { accepted: false, reason: 'TARGET_ERROR' }; }
  }

  // Único punto de paso en la versión protegida: decidir con fuentes controladas y, solo si CONTINUE, enviar.
  commit(request, now, path, pre) {
    const d = pre || this.decideNow(request, now, path);
    const base = { path, decision: d.record.decision, reasons: d.record.reasons.map(r => r.code) };
    // v0.6.4: antes de abrir un ticket o de informar "no se pagó", se pregunta al libro si esta solicitud ya quedó pagada.
    if (d.record.decision !== 'CONTINUE' && this.mode === 'protected') {
      const prior = this.ledgerStatus(d.input.request_id, d.input.action);
      if (prior && !prior.ledger_status_unknown) return { ...base, executed: false, ledger: 'NOT_SENT', ...prior };
      // v0.6.4: si no se pudo consultar el libro, la respuesta conserva que el resultado de un intento anterior sigue sin saberse.
      if (prior && prior.ledger_status_unknown) base.ledger_status_unknown = true;
    }
    if (d.record.decision === 'ESCALATE' && this.mode === 'protected') {
      const t = this.tickets.open(d.input, d.record, now);
      const { current_state, ...req } = d.input;
      this.pending.set(t.ticket_id, req);
      return { ...base, executed: false, ledger: 'NOT_SENT', ticket: t, input: d.input };
    }
    if (d.record.decision !== 'CONTINUE') return { ...base, executed: false, ledger: 'NOT_SENT' };
    const r = this.send(d.input, now, path, d);
    const out = { ...base, executed: r.accepted, ledger: r.accepted ? 'POSTED' : 'REFUSED:' + r.reason };
    return r.accepted ? out : this.withLedgerStatus(out, d.input.request_id, d.input.action);
  }

  // v0.6.3 — Confirmación perdida: si el libro dice que la operación ya se ejecutó, se le pregunta qué quedó registrado
  // en vez de suponer que no se pagó. Así un reintento no paga dos veces y el resultado no miente sobre el dinero.
  // v0.6.4: se consulta con CUALQUIER rechazo (por ejemplo DECISION_ALREADY_USED en un reintento del mismo segundo),
  // no solo con ALREADY_EXECUTED.
  withLedgerStatus(out, requestId, action) {
    const prior = this.ledgerStatus(requestId, action);
    if (!prior) return out;
    // v0.6.4: si el envío falló con una excepción y tampoco se pudo consultar el libro, el resultado es DESCONOCIDO, no "no enviado".
    if (prior.ledger_status_unknown && out.ledger === 'REFUSED:TARGET_ERROR') return { ...out, ...prior, ledger: 'OUTCOME_UNKNOWN' };
    return { ...out, ...prior };
  }
  // v0.6.4: "ya pagado" solo si el asiento con ese identificador es ESTA operación (monto, moneda, destino).
  // Si es otra, se informa un conflicto explícito: el identificador ya corresponde a una operación diferente.
  ledgerStatus(requestId, action) {
    if (typeof this.ledger.status !== 'function') return null;
    // v0.6.5 (revisión previa r2, ChatGPT): sin un identificador válido (texto no vacío, la misma regla de decide) no hay
    // pago que conciliar: no se consulta el libro, y ninguna respuesta suya se atribuye a esta solicitud.
    if (typeof requestId !== 'string' || requestId.length === 0) return null;
    let st;
    try { st = this.ledger.status(requestId); } catch { return { ledger_status_unknown: true }; }   // v0.6.4: la consulta falló
    if (!st || typeof st !== 'object' || typeof st.executed !== 'boolean') return { ledger_status_unknown: true };
    if (!st.executed) return null;
    // v0.6.4: una respuesta "ejecutado" sin asiento válido no se usa: el estado queda desconocido (no tumba la cola).
    const e = st.entry, a = isObj(action) ? action : {};
    if (!isObj(e) || typeof e.seq !== 'number') return { ledger_status_unknown: true };
    // v0.6.5 (revisión previa, ChatGPT): un asiento que no trae el identificador consultado no es evidencia sobre esta solicitud.
    if (e.request_id !== requestId) return { ledger_status_unknown: true };
    // v0.6.5: un asiento sin los datos de la operación (monto, moneda, destino) no permite decir si es esta operación u otra:
    // el estado queda desconocido, no se informa REQUEST_ID_CONFLICT ni se cierra el ticket por ese motivo.
    if (!(typeof e.amount === 'number' && Number.isFinite(e.amount) && typeof e.currency === 'string' && typeof e.destination === 'string')) return { ledger_status_unknown: true };
    const sameOperation = e.amount === a.amount && e.currency === a.currency && e.destination === a.destination;
    return sameOperation ? { already_posted: true, posted_entry: e.seq }
      : { request_id_conflict: true, posted_entry: e.seq, posted_effect: { amount: e.amount, currency: e.currency, destination: e.destination } };
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
    // v0.6.4: una solicitud anidada de más se rechaza antes de copiarla (la copia recursiva se caería).
    if (tooDeep(request, MAX_INPUT_DEPTH)) return { queued: false, decision_at_enqueue: 'REJECT', reason: 'MALFORMED_REQUEST' };
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
        // v0.6.4: tras una excepción no se afirma "no enviado": se informa lo que el libro tenga (o que no se sabe).
        const failed = { path: 'scheduled_queue', executed: false, decision: 'REJECT', reasons: ['ITEM_ERROR'], error: e.message, ledger: 'NOT_CONFIRMED' };
        return this.withLedgerStatus(failed,
          isObj(q.request) ? q.request.request_id : undefined, isObj(q.request) && isObj(q.request.action) ? q.request.action : undefined);
      }
    });
    this.queue = [];
    return out;
  }

  // Recorrido completo de una escalación: aprobación firmada → fuentes VIGENTES → nueva decisión → pago una sola vez.
  // v0.6.1: al resolver se vuelve a armar la solicitud desde las fuentes controladas (autorización, política,
  // registro de agentes, catálogo) y no desde lo guardado al abrir el ticket. Si alguna cambió, la aprobación
  // ya no corresponde a lo que se aprobó: REJECT y hace falta una solicitud nueva.
  // v0.6.4: cualquier respuesta sin pago nuevo (incluido TICKET_ALREADY_CLOSED) informa además lo que el libro tiene para esa solicitud.
  resolveEscalation(ticketId, response, now) {
    const out = this.resolveEscalationInner(ticketId, response, now), req = this.pending.get(ticketId);
    if (!req || out.executed || out.already_posted || out.request_id_conflict) return out;
    return this.withLedgerStatus(out, req.request_id, req.action);
  }

  resolveEscalationInner(ticketId, response, now) {
    const req = this.pending.get(ticketId), t = this.tickets.get(ticketId);
    if (!req || !t) return { path: 'escalation', executed: false, decision: 'REJECT', reason: 'TICKET_NOT_FOUND', ledger: 'NOT_SENT' };
    const derivedId = derivedAuthorizationId(req.authorization.id, ticketId);
    const closeTicket = reason => { t.status = 'CLOSED'; t.closed_at = now.toISOString(); t.close_reason = reason; this.auths.remove(derivedId); };
    // v0.6.4: PRIMERO se concilia con el libro (confirmación perdida), antes de evaluar si hoy se permitiría pagar.
    const prior = t.status === 'OPEN' && this.ledgerStatus(req.request_id, req.action);
    if (prior && prior.already_posted) { closeTicket('ALREADY_POSTED_EARLIER'); return { path: 'escalation', executed: false, decision: 'CONTINUE', reason: 'ALREADY_POSTED_EARLIER', ticket_status: 'CLOSED', ledger: 'ALREADY_POSTED', ...prior }; }
    if (prior && prior.request_id_conflict) { closeTicket('REQUEST_ID_CONFLICT'); return { path: 'escalation', executed: false, decision: 'REJECT', reason: 'REQUEST_ID_CONFLICT', ticket_status: 'CLOSED', ledger: 'NOT_SENT', ...prior }; }
    const fresh = this.canonicalRequest(req);
    if (t.status === 'OPEN' && requestHashOf(fresh) !== t.request_hash) {
      const changed = ['authorization', 'policy', 'requested_by', 'action'].filter(k => JSON.stringify(fresh[k]) !== JSON.stringify(req[k]));
      t.status = 'CLOSED'; t.closed_at = now.toISOString(); t.close_reason = 'REQUEST_CONDITIONS_CHANGED_WHILE_PENDING'; this.auths.remove(derivedAuthorizationId(req.authorization.id, ticketId));
      return { path: 'escalation', executed: false, decision: 'REJECT', reason: 'REQUEST_CONDITIONS_CHANGED_WHILE_PENDING', changed, ledger: 'NOT_SENT' };
    }
    const input = { ...fresh, current_state: this.state.read(now) };
    const commit = (recheck, re) => {   // solo con CONTINUE: firmar, registrar la autorización derivada y enviar al libro
      const signature = signDecision(recheck, this.keys.privateKey);
      this.decisions.push({ record: recheck, signature, path: 'escalation', at: iso(now) });
      this.auths.put(re.authorization, { budget_key: this.auths.budgetKey(req.authorization.id) });
      const res = this.send(re, now, 'escalation', { record: recheck, signature });
      // v0.6.4 (revisión de Grok): la derivada existe solo mientras se registra el pago; si el libro no lo acepta, se retira.
      // Un reintento del ticket la vuelve a crear con las fuentes vigentes.
      if (!res.accepted) this.auths.remove(re.authorization.id);
      // v0.6.3: si el pago ya había quedado registrado (la confirmación anterior se perdió), el ticket se cierra sin pagar otra vez.
      if (!res.accepted && this.withLedgerStatus({}, re.request_id, re.action).already_posted) return { accepted: true, already_posted: true, reason: 'ALREADY_POSTED_EARLIER' };
      return res;
    };
    const r = resolveEscalation(this.tickets, ticketId, input, response, now, this.approvers, { commit });
    // v0.6.4: cerrado el ticket (pagado, denegado, condiciones cambiadas o rechazado), la autorización derivada se retira.
    if (t.status === 'CLOSED') this.auths.remove(derivedId);
    if (r.commit) {
      const res = r.commit;
      if (res.already_posted) return { path: 'escalation', executed: false, already_posted: true, decision: 'CONTINUE', reason: res.reason, ticket_status: r.status, ledger: 'ALREADY_POSTED' };
      return { path: 'escalation', executed: res.accepted, decision: 'CONTINUE', reason: r.reason, ticket_status: r.status, ledger: res.accepted ? 'POSTED' : 'REFUSED:' + res.reason };
    }
    if (r.recheck) {
      const signature = signDecision(r.recheck, this.keys.privateKey);
      this.decisions.push({ record: r.recheck, signature, path: 'escalation', at: iso(now) });
    }
    return { path: 'escalation', executed: false, decision: r.outcome, reason: r.reason, ticket_status: r.status, reasons: r.recheck ? r.recheck.reasons.map(x => x.code) : [], changed: r.changed, ledger: 'NOT_SENT' };
  }
}

module.exports = { Gateway, DEFAULT_CATALOG };
