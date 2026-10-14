// Ciclo de vida de un ESCALATE — v0.4 (cierre del ticket revisado en v0.6.1).
// Nada se ejecuta mientras el caso está abierto. Reglas:
//  - El caso (ticket) queda ligado a la solicitud exacta: qué, quién, autorización original y política (request_hash).
//    Al resolverse, la acción se re-evalúa con el ESTADO ACTUAL que se entregue en ese momento (fresco),
//    para que una aprobación que tarda no quede atrapada en un estado viejo.
//  - Se resuelve UNA sola vez. Cerrado, vencido, con fecha inválida o de otra solicitud → REJECT (detalle más abajo).
//  - Solo aprueba quien figura en el DIRECTORIO DE AUTORIDAD como persona activa con permiso para aprobar
//    escalaciones y con tope de monto suficiente, y la aprobación debe venir FIRMADA con su clave (Ed25519)
//    sobre ese ticket y esa solicitud. Declarar un nombre o "soy humano" no basta.
//  - Si aprueba: nueva autorización ligada a las condiciones actuales, con la aprobación firmada adjunta,
//    y la acción vuelve a pasar por decide() completa. El ejecutor NO cambia: no se puede reclasificar como humano.
// SIMULADO EN ESTA DEMO: el directorio de autoridad y el almacén de tickets viven en memoria.
// En producción vendrían del IAM de la organización y de la capa de enforcement.
'use strict';
const crypto = require('crypto');
const { decide, canonical, sha256, requestHashOf } = require('./decide');

const isDate = x => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(x) && !Number.isNaN(Date.parse(x));

class TicketStore {
  constructor() { this.tickets = new Map(); }
  open(input, decision, now, timeoutSeconds = 900) {
    if (decision.decision !== 'ESCALATE') throw new Error('only ESCALATE decisions open a ticket');
    const t = { ticket_id: crypto.randomUUID(), status: 'OPEN', request_id: input.request_id,
      request_hash: decision.bound_to.request_hash, reasons: decision.reasons.map(r => r.code),
      opened_at: now.toISOString(), deadline: new Date(now.getTime() + timeoutSeconds * 1000).toISOString() };
    this.tickets.set(t.ticket_id, t);
    return { ...t };
  }
  get(id) { return this.tickets.get(id); }
}

// Lo que firma el aprobador: el ticket, la solicitud, la acción concreta y su decisión.
function approvalPayload(ticket, input, approverId) {
  return { ticket_id: ticket.ticket_id, request_id: ticket.request_id, request_hash: ticket.request_hash,
           action: input.action, approver: approverId, decision: 'approve' };
}
function signApproval(ticket, input, approverId, privateKey) {
  return crypto.sign(null, Buffer.from(canonical(approvalPayload(ticket, input, approverId))), privateKey).toString('base64');
}

// Verificación de una aprobación contra el directorio de autoridad.
function checkApprover(registry, approverId, amount) {
  const e = registry && registry[approverId];
  if (!e) return 'APPROVER_NOT_IN_DIRECTORY';
  if (e.kind !== 'human') return 'APPROVER_NOT_HUMAN';
  if (e.status !== 'active') return 'APPROVER_NOT_ACTIVE';
  if (e.can_approve_escalations !== true) return 'APPROVER_LACKS_ESCALATION_AUTHORITY';
  if (!(typeof e.max_amount === 'number' && amount <= e.max_amount)) return 'APPROVER_AMOUNT_EXCEEDED';
  return null;
}

// v0.6.1 — Cuándo se cierra el ticket (revisiones de ChatGPT y Grok del 13-oct-2026):
//  - Se cierra por: plazo vencido o inválido, solicitud distinta, denegación FIRMADA, nueva decisión REJECT/ESCALATE,
//    o pago aceptado por el sistema objetivo.
//  - NO se cierra por una respuesta que no se puede autenticar (fuera del directorio, firma inválida, sin autoridad,
//    incompleta): esa respuesta se rechaza, pero el ticket sigue abierto para el aprobador legítimo.
//    Tras MAX_FAILED_RESPONSES respuestas así, se cierra.
//  - Si la nueva decisión es CONTINUE y se pasó opts.commit, el ticket solo se cierra si el sistema objetivo aceptó el pago.
//    Si lo rechazó (por ejemplo, el core no respondió), el ticket sigue abierto hasta su plazo y un reintento
//    vuelve a verificar todo; la ejecución única la garantiza el libro (una por request_id).
const MAX_FAILED_RESPONSES = 3;
const DENY = 'deny';

function resolveEscalation(store, ticketId, input, response, now, registry, opts = {}) {
  const t = store.get(ticketId);
  if (!t) return { status: 'NONE', outcome: 'REJECT', reason: 'TICKET_NOT_FOUND' };
  if (t.status !== 'OPEN') return { status: t.status, outcome: 'REJECT', reason: 'TICKET_ALREADY_CLOSED' };   // no se reutiliza
  const close = (reason, extra = {}) => { t.status = 'CLOSED'; t.closed_at = now.toISOString(); t.close_reason = reason; return { status: 'CLOSED', outcome: 'REJECT', reason, ...extra }; };
  const notAccepted = reason => {   // respuesta rechazada; el ticket sigue abierto (salvo demasiados intentos)
    t.failed_responses = (t.failed_responses || 0) + 1;
    if (t.failed_responses >= MAX_FAILED_RESPONSES) return close('TOO_MANY_INVALID_RESPONSES', { last: reason });
    return { status: 'OPEN', outcome: 'REJECT', reason };
  };
  if (!isDate(t.deadline)) return close('TICKET_DEADLINE_INVALID');
  if (now.getTime() > Date.parse(t.deadline)) return close('ESCALATION_TIMEOUT');
  // la aprobación tiene que ser para ESTA solicitud exacta
  if (input.request_id !== t.request_id || requestHashOf(JSON.parse(JSON.stringify(input))) !== t.request_hash) return close('TICKET_REQUEST_MISMATCH');
  if (!response || typeof response.approver !== 'string' || typeof response.signature !== 'string' || typeof response.approved !== 'boolean')
    return notAccepted('ESCALATION_RESPONSE_INCOMPLETE');
  const entry = registry && registry[response.approver];
  if (!entry) return notAccepted('APPROVER_NOT_IN_DIRECTORY');
  const payload = response.approved ? approvalPayload(t, input, response.approver) : { ...approvalPayload(t, input, response.approver), decision: DENY };
  let okSig = false;
  try { okSig = crypto.verify(null, Buffer.from(canonical(payload)), entry.public_key, Buffer.from(response.signature, 'base64')); } catch { okSig = false; }
  if (!okSig) return notAccepted('APPROVAL_SIGNATURE_INVALID');
  const bad = checkApprover(registry, response.approver, input.action.amount);
  if (bad) return notAccepted(bad);
  if (!response.approved) return close('ESCALATION_DENIED');   // denegación autenticada
  // nueva autorización ligada a las condiciones actuales + aprobación humana firmada adjunta
  const re = JSON.parse(JSON.stringify(input));
  const s = re.current_state;
  re.authorization = { ...re.authorization, id: re.authorization.id + '-esc-' + t.ticket_id.slice(0, 8),
    granted_by: response.approver, granted_at: now.toISOString(),
    conditions_at_grant: { approver_status: s.approver_status, amount_limit: s.amount_limit, account_status: s.account_status, risk_level: s.risk_level },
    human_approval: { approver: response.approver, ticket_id: t.ticket_id, request_id: t.request_id, signature: response.signature } };
  const verifier = makeApprovalVerifier(registry, t);
  const recheck = decide(re, now, { verifyHumanApproval: verifier });
  const result = { status: 'CLOSED', outcome: recheck.decision, reason: 'REAUTHORIZED_AND_RECHECKED', recheck, input: re };
  if (recheck.decision === 'CONTINUE' && typeof opts.commit === 'function') {
    const res = opts.commit(recheck, re);
    result.commit = res;
    if (!res || res.accepted !== true) { t.last_commit_refusal = res && res.reason; return { ...result, status: 'OPEN' }; }
  }
  t.status = 'CLOSED'; t.closed_at = now.toISOString(); t.close_reason = recheck.decision;
  return result;
}

// Firma de una denegación: mismo contenido que la aprobación, con decision 'deny'.
function signDenial(ticket, input, approverId, privateKey) {
  return crypto.sign(null, Buffer.from(canonical({ ...approvalPayload(ticket, input, approverId), decision: DENY })), privateKey).toString('base64');
}

// Verificador que decide() usa para aceptar una aprobación humana de una acción irreversible.
// Sin verificador, decide() ignora cualquier "human_approval" que venga en la entrada.
function makeApprovalVerifier(registry, ticket) {
  return (input) => {
    const h = input.authorization && input.authorization.human_approval;
    if (!h || h.ticket_id !== ticket.ticket_id || h.request_id !== input.request_id) return false;
    if (checkApprover(registry, h.approver, input.action.amount)) return false;
    try { return crypto.verify(null, Buffer.from(canonical(approvalPayload(ticket, { ...input, action: input.action }, h.approver))),
            registry[h.approver].public_key, Buffer.from(h.signature, 'base64')); } catch { return false; }
  };
}

module.exports = { TicketStore, resolveEscalation, signApproval, signDenial, checkApprover, MAX_FAILED_RESPONSES };
