// Escenarios del caso transferencia/reembolso. "now" fijo para que sea reproducible.
'use strict';
const NOW = new Date('2026-10-11T15:00:10Z');
function base() {
  return {
    request_id: 'req-001',
    action: { type: 'transfer', amount: 4000, currency: 'USD', destination: 'acct-9921', irreversible: true },
    requested_by: { id: 'agent-payments-7', kind: 'ai_agent' },
    authorization: {
      id: 'auth-5531', granted_by: 'manager-42', granted_at: '2026-10-11T14:00:00Z', valid_until: '2026-10-11T18:00:00Z',
      scope: { action_types: ['transfer', 'refund'], max_amount: 10000 },
      conditions_at_grant: { approver_status: 'active', amount_limit: 10000, account_status: 'open', risk_level: 'low' },
    },
    current_state: { observed_at: '2026-10-11T15:00:08Z', approver_status: 'active', amount_limit: 10000, account_status: 'open', risk_level: 'low' },
    policy: { max_state_age_seconds: 5, human_review_above_amount: 5000 },
  };
}
function mod(f) { const p = base(); f(p); return p; }
const SCENARIOS = [
  { id: 'S1', title: 'Todo en orden', input: base(), expected: 'CONTINUE' },
  { id: 'S2', title: 'Revocan al aprobador entre la autorización y la ejecución', input: mod(p => { p.current_state.approver_status = 'revoked'; }), expected: 'REJECT' },
  { id: 'S3', title: 'Bajan el límite de monto a 2.000 antes de ejecutar', input: mod(p => { p.current_state.amount_limit = 2000; }), expected: 'REJECT' },
  { id: 'S4', title: 'El riesgo de la cuenta sube de "low" a "high"; todos los límites siguen cumpliéndose', input: mod(p => { p.current_state.risk_level = 'high'; }), expected: 'ESCALATE' },
  { id: 'S5', title: 'El sistema de permisos no responde: estado del aprobador desconocido', input: mod(p => { p.current_state.approver_status = 'unknown'; }), expected: 'ESCALATE' },
  { id: 'S6', title: 'El estado se leyó hace 40 segundos (dato viejo)', input: mod(p => { p.current_state.observed_at = '2026-10-11T14:59:30Z'; }), expected: 'ESCALATE' },
  { id: 'S7', title: 'Monto 8.000, irreversible, lo ejecuta un agente de IA', input: mod(p => { p.action.amount = 8000; }), expected: 'ESCALATE' },
  { id: 'S8', title: 'Monto 8.000, irreversible, lo ejecuta una persona', input: mod(p => { p.action.amount = 8000; p.requested_by = { id: 'manager-42', kind: 'human' }; }), expected: 'CONTINUE' },
  { id: 'S9', title: 'Entrada mal formada: monto como texto "4000"', input: mod(p => { p.action.amount = '4000'; }), expected: 'REJECT' },
  { id: 'S10', title: 'Autorización vencida', input: mod(p => { p.authorization.valid_until = '2026-10-11T15:00:00Z'; }), expected: 'REJECT' },
];
module.exports = { SCENARIOS, NOW };
