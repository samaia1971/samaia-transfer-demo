// Dos referencias SIMPLIFICADAS para comparar. No son OPA ni Cedar: muestran qué controles cambian la decisión.
'use strict';
// A) Regla al momento de autorizar: si hay autorización vigente y la acción está en su alcance, se ejecuta.
function ruleAtGrant(p, now = new Date()) {
  const au = p.authorization, a = p.action;
  const ok = au && Date.parse(au.valid_until) > now.getTime() && au.scope.action_types.includes(a.type) && a.amount <= au.scope.max_amount;
  return ok ? 'CONTINUE' : 'REJECT';
}
// B) Política bien escrita que además consulta el estado actual (tipo OPA/Cedar con datos en vivo):
//    rechaza si el aprobador está revocado, si el monto supera el límite actual o la cuenta no opera.
function currentStatePolicy(p, now = new Date()) {
  if (ruleAtGrant(p, now) === 'REJECT') return 'REJECT';
  const s = p.current_state || {}, a = p.action;
  if (s.approver_status === 'revoked') return 'REJECT';
  if (typeof s.amount_limit === 'number' && a.amount > s.amount_limit) return 'REJECT';
  if (s.account_status === 'closed' || s.account_status === 'frozen') return 'REJECT';
  return 'CONTINUE';
}
module.exports = { ruleAtGrant, currentStatePolicy };
