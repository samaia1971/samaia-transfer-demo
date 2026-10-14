// Verificador independiente (v0.5; en v0.6 compara el efecto con la acción autorizada y detecta ejecuciones duplicadas).
// No lee el log del gateway. Usa solo dos fuentes:
//   1) las decisiones FIRMADAS por el Execution Boundary (se comprueba cada firma con la clave pública);
//   2) la exportación del LIBRO CONTABLE (el sistema objetivo), con su cadena de hashes.
// Responde por cada solicitud: qué se autorizó, qué cruzó el límite, qué hizo el objetivo,
// qué no se pudo verificar y qué caminos se probaron. No da un PASS/FAIL global.
'use strict';
const { verifyDecision } = require('./decide');
const { verifyChain } = require('./ledger');

const CANNOT_VERIFY = [
  'Si el libro nunca registró un pago (libro comprometido u omisión en origen), este verificador no lo ve: hace falta una fuente externa, como el extracto bancario o una conciliación.',
  'El camino ("path") de cada asiento lo declara quien envía el pago; el libro no puede comprobarlo.',
  'Solo cubre los caminos probados (paths_tested). Otros caminos hacia el banco no están cubiertos.',
  'Sin anchoredHead publicado por separado, borrar las últimas entradas y recalcular la cabeza no se detecta.',
];

// El asiento debe coincidir con la acción autorizada que va DENTRO de la decisión firmada.
const sameEffect = (p, act) => !!act && p.amount === act.amount && p.currency === act.currency && p.destination === act.destination;

function safeVerify(record, signature, pub) { try { return verifyDecision(record, signature, pub); } catch { return false; } }

function verify({ decisions, ledgerExport, boundaryPublicKey, anchoredHead, maxDecisionAgeSeconds = 5, pathsTested = [] }) {
  const chain = verifyChain(ledgerExport, anchoredHead);
  const recs = (decisions || []).map(x => ({ ...x, valid: safeVerify(x.record, x.signature, boundaryPublicKey) }));
  const entries = chain.valid ? ledgerExport.entries : (ledgerExport && ledgerExport.entries || []);
  const ids = [...new Set([...recs.map(x => x.record.bound_to.request_id), ...entries.map(e => e.request_id)])];

  const requests = ids.map(id => {
    const rs = recs.filter(x => x.record.bound_to.request_id === id);
    const posts = entries.filter(e => e.request_id === id);
    const backing = new Map(rs.filter(x => x.valid && x.record.decision === 'CONTINUE').map(x => [x.record.decision_hash, x.record]));
    let finding;
    if (!chain.valid) finding = 'UNVERIFIABLE';
    else {
      const unbacked = posts.filter(p => !p.decision_hash || !backing.has(p.decision_hash));
      const stale = posts.filter(p => backing.has(p.decision_hash)
        && (Date.parse(p.posted_at) - Date.parse(backing.get(p.decision_hash).bound_to.state_observed_at)) / 1000 > maxDecisionAgeSeconds);
      const differs = posts.filter(p => backing.has(p.decision_hash) && !sameEffect(p, backing.get(p.decision_hash).bound_to.action));
      const hashes = posts.map(p => p.decision_hash).filter(Boolean);
      if (unbacked.length && rs.some(x => x.record.decision !== 'CONTINUE')) finding = 'BLOCKED_BUT_POSTED';
      else if (unbacked.length) finding = 'POSTED_WITHOUT_VALID_DECISION';
      else if (differs.length) finding = 'EFFECT_DIFFERS_FROM_AUTHORIZED';
      else if (stale.length) finding = 'EXECUTED_ON_STALE_DECISION';
      else if (hashes.length !== new Set(hashes).size) finding = 'DECISION_REUSED';
      else if (posts.length > 1) finding = 'DUPLICATE_EXECUTION';
      else finding = 'CONSISTENT';
    }
    return {
      request_id: id,
      authorized: rs.map(x => ({ decision: x.record.decision, path: x.path, at: x.at, signature_valid: x.valid })),
      crossed_boundary: posts.filter(p => backing.has(p.decision_hash)).length,
      target_effect: chain.valid ? (posts.length ? 'POSTED' : 'NOT_POSTED') : 'UNKNOWN',
      postings: posts.map(p => ({ seq: p.seq, amount: p.amount, currency: p.currency, destination: p.destination, path_declared: p.path, posted_at: p.posted_at, backed_by_decision: backing.has(p.decision_hash) })),
      finding,
    };
  });
  return { ledger_chain: chain, requests, paths_tested: pathsTested, cannot_verify: CANNOT_VERIFY };
}

module.exports = { verify, CANNOT_VERIFY };
