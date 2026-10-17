// Meta-prueba del "detector roto" (v0.5; 23 mutantes en v0.6; 28 en v0.6.1; 35 en v0.6.3; 58 en v0.6.4; 61 desde v0.6.5) (pruebas de mutación).
// Pregunta: si alguien rompe un control sin querer, ¿las pruebas lo notan?
// Para cada mutante se copia la demo a una carpeta temporal, se rompe UNA línea de un control
// (o, en un caso, las dos líneas de un mismo defecto) y se corre la batería completa (checks.js). Si ninguna comprobación falla, el detector está ciego
// para ese defecto: un "todo verde" no probaría nada.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');

const MUTANTS = [
  { id: 'M1', file: 'decide.js', what: 'decide ignora que el aprobador fue revocado o suspendido',
    find: "if (s.approver_status === 'revoked' || s.approver_status === 'suspended') reasons.push(", replace: 'if (false) reasons.push(' },
  { id: 'M2', file: 'decide.js', what: 'decide ignora que las condiciones cambiaron desde la autorización',
    find: 'if (changed.length) reasons.push(', replace: 'if (false) reasons.push(' },
  { id: 'M3', file: 'decide.js', what: 'decide ignora que el estado está viejo',
    find: 'if (age > pol.max_state_age_seconds) reasons.push(', replace: 'if (false) reasons.push(' },
  { id: 'M4', file: 'decide.js', what: 'decide ignora que la cuenta destino está congelada o cerrada',
    find: "if (s.account_status === 'closed' || s.account_status === 'frozen') reasons.push(", replace: 'if (false) reasons.push(' },
  { id: 'M5', file: 'ledger.js', what: 'el libro deja de comprobar la firma de la decisión',
    find: "if (!ok) return 'DECISION_SIGNATURE_INVALID';", replace: '' },
  { id: 'M6', file: 'ledger.js', what: 'el libro acepta decisiones viejas',
    find: "if (!(age >= 0 && age <= this.maxAge)) return 'DECISION_STALE';", replace: '' },
  { id: 'M7', file: 'ledger.js', what: 'el libro acepta reusar la misma decisión',
    find: "if (this.used.has(d.decision_hash)) return 'DECISION_ALREADY_USED';", replace: '' },
  { id: 'M8', file: 'ledger.js', what: 'el libro no comprueba que la decisión sea de esta solicitud',
    find: "if (d.bound_to.input_hash !== sha256(canonical(input)) || d.bound_to.request_id !== input.request_id) return 'DECISION_NOT_FOR_THIS_REQUEST';", replace: '' },
  { id: 'M9', file: 'ledger.js', what: 'el libro deja de controlar (acepta cualquier pago)',
    find: 'if (this.enforce) {', replace: 'if (false) {' },
  { id: 'M10', file: 'gateway.js', what: 'la API legacy deja de pasar por decide en la versión protegida',
    find: "if (this.mode === 'protected') return this.commit(request, now, 'legacy_batch_api');", replace: '' },
  { id: 'M11', file: 'gateway.js', what: 'la cola protegida decide al encolar y libera días después con esa decisión vieja',
    edits: [
      { find: "if (this.mode === 'vulnerable') {\n      const d = this.decideNow(request, now, 'scheduled_queue');", replace: "if (true) {\n      const d = this.decideNow(request, now, 'scheduled_queue');" },
      { find: "if (this.mode === 'vulnerable') {\n          if (q.d.record.decision", replace: "if (true) {\n          if (q.d.record.decision" },
    ] },
  { id: 'M12', file: 'verify.js', what: 'el verificador (el detector) deduce el efecto del log de decisiones en vez de mirar el libro',
    find: 'const posts = entries.filter(e => e.request_id === id);',
    replace: "const posts = rs.filter(x => x.valid && x.record.decision === 'CONTINUE').map(x => ({ request_id: id, decision_hash: x.record.decision_hash, posted_at: x.record.bound_to.state_observed_at, path: x.path }));" },
  // v0.6 — controles agregados tras la revisión de ChatGPT del 13-oct-2026
  { id: 'M13', file: 'ledger.js', what: 'el libro deja ejecutar dos veces la misma operación',
    find: "if (this.executed.has(input.request_id)) return 'ALREADY_EXECUTED';", replace: '' },
  { id: 'M14', file: 'ledger.js', what: 'el libro no comprueba si el estado cambió entre decidir y registrar',
    find: "if (!this.state || input.current_state.version !== this.state.version) return 'STATE_CHANGED_SINCE_DECISION';", replace: '' },
  { id: 'M15', file: 'ledger.js', what: 'el libro no comprueba si la autorización venció al registrar',
    find: "if (!(Date.parse(stored.valid_until) > now.getTime())) return 'AUTHORIZATION_EXPIRED_AT_COMMIT';", replace: '' },
  { id: 'M16', file: 'ledger.js', what: 'el libro acepta una autorización alterada respecto del registro',
    find: "if (canonical(stored) !== canonical(input.authorization)) return 'AUTHORIZATION_ALTERED';", replace: '' },
  { id: 'M17', file: 'ledger.js', what: 'el libro no lleva el tope acumulado por autorización',
    find: "if ((this.consumed.get(key) || 0) + posting.amount > stored.scope.max_amount) return 'AUTHORIZATION_BUDGET_EXCEEDED';", replace: '' },
  { id: 'M18', file: 'ledger.js', what: 'el libro no compara el pago con la acción autorizada',
    find: "if (posting.amount !== act.amount || posting.currency !== act.currency || posting.destination !== act.destination) return 'POSTING_DIFFERS_FROM_AUTHORIZED';", replace: '' },
  { id: 'M19', file: 'gateway.js', what: 'el gateway protegido cree el tipo de ejecutor que declara la solicitud',
    find: "requested_by: { id: String(rid), kind: who ? who.kind : 'unregistered' },", replace: "requested_by: { id: String(rid), kind: request.requested_by.kind }," },
  { id: 'M20', file: 'gateway.js', what: 'el gateway protegido usa la política que declara la solicitud',
    find: 'policy: clone(this.policy),', replace: 'policy: clone(request.policy),' },
  { id: 'M21', file: 'verify.js', what: 'el verificador no compara el asiento con la acción autorizada',
    find: "else if (differs.length) finding = 'EFFECT_DIFFERS_FROM_AUTHORIZED';", replace: '' },
  { id: 'M22', file: 'verify.js', what: 'el verificador no detecta ejecuciones duplicadas',
    find: "else if (posts.length > 1) finding = 'DUPLICATE_EXECUTION';", replace: '' },
  { id: 'M23', file: 'ledger.js', what: 'la verificación de la cadena del libro no detecta asientos borrados',
    find: "if (rest.prev_hash !== prev) return { valid: false, reason: `entry ${i + 1}: prev_hash mismatch (entry missing or reordered)` };", replace: '' },
  // v0.6.1 — controles agregados tras las revisiones de ChatGPT y Grok sobre la v0.6 (13-oct-2026)
  { id: 'M24', file: 'gateway.js', what: 'el gateway protegido cree la irreversibilidad que declara el agente',
    find: 'irreversible: cat ? cat.irreversible === true : true },', replace: 'irreversible: a.irreversible },' },
  { id: 'M25', file: 'gateway.js', what: 'la escalación usa la solicitud guardada al abrir el ticket en vez de las fuentes vigentes',
    find: 'const fresh = this.canonicalRequest(req);', replace: 'const fresh = clone(req);' },
  { id: 'M26', file: 'gateway.js', what: 'una solicitud mal formada entra a la cola y su error detiene la liberación',
    edits: [
      { find: "if (this.mode === 'protected' && !(isObj(request) && typeof request.request_id === 'string' && isObj(request.action)))", replace: 'if (false)' },
      { find: 'return this.withLedgerStatus(failed,', replace: 'throw e; return this.withLedgerStatus(failed,' },
    ] },
  { id: 'M27', file: 'escalation.js', what: 'una respuesta no autenticada cierra el ticket',
    find: "return { status: 'OPEN', outcome: 'REJECT', reason };", replace: 'return close(reason);' },
  { id: 'M28', file: 'escalation.js', what: 'el ticket se cierra aunque el sistema objetivo rechace el pago',
    find: "if (!res || res.accepted !== true) { t.last_commit_refusal = res && res.reason; return { ...result, status: 'OPEN' }; }", replace: '' },
  // v0.6.3 — controles agregados tras la revisión asistida por IA del 14-oct-2026 y los casos nuevos
  { id: 'M29', file: 'escalation.js', what: 'la aprobación absorbe un cambio de condiciones ocurrido mientras se esperaba (comportamiento de la v0.6.2)',
    edits: [
      { find: "if (changedSinceReview.length) return close(", replace: "if (false) return close(" },
      { find: 'conditions_at_grant: { ...t.reviewed_conditions },', replace: "conditions_at_grant: { ...t.reviewed_conditions, ...Object.fromEntries(Object.keys(t.reviewed_conditions).map(k => [k, s[k]])) }," },
    ] },
  { id: 'M30', file: 'ledger.js', what: 'el libro no comprueba si la política cambió entre decidir y registrar',
    find: "if (typeof this.policy !== 'function' || canonical(this.policy()) !== canonical(input.policy) || d.bound_to.policy_hash !== sha256(canonical(input.policy))) return 'POLICY_CHANGED_SINCE_DECISION';", replace: '' },
  { id: 'M31', file: 'escalation.js', what: 'tres respuestas falsas cierran el ticket legítimo (comportamiento de la v0.6.2)',
    find: "return { status: 'OPEN', outcome: 'REJECT', reason };", replace: "if (t.failed_responses >= 3) return close('TOO_MANY_INVALID_RESPONSES'); return { status: 'OPEN', outcome: 'REJECT', reason };" },
  { id: 'M32', file: 'verify.js', what: 'el verificador usa la evidencia sin revisar su forma (se cae con un registro nulo)',
    find: 'const recs = all.filter(wellFormedDecision).map(', replace: 'const recs = all.map(' },
  { id: 'M33', file: 'gateway.js', what: 'el gateway no pregunta al libro si el pago ya estaba registrado (confirmación perdida)',
    find: 'const prior = this.ledgerStatus(requestId, action);', replace: 'const prior = null;' },
  { id: 'M34', file: 'decide.js', what: 'decide no comprueba que el destino esté dentro de la autorización',
    find: "if (Array.isArray(au.scope.destinations) && !au.scope.destinations.includes(a.destination)) reasons.push(", replace: 'if (false) reasons.push(' },
  { id: 'M35', file: 'decide.js', what: 'decide ignora las condiciones opcionales (datos del beneficiario)',
    find: 'const keys = conditionKeysOf(au);', replace: 'const keys = CONDITION_KEYS;' },
  // v0.6.4 — hallazgos F1–F3 de la revisión del 16-oct-2026
  { id: 'M36', file: 'gateway.js', what: 'el gateway acepta la autorización derivada de una escalación en solicitudes ordinarias',
    find: 'const auth = stored && stored.derived_from === undefined ? stored : null;', replace: 'const auth = stored;' },
  { id: 'M37', file: 'ledger.js', what: 'el libro no limita la autorización derivada a su solicitud, su acción y su autorización madre',
    find: 'if (stored.derived_from !== undefined) {', replace: 'if (false) {' },
  { id: 'M38', file: 'gateway.js', what: 'al cerrar el ticket (por ejemplo, denegado) la autorización derivada queda guardada',
    find: "if (t.status === 'CLOSED') this.auths.remove(derivedId);", replace: '' },
  { id: 'M39', file: 'verify.js', what: 'el verificador no marca fechas inválidas o anteriores a la decisión',
    find: "else if (badTime.length) finding = 'TIMING_INVALID';", replace: '' },
  { id: 'M40', file: 'gateway.js', what: 'el gateway no consulta el libro antes de informar REJECT/ESCALATE (confirmación perdida)',
    find: "if (prior && !prior.ledger_status_unknown) return { ...base, executed: false, ledger: 'NOT_SENT', ...prior };", replace: '' },
  { id: 'M41', file: 'gateway.js', what: 'la escalación no consulta el libro antes de volver a decidir (confirmación perdida)',
    find: "if (prior && prior.already_posted) { closeTicket('ALREADY_POSTED_EARLIER');", replace: "if (false) { closeTicket('ALREADY_POSTED_EARLIER');" },
  // v0.6.4 — segunda revisión (ChatGPT) de la v0.6.4 antes de publicar
  { id: 'M42', file: 'gateway.js', what: 'el gateway da por pagada la operación si existe CUALQUIER asiento con ese identificador',
    find: 'const sameOperation = e.amount === a.amount && e.currency === a.currency && e.destination === a.destination;', replace: 'const sameOperation = true;' },
  { id: 'M43', file: 'gateway.js', what: 'la escalación no detecta que el identificador ya se usó para otra operación (cierra como pagada o queda abierta)',
    find: "if (prior && prior.request_id_conflict) { closeTicket('REQUEST_ID_CONFLICT');", replace: "if (false) { closeTicket('REQUEST_ID_CONFLICT');" },
  { id: 'M44', file: 'gateway.js', what: 'un ticket ya cerrado responde sin informar el pago que el libro tiene registrado',
    find: 'if (!req || out.executed || out.already_posted || out.request_id_conflict) return out;', replace: 'return out;' },
  { id: 'M45', file: 'gateway.js', what: 'la autorización derivada queda guardada aunque el libro no acepte el pago (ticket abierto)',
    find: 'if (!res.accepted) this.auths.remove(re.authorization.id);', replace: '' },
  // v0.6.4 — revisión previa (ChatGPT) de la r3
  { id: 'M46', file: 'gateway.js', what: 'una excepción del sistema objetivo se propaga (sin resultado explícito ni limpieza)',
    find: "} catch (e) { return { accepted: false, reason: 'TARGET_ERROR' }; }", replace: '} catch (e) { throw e; }' },
  { id: 'M47', file: 'ledger.js', what: 'el libro no valida que el camino sea un texto corto',
    find: "if (typeof posting.path !== 'string' || posting.path.length > 64) return 'POSTING_MALFORMED';", replace: '' },
  { id: 'M48', file: 'ledger.js', what: 'el libro marca "ejecutado" y consume presupuesto antes de armar el asiento',
    find: "try { e.entry_hash = sha256(canonical(e)); } catch {", replace: "this.executed.add(input.request_id); try { e.entry_hash = sha256(canonical(e)); } catch {" },
  { id: 'M49', file: 'verify.js', what: 'el verificador ignora un asiento mal formado que cita una decisión conocida',
    find: "else if (malformedFor.has(id)) finding = 'MALFORMED_POSTING';", replace: '' },
  { id: 'M50', file: 'verify.js', what: 'con evidencia mal formada no atribuible, el verificador igual da CONSISTENT',
    find: "if (unattributed > 0 && finding === 'CONSISTENT') finding = 'INCONCLUSIVE_MALFORMED_EVIDENCE';", replace: '' },
  { id: 'M51', file: 'gateway.js', what: 'el gateway usa como clave del catálogo cualquier valor (heredados u objetos)',
    find: "const own = (table, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(table, k) ? table[k] : undefined;", replace: 'const own = (table, k) => table[k];' },
  // v0.6.4 — revisión previa (ChatGPT) de la r4
  { id: 'M52', file: 'verify.js', what: 'el verificador atribuye asientos usando también decisiones con firma inválida',
    find: 'const hashToReq = new Map(recs.filter(x => x.valid).map(', replace: 'const hashToReq = new Map(recs.map(' },
  { id: 'M53', file: 'gateway.js', what: 'una falla de la consulta de estado del libro se propaga como excepción',
    find: 'try { st = this.ledger.status(requestId); } catch { return { ledger_status_unknown: true }; }', replace: 'st = this.ledger.status(requestId);' },
  { id: 'M54', file: 'gateway.js', what: 'tras una excepción al enviar y sin poder consultar el libro, se informa un rechazo en vez de un resultado desconocido',
    find: "if (prior.ledger_status_unknown && out.ledger === 'REFUSED:TARGET_ERROR') return { ...out, ...prior, ledger: 'OUTCOME_UNKNOWN' };", replace: '' },
  { id: 'M55', file: 'decide.js', what: 'decide recorre una entrada anidada de más antes de validarla (se cae)',
    find: 'if (tooDeep(p, MAX_INPUT_DEPTH)) {', replace: 'if (false) {' },
  // v0.6.4 — revisión previa (ChatGPT) de la r5
  { id: 'M56', file: 'gateway.js', what: 'el nuevo intento pierde que el resultado anterior sigue desconocido',
    find: 'if (prior && prior.ledger_status_unknown) base.ledger_status_unknown = true;', replace: '' },
  { id: 'M57', file: 'gateway.js', what: 'el gateway usa una respuesta "ejecutado" del libro sin validar el asiento',
    find: "if (!isObj(e) || typeof e.seq !== 'number') return { ledger_status_unknown: true };", replace: '' },
  { id: 'M58', file: 'gateway.js', what: 'el encolado copia una solicitud anidada de más sin revisarla (se cae)',
    find: "if (tooDeep(request, MAX_INPUT_DEPTH)) return { queued: false, decision_at_enqueue: 'REJECT', reason: 'MALFORMED_REQUEST' };", replace: '' },
  // v0.6.5 — límite conocido de la v0.6.4 publicada
  { id: 'M59', file: 'gateway.js', what: 'un asiento sin monto, moneda o destino válidos se compara como otra operación (falso REQUEST_ID_CONFLICT)',
    find: "if (!(typeof e.amount === 'number' && Number.isFinite(e.amount) && typeof e.currency === 'string' && typeof e.destination === 'string')) return { ledger_status_unknown: true };", replace: '' },
  { id: 'M60', file: 'gateway.js', what: 'el gateway acepta como evidencia el asiento de otra solicitud (no compara el request_id)',
    find: 'if (e.request_id !== requestId) return { ledger_status_unknown: true };', replace: '' },
  { id: 'M61', file: 'gateway.js', what: 'el gateway concilia con el libro una solicitud sin identificador válido (undefined === undefined)',
    find: "if (typeof requestId !== 'string' || requestId.length === 0) return null;", replace: '' },
];

function runMutant(m, srcDir = __dirname) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'samaia-mutant-'));
  try {
    for (const f of fs.readdirSync(srcDir).filter(f => f.endsWith('.js'))) fs.copyFileSync(path.join(srcDir, f), path.join(dir, f));
    const file = path.join(dir, m.file);
    let src = fs.readFileSync(file, 'utf8');
    for (const e of m.edits || [{ find: m.find, replace: m.replace }]) {
      const n = src.split(e.find).length - 1;
      if (n !== 1) throw new Error(`${m.id}: el patrón aparece ${n} veces en ${m.file} (debe aparecer 1)`);
      src = src.replace(e.find, e.replace);
    }
    fs.writeFileSync(file, src);
    const { runChecks } = require(path.join(dir, 'checks.js'));
    const failed = runChecks().filter(r => !r.ok);
    return { id: m.id, file: m.file, what: m.what, caught: failed.length > 0, caught_by: failed.map(r => r.id) };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function runAllMutants() { return MUTANTS.map(m => runMutant(m)); }

module.exports = { MUTANTS, runMutant, runAllMutants };
