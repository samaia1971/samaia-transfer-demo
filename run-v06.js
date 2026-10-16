// v0.6.3 — Misma batería contra la versión vulnerable y la protegida, informe del verificador y mutantes.
// Escribe el resultado en out/ (archivo generado, fuera del manifiesto) y lo compara con resultados_v06.json,
// que es la evidencia congelada de esta versión. Correr la demo ya no modifica archivos del manifiesto (hallazgo 5, 14-oct-2026).
'use strict';
const { runScenario, SCENARIOS } = require('./checks');
const { runAllMutants } = require('./mutants');

const rows = [];
console.log('ESCENARIO                     | VULNERABLE: ¿pagó? / hallazgo del verificador | PROTEGIDA: ¿pagó? / decisión final / hallazgo');
for (const k of Object.keys(SCENARIOS)) {
  const v = runScenario(k, 'vulnerable'), p = runScenario(k, 'protected');
  const last = p.outcomes[p.outcomes.length - 1];
  rows.push({ id: k, title: SCENARIOS[k].title,
    vulnerable: { posted: v.posted, paths: v.outcomes.map(o => `${o.path}:${o.ledger}`), finding: v.finding },
    protected: { posted: p.posted, paths: p.outcomes.map(o => `${o.path}:${o.decision}:${o.ledger}`), decision: last.decision, reasons: last.reasons, finding: p.finding } });
  const n = x => x.postings > 1 ? `PAGÓ x${x.postings}` : (x.posted ? 'PAGÓ' : 'no pagó');
  console.log(`${k.padEnd(29)} | ${n(v).padEnd(9)} ${v.finding.padEnd(31)} | ${n(p).padEnd(9)} ${String(p.outcomes[0].decision).padEnd(9)} ${p.finding}`);
}
const mutants = runAllMutants();
console.log('\nMETA-PRUEBA (detector roto): controles rotos a propósito');
for (const m of mutants) console.log(`${m.caught ? 'DETECTADO' : 'CIEGO    '} ${m.id.padEnd(4)} ${m.what}  <- ${m.caught_by.join(', ')}`);
console.log(`\n${mutants.filter(m => m.caught).length}/${mutants.length} mutantes detectados`);
const fs = require('fs'), path = require('path');
const out = JSON.stringify({ version: 'samaia-transfer-demo/0.6.3', scenarios: rows, mutants }, null, 2) + '\n';
fs.mkdirSync(path.join(__dirname, 'out'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'out', 'resultados_v06.json'), out);
const frozen = path.join(__dirname, 'resultados_v06.json');
const same = fs.existsSync(frozen) && fs.readFileSync(frozen, 'utf8') === out;
console.log(`\nResultado escrito en out/resultados_v06.json. ¿Coincide con la evidencia congelada resultados_v06.json? ${same ? 'sí' : 'NO'}`);
if (process.argv.includes('--freeze')) { fs.writeFileSync(frozen, out); console.log('Evidencia congelada actualizada (--freeze).'); }
