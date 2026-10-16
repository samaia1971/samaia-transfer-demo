// Ejecuta los escenarios: SAMAIA vs dos reglas simples, y mide la latencia de la determinación.
'use strict';
const { decide } = require('./decide');
const { ruleAtGrant, currentStatePolicy } = require('./baselines');
const { SCENARIOS, NOW } = require('./scenarios');
const rows = [];
for (const sc of SCENARIOS) {
  const out = decide(sc.input, NOW);
  let a, b;
  try { a = ruleAtGrant(sc.input, NOW); } catch { a = 'ERROR'; }
  try { b = currentStatePolicy(sc.input, NOW); } catch { b = 'ERROR'; }
  rows.push({ id: sc.id, title: sc.title, samaia: out.decision, ok: out.decision === sc.expected, ruleAtGrant: a, currentStatePolicy: b, reasons: out.reasons.map(r => r.code).join(', ') });
}
for (const r of rows) console.log(`${r.id.padEnd(4)} SAMAIA=${r.samaia.padEnd(8)} ${r.ok ? 'OK ' : 'XX '} reglaAlAutorizar=${r.ruleAtGrant.padEnd(8)} politicaEstadoActual=${r.currentStatePolicy.padEnd(8)} | ${r.reasons} | ${r.title}`);
const pass = rows.filter(r => r.ok).length;
console.log(`\nResultado esperado: ${pass}/${rows.length}`);
// Latencia de la determinación (sin contar la obtención de datos de IAM/estado).
const N = 200000, t = [];
for (let i = 0; i < N; i++) { const s = SCENARIOS[i % SCENARIOS.length].input; const t0 = process.hrtime.bigint(); decide(s, NOW); t.push(Number(process.hrtime.bigint() - t0) / 1000); }
t.sort((x, y) => x - y);
console.log(`Latencia de decide() en ${N} llamadas (microsegundos): p50=${t[N/2|0].toFixed(1)} p99=${t[N*0.99|0].toFixed(1)} max=${t[N-1].toFixed(1)}`);
// v0.6.3: la latencia cambia en cada máquina; se escribe en out/ para no tocar resultados.json (evidencia de la v0.4).
require('fs').mkdirSync(__dirname + '/out', { recursive: true });
require('fs').writeFileSync(__dirname + '/out/resultados.json', JSON.stringify({ rows, latency_us: { p50: t[N/2|0], p99: t[N*0.99|0] } }, null, 2) + '\n');
