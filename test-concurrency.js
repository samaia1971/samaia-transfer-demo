// v0.6.3 — Concurrencia real: varios PROCESOS envían pagos al mismo libro al mismo tiempo.
// Pregunta: ¿se puede pagar dos veces la misma operación, o pasarse del tope de la autorización, si los pedidos llegan juntos?
//  - Libro de la demo (atómico): comprueba y registra en un solo paso sin esperas; los pedidos se atienden uno por vez.
//  - Libro ingenuo (para comparar): comprueba, espera unos milisegundos (como una consulta a otra base) y después registra.
// Límite declarado: hay un solo proceso que lleva el libro. No prueba un libro repartido en varias máquinas ni una base
// de datos real; en producción esto lo garantiza una transacción del core bancario.
'use strict';
const test = require('node:test'), assert = require('node:assert');
const { fork } = require('child_process');
const path = require('path');
const { world, WED } = require('./checks');

const N = 8;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const asPosting = d => ({ input: d.input, amount: d.input.action.amount, currency: d.input.action.currency,
  destination: d.input.action.destination, path: 'direct_tool', decision: d.record, signature: d.signature });

// Lanza un proceso por pago; cuando todos están listos, les da la salida a la vez y atiende lo que llega.
async function race(ledger, postings, { atomic }) {
  const kids = postings.map(() => fork(path.join(__dirname, 'concurrency-client.js'), [], { execArgv: [], stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
  const results = [];
  let inFlight = 0, maxInFlight = 0;
  await Promise.all(kids.map((k, i) => new Promise(res => { k.once('message', m => m.type === 'ready' && res()); k.send({ type: 'load', posting: postings[i] }); })));
  const done = Promise.all(kids.map(k => new Promise(res => {
    k.on('message', async m => {
      if (m.type !== 'post') return;
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      let r;
      if (atomic) r = ledger.post(m.posting, WED);                 // comprobar y registrar en un solo paso
      else {                                                       // ingenuo: comprobar, esperar, registrar
        const refusal = ledger.check(m.posting, WED);
        await sleep(20);
        if (refusal) r = { accepted: false, reason: refusal };
        else { ledger.enforce = false; r = ledger.post(m.posting, WED); ledger.enforce = true; }
      }
      inFlight--;
      results.push(r);
      k.send({ type: 'result' });
      res();
    });
  })));
  kids.forEach(k => k.send({ type: 'go' }));
  await done;
  await Promise.all(kids.map(k => new Promise(res => (k.exitCode !== null ? res() : k.once('exit', res)))));
  return { accepted: results.filter(r => r.accepted).length, refused: results.filter(r => !r.accepted).map(r => r.reason), maxInFlight };
}

function samePaymentEightTimes() {
  const w = world('protected');
  const d = w.gw.decideNow(w.issue('C1'), WED, 'direct_tool');
  return { w, postings: Array.from({ length: N }, () => asPosting(d)) };
}
function fourPaymentsOneBudget() {   // 4 pagos de 4.000 con la misma autorización (tope 10.000): caben 2
  const w = world('protected');
  const ds = ['C2a', 'C2b', 'C2c', 'C2d'].map(id => w.gw.decideNow(w.issue(id, { authId: 'auth-shared-c' }), WED, 'direct_tool'));
  return { w, postings: ds.map(asPosting) };
}

test(`concurrencia real: ${N} procesos envían a la vez el mismo pago → el libro de la demo paga una sola vez`, async () => {
  const { w, postings } = samePaymentEightTimes();
  const r = await race(w.ledger, postings, { atomic: true });
  assert.strictEqual(r.accepted, 1, JSON.stringify(r));
  assert.strictEqual(w.ledger.entries.length, 1);
  assert.ok(r.refused.every(x => x === 'DECISION_ALREADY_USED' || x === 'ALREADY_EXECUTED'), JSON.stringify(r.refused));
});

test('concurrencia real: 4 procesos con 4 pagos de 4.000 sobre una autorización de 10.000 → el libro de la demo acepta solo 2', async () => {
  const { w, postings } = fourPaymentsOneBudget();
  const r = await race(w.ledger, postings, { atomic: true });
  assert.strictEqual(r.accepted, 2, JSON.stringify(r));
  assert.ok(r.refused.every(x => x === 'AUTHORIZATION_BUDGET_EXCEEDED'), JSON.stringify(r.refused));
});

// Contraprueba: si la prueba no detectara a un libro ingenuo, no probaría nada.
test(`contraprueba: un libro que espera entre comprobar y registrar paga el mismo pago más de una vez con ${N} procesos`, async () => {
  const { w, postings } = samePaymentEightTimes();
  const r = await race(w.ledger, postings, { atomic: false });
  assert.ok(r.maxInFlight > 1, 'los pedidos no llegaron a solaparse: la contraprueba no es válida');
  assert.ok(r.accepted > 1, JSON.stringify(r));
});

test('contraprueba: el libro ingenuo se pasa del tope de la autorización con 4 procesos', async () => {
  const { w, postings } = fourPaymentsOneBudget();
  const r = await race(w.ledger, postings, { atomic: false });
  assert.ok(r.accepted > 2, JSON.stringify(r));
});
