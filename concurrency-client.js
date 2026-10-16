// v0.6.3 — Proceso cliente para test-concurrency.js: recibe un pago, espera la señal de salida y lo envía al libro.
'use strict';
let posting = null;
process.on('message', m => {
  if (m.type === 'load') { posting = m.posting; process.send({ type: 'ready' }); }
  else if (m.type === 'go') process.send({ type: 'post', posting });
  else if (m.type === 'result') process.exit(0);
});
