// v0.5–v0.6.1 — caminos alternativos, sistema objetivo, verificador independiente, fallos de la revisión de ChatGPT y mutantes.
'use strict';
const test = require('node:test'), assert = require('node:assert');
const { runChecks } = require('./checks');
const { runAllMutants } = require('./mutants');

for (const r of runChecks()) test(`${r.id} ${r.name}`, () => assert.ok(r.ok, r.detail));

// Meta-prueba: cada control roto a propósito tiene que hacer fallar al menos una comprobación.
for (const m of runAllMutants()) test(`mutante ${m.id}: ${m.what} → lo detecta la batería`, () => assert.ok(m.caught, `${m.id} no fue detectado`));
