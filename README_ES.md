# Demo: caso transferencia / reembolso — propuesta experimental v0.6.4 (16-oct-2026)

**En cinco líneas.** Un agente de IA quiere pagar 4.000 USD con una autorización que ya tiene.
La demo decide en el último momento si puede hacerlo (CONTINUE), si debe ir a un humano (ESCALATE) o si no (REJECT).
Corre todo contra una versión **vulnerable** y una **protegida**, por cuatro caminos hacia el pago.
Un verificador independiente revisa el **libro contable**, no el log del agente, y muestra casos en que el log dice "rechazado" y el dinero salió igual.
Todo es simulado: es un ejemplo trabajado del patrón dentro de su propio modelo, no una solución general. Los límites están al final.

```
node --test       → 166/166  (40 de la v0.4 + 64 comprobaciones + 58 controles rotos a propósito + 4 de concurrencia con procesos reales)
node run-v06.js   → tabla vulnerable vs. protegida, informe del verificador y meta-prueba (escribe en out/, no toca la evidencia congelada)
node run.js       → los 10 escenarios de la v0.4 y la latencia de decide() (escribe en out/)
sha256sum -c MANIFEST.sha256   → comprueba que ningún archivo cambió
```
(o `npm test` / `npm run demo`; requiere Node 18 o superior, sin dependencias. GitHub Actions corre las pruebas, la demo y el manifiesto en Node 18, 20 y 22.)

## Cómo está armado

```
 agente ──► GATEWAY ───────────────────────────────────────────────► LIBRO CONTABLE (objetivo)
            caminos: herramienta · API legacy · cola · escalación      controla al registrar:
            protegida: arma la entrada desde fuentes controladas        decisión firmada y fresca,
              (agentes, autorizaciones, política, catálogo, estado),    pago = acción autorizada,
              decide y firma una vez por intento                        autorización vigente e intacta,
            vulnerable: cree lo que declara la solicitud, la API        estado y política sin cambios desde la decisión,
              legacy escribe directo y la cola usa la decisión vieja    una ejecución por operación, tope acumulado
                                     │                                             │
                                     └──► decisiones firmadas ──┐   ┌── exportación encadenada
                                                                ▼   ▼
                                                          VERIFICADOR INDEPENDIENTE
                                            (no lee el log del gateway: firma + libro)
```

## Resultado

| Escenario | Vulnerable | Protegida |
|---|---|---|
| A1 Todo en orden | paga · CONSISTENT | paga · CONSISTENT |
| A2 Revocan al aprobador | no paga | REJECT · no paga |
| A3 Revocan al aprobador; reintento por la API legacy | **paga** · **BLOCKED_BUT_POSTED** | REJECT en los dos caminos · no paga |
| A4 Sube el riesgo | no paga | ESCALATE · no paga |
| A5 Datos de cumplimiento de hace 40 s | no paga | ESCALATE · no paga |
| A6 Aprobado el lunes, retención el martes, se libera el miércoles | **paga** · **EXECUTED_ON_STALE_DECISION** | REJECT al liberar · no paga |
| A7 El agente sube en su solicitud el umbral de revisión humana | **paga** · CONSISTENT (ver límites) | ESCALATE · no paga |
| A8 El agente se declara "human" | **paga** · CONSISTENT (ver límites) | ESCALATE · no paga |
| A9 La misma solicitud dos veces | **paga dos veces** · **DUPLICATE_EXECUTION** | paga una vez; la segunda, ALREADY_EXECUTED |
| A10 El agente declara "irreversible: false" en un pago de 8.000 | **paga** · CONSISTENT (ver límites) | ESCALATE · no paga |
| A11 Pago aprobado; luego cambian los datos bancarios del beneficiario | no paga | ESCALATE · no paga |
| A12 El agente paga a la cuenta nueva del beneficiario con la aprobación de la vieja | **paga** · CONSISTENT (ver límites) | REJECT por destino fuera de la autorización · no paga |

## v0.5 → v0.6: fallos encontrados en la revisión de ChatGPT del 13-oct-2026

Los cuatro se reprodujeron en la v0.5 antes de corregirlos. Cada uno tiene ahora una comprobación (R) y un mutante que demuestra que la comprobación lo detecta.

| # | Fallo en v0.5 | Corrección en v0.6 | Comprobación |
|---|---|---|---|
| 1 | La misma solicitud enviada dos veces se pagaba dos veces, y el verificador decía CONSISTENT | El libro registra una sola ejecución por `request_id`, lleva un tope acumulado por autorización y el verificador marca DUPLICATE_EXECUTION | R1a, R1b, R1c |
| 2 | El agente podía subir el umbral de revisión humana o declararse "human" y pasar de ESCALATE a CONTINUE | La versión protegida toma identidad, autorización y política de fuentes controladas (`sources.js` y registro de agentes). De la solicitud solo usa request_id, acción e identificadores | R2a, R2b |
| 3 | Entre decidir y registrar, revocar al aprobador o vencer la autorización no impedía el pago | El libro comprueba al registrar que la autorización existe, no fue alterada y no venció, y que la versión del estado es la misma con la que se decidió | R3a, R3b, R3c |
| 4 | Con el libro sin control, una decisión de 4.000 USD registrada como 9.000 EUR a otra cuenta salía CONSISTENT | La decisión firmada incluye la acción autorizada (monto, moneda, destino). El libro y el verificador comparan el asiento contra ella | L3, R4 |

También se agregó el **recorrido completo de una escalación** (R5): pago de 8.000 por un agente → ESCALATE → aprobación firmada → lectura del estado actual → nueva decisión → pago una sola vez → verificador CONSISTENT. Un segundo intento con la misma aprobación no paga. Además: la autorización vence mientras se espera (R6) y el estado cambia mientras se espera (R7). En ambos casos no se paga.

## v0.6 → v0.6.1: fallos encontrados en las revisiones de ChatGPT y Grok sobre la v0.6 (13-oct-2026)

Todos se reprodujeron en la v0.6 antes de corregirlos. Cada uno tiene una comprobación nueva y un mutante (M24–M28) que demuestra que la comprobación lo detecta.

| # | Fallo en v0.6 | Corrección en v0.6.1 | Comprobación |
|---|---|---|---|
| 1 | El agente declaraba si su pago era irreversible. Con `irreversible: false`, un pago de 8.000 pasaba de ESCALATE a CONTINUE y se registraba (ChatGPT) | La versión protegida toma la irreversibilidad de un **catálogo de operaciones** controlado. Un tipo desconocido cuenta como irreversible | R8 (escenario A10) |
| 2 | Al resolver una escalación se usaba la autorización guardada al abrir el ticket. Si bajaban su tope a 1.000 mientras se esperaba, igual se pagaban 8.000 (ChatGPT) | Al resolver, la solicitud se vuelve a armar desde las fuentes vigentes. Si cambió la autorización, la política, el registro del agente o el catálogo: REJECT por REQUEST_CONDITIONS_CHANGED_WHILE_PENDING. Hace falta una solicitud nueva | R9 |
| 3 | Igual con la política: endurecerla mientras se esperaba no impedía el pago (ChatGPT) | La misma corrección que en el punto 2 | R10 |
| 4 | Una solicitud vacía en la cola lanzaba una excepción y dejaba sin procesar el pago válido que venía detrás (ChatGPT) | La versión protegida no encola solicitudes sin forma mínima (MALFORMED_REQUEST). Cada elemento de la cola se procesa por separado, y si uno falla queda un resultado explícito | R11 |
| 5 | Una respuesta con firma inválida cerraba el ticket, y la aprobación legítima posterior ya no servía (ChatGPT) | Una respuesta que no se puede autenticar se rechaza, pero el ticket sigue abierto. Tras 3 respuestas así, se cierra. Una **denegación** solo cierra el ticket si viene firmada | R12 |
| 6 | El ticket se cerraba antes de que el libro aceptara el pago. Si el libro lo rechazaba, la aprobación quedaba gastada sin efecto (Grok) | El ticket solo se cierra cuando el libro acepta. Si lo rechaza, el ticket sigue abierto hasta su plazo y un reintento vuelve a verificar todo. La ejecución única la sigue garantizando el libro | R13 |

También se corrigió el encabezado de `gateway.js`, que todavía decía "tres caminos" (Grok), y el ZIP ahora trae `MANIFEST.sha256` con el hash de cada archivo (Grok).

## v0.6.2 → v0.6.3: revisión asistida por IA (ChatGPT) del 14-oct-2026, confirmación perdida y concurrencia

Es una **revisión asistida por IA**, no una auditoría independiente de seguridad. Cada hallazgo se verificó leyendo el código o reproduciéndolo en una copia aislada antes de corregirlo. Cada corrección tiene una comprobación nueva y un mutante (M29–M35) que demuestra que la comprobación lo detecta.

| # | Hallazgo en v0.6.2 | Corrección en v0.6.3 | Comprobación |
|---|---|---|---|
| 1 | Si el riesgo subía mientras se esperaba la aprobación humana, la aprobación lo absorbía: la nueva autorización copiaba el estado del momento y el pago salía | El ticket guarda las condiciones que se le mostraron al aprobador y **la firma las cubre**. Si cambiaron al resolver: REJECT por CONDITIONS_CHANGED_SINCE_REVIEW; hace falta una solicitud nueva | R14, R14b |
| 2 | El libro comparaba la versión del estado, pero no la política, entre decidir y registrar | La decisión firmada incluye el hash de la política y el libro la compara con la política vigente al registrar: POLICY_CHANGED_SINCE_DECISION | R15 |
| 3 | Tres respuestas falsas cerraban un ticket legítimo | Una respuesta que no se puede autenticar o autorizar se rechaza y se cuenta, pero no cambia el estado del ticket; el plazo lo acota | R16 |
| 4 | El verificador se caía con un registro nulo o mal formado | Separa la evidencia mal formada, la cuenta en `malformed_evidence` y mantiene los demás resultados | R17 |
| 5 | `npm run demo` reescribía un archivo del manifiesto y `sha256sum -c` fallaba | La demo escribe en `out/` (fuera del manifiesto) y avisa si su resultado coincide con la evidencia congelada | — (CI) |
| 6 | Versiones desalineadas (0.6.1 en código y README, etiqueta v0.6.2) | Todo dice 0.6.3 | — |
| 7 | Sin integración continua | `.github/workflows/test.yml`: pruebas, demo y manifiesto en Node 18, 20 y 22 | — |
| 8 | `LICENSE` traía solo un aviso y un enlace | Texto completo de PolyForm Noncommercial 1.0.0 | — |
| 9 | Las revisiones se llamaban "externas" | Se llaman "revisiones asistidas por IA" | — |

**Nuevo en esta versión:**
- **Confirmación perdida** (R18, R19): el libro registra el pago pero la respuesta no llega. El reintento no paga otra vez: el gateway le pregunta al libro qué quedó registrado y responde `already_posted`. En una escalación, el ticket se cierra sin pagar de nuevo.
- **Datos del beneficiario** (A11, A12; caso planteado en LinkedIn el 15-oct-2026): la autorización puede fijar los destinos permitidos y la versión de los datos del beneficiario. Si esos datos cambian después de aprobar: ESCALATE. Si el agente intenta pagar a la cuenta nueva con la aprobación de la vieja: REJECT.
- **Concurrencia con procesos reales** (`test-concurrency.js`): 8 procesos envían a la vez el mismo pago y el libro paga una vez; 4 procesos con 4 pagos sobre una autorización de 10.000 y el libro acepta 2. Una contraprueba con un libro que espera entre comprobar y registrar paga de más, para mostrar que la prueba detecta el problema.
- **Informe del verificador:** para cada resultado dice qué fuentes revisó, qué vio y qué no comprobó (`coverage`).

## v0.6.3 → v0.6.4: revisión asistida por IA de la v0.6.3 (16-oct-2026)

La v0.6.3 se publicó **antes** de pasar por su propia revisión. Esa revisión (ChatGPT; Grok no encontró fallas) halló un fallo grave en la escalación. Los hallazgos se reprodujeron antes de corregirlos; cada comprobación nueva falla en la versión anterior y pasa en la v0.6.4, y cada corrección tiene un mutante (M36–M58; M26, M33, M40 y M41 se ajustaron). La v0.6.4 se revisó otra vez **antes** de publicarla, en cinco pasadas (G1–G14). Desde F1, ninguna pasada encontró un pago indebido ni un pago doble; los hallazgos fueron de informe del resultado y de robustez ante fallos inyectados y entradas patológicas.

| # | Hallazgo en v0.6.3 | Corrección en v0.6.4 | Comprobación |
|---|---|---|---|
| F1 (alta) | La aprobación de una escalación creaba una autorización derivada que quedaba guardada y servía para **otros** pagos, incluso después de una **denegación firmada**; y seguía usando el tope viejo si bajaban el de la autorización madre | La autorización derivada sirve una sola vez: queda ligada a la solicitud y a la acción aprobadas y a la autorización madre (`parent_hash`). El gateway no la acepta en solicitudes ordinarias, se retira al cerrar el ticket (pagado, denegado o rechazado) y el libro la vuelve a comprobar: DERIVED_AUTHORIZATION_NOT_FOR_THIS_REQUEST / PARENT_AUTHORIZATION_CHANGED | R22, R23, R24 |
| F2 (media) | El verificador daba CONSISTENT con fechas inválidas (`not-a-date`, null) o con un asiento anterior al estado en que se basó la decisión, y se caía con un valor raro | Fechas válidas y en orden o el resultado es TIMING_INVALID; nunca se cae | R25 |
| F3 (media) | Tras una confirmación perdida, un reintento en el mismo segundo (DECISION_ALREADY_USED) o después de un cambio de condiciones informaba "no se pagó" aunque el libro tenía el pago | El gateway consulta el libro con cualquier rechazo y antes de informar REJECT/ESCALATE o de volver a decidir una escalación; responde `already_posted` | R26, R27 (R19 ajustada) |
| G1 (revisión previa) | Tras una confirmación perdida, si cambiaba la política o la autorización antes del reintento, la escalación se cerraba por "condiciones cambiadas" sin informar el pago ya hecho, y los reintentos siguientes tampoco | La escalación concilia con el libro **antes** de evaluar cambios; cualquier respuesta sin pago nuevo (incluido TICKET_ALREADY_CLOSED) informa lo que el libro tiene | R28 |
| G2 (revisión previa) | "Ya pagado" se decidía solo por el identificador: un ticket de 8.000 se cerraba como pagado porque había un asiento de 4.000 con el mismo identificador | Solo es "ya pagado" si el asiento es la misma operación (monto, moneda, destino); si no, conflicto explícito REQUEST_ID_CONFLICT | R29 |
| G3 (revisión previa) | Las decisiones firmadas decían 0.6.3 | Dicen 0.6.4 | — |
| G4 (revisión previa, Grok) | Si el libro no aceptaba el pago aprobado, la autorización derivada quedaba guardada mientras el ticket seguía abierto (no permitía pagar otra cosa: higiene) | La derivada existe solo mientras se registra el pago; si el libro no lo acepta, se retira y un reintento la vuelve a crear | R30 (R24 ajustada) |
| G5 (revisión previa r3, ChatGPT) | Si el sistema objetivo lanzaba una excepción al registrar el pago aprobado, la excepción salía sin resultado y la autorización derivada quedaba guardada | Una excepción es un rechazo explícito (TARGET_ERROR); la derivada se retira y se concilia con el libro (si el pago sí quedó, se informa) | R31 |
| G6 (revisión previa r3, ChatGPT) | Un asiento sin request_id se descartaba como mal formado y el verificador daba CONSISTENT (o NOT_POSTED) aunque hubiera un segundo pago | Si el asiento cita una decisión conocida: MALFORMED_POSTING para esa solicitud; si no se puede atribuir: ningún resultado favorable es concluyente (INCONCLUSIVE_MALFORMED_EVIDENCE) | R32 |
| G7 (revisión previa r3, ChatGPT) | Un posting con un camino no serializable marcaba la solicitud como ejecutada y consumía presupuesto sin crear el asiento | El camino debe ser un texto corto; el asiento se arma antes de tocar el estado del libro | R33 |
| G8 (revisión previa r3, ChatGPT) | Un tipo de acción que no es texto ({toString:null}) tumbaba el gateway; nombres heredados ("constructor") se buscaban en el catálogo | Solo se usan como clave valores de texto propios de cada tabla | R34 |
| G9 (revisión previa r4, ChatGPT) | Una copia de la decisión con firma inválida y otro request_id desviaba la atribución del asiento mal formado (y el resultado dependía del orden) | Solo las decisiones con firma válida sirven para atribuir | R35 |
| G10 (revisión previa r4, ChatGPT) | Si el envío fallaba con excepción después de registrar y la consulta de estado también fallaba, la cola decía "no enviado" y los otros caminos dejaban escapar la excepción | La falla de la consulta se maneja; el resultado es OUTCOME_UNKNOWN (nunca "no enviado"); al volver la consulta, se reconoce el pago sin duplicarlo | R36 |
| G11 (revisión previa r4, ChatGPT) | Un campo anidado miles de niveles tumbaba decide() antes de validar | La profundidad se mide sin recursión y se rechaza (INPUT_INVALID) antes del hash; el registro de rechazo no vuelve a recorrer el objeto | R37 |
| G12 (revisión previa r5, ChatGPT) | Tras un resultado desconocido, un nuevo intento rechazado (cuenta congelada) perdía la marca de que el pago anterior seguía sin saberse | La respuesta conserva `ledger_status_unknown` mientras la consulta no responda | R38 |
| G13 (revisión previa r5, ChatGPT) | Una respuesta de estado "ejecutado" sin asiento tumbaba la cola entera | Se valida la respuesta completa; si no sirve, el estado es desconocido y la cola sigue | R39 |
| G14 (revisión previa r5, ChatGPT) | Una solicitud anidada 10.000 niveles tumbaba el encolado (y la copia en la versión vulnerable) | Se mide la profundidad antes de copiarla y se rechaza | R40 |

También se precisó la redacción de los límites: qué prueba la firma del aprobador, qué significa "independiente", cómo compara una escalación las condiciones (bajo → alto → bajo), límites sin unidad de moneda y alcance de los mutantes.

## Archivos

- `decide.js` — la decisión. Las reglas son las de la v0.4. Desde la v0.6, el registro firmado incluye la acción autorizada; desde la v0.6.3, el hash de la política, los destinos permitidos y la condición opcional de datos del beneficiario.
- `escalation.js` — ciclo de vida de ESCALATE: ticket ligado a la solicitud y a las condiciones revisadas, un solo uso, plazo, directorio de autoridad y aprobación firmada.
- `sources.js` (v0.6) — fuentes controladas simuladas: estado actual con número de versión y registro de autorizaciones.
- `gateway.js` — capa de ejecución en versión vulnerable y protegida, con los cuatro caminos y el catálogo de operaciones (v0.6.1).
- `ledger.js` — el sistema objetivo, con sus controles al registrar, la consulta `status()` y la cadena de hashes.
- `verify.js` — verificador independiente. No da un PASS/FAIL global: informa por solicitud, con su cobertura, y declara lo que no puede verificar.
- `checks.js` — 12 escenarios y 64 comprobaciones: P (protegida), L (libro), V (verificador) y R (revisiones asistidas por IA, escalación, confirmación perdida y beneficiario).
- `mutants.js` — meta-prueba del "detector roto": 58 controles rotos a propósito (decide, libro, gateway, escalación, verificador y cadena), todos detectados.
- `test-concurrency.js` y `concurrency-client.js` (v0.6.3) — prueba con procesos reales y su contraprueba.
- `.github/workflows/test.yml` (v0.6.3) — integración continua.
- `MANIFEST.sha256` — hash de cada archivo. Se comprueba con `sha256sum -c MANIFEST.sha256`.
- `baselines.js`, `scenarios.js`, `run.js`, `test.js` — lo de la v0.4.
- `package.json` — solo scripts, sin dependencias.
- `RELATED_WORK.md` — quién más hace esto (en inglés).

## Lo que mostró la meta-prueba

- El control en el libro puede **tapar** una regresión del gateway. M10 (la API legacy deja de pasar por decide) solo lo detecta P3, que exige una decisión firmada en ese camino. Por eso se comprueba la mediación además del resultado.
- Un mutante mal construido (la primera versión de M11) quedó "ciego" porque no cambiaba nada. También hay que revisar los mutantes.

## Límites (lo que esta versión NO prueba)

- **Todo es simulado.** El libro, las fuentes y los caminos viven en memoria. Un sistema real tiene caminos que nadie inventarió.
- **Concurrencia.** Se prueba con varios procesos reales enviando al mismo libro, pero el libro lo lleva un solo proceso que atiende un pedido por vez. No se prueba un libro repartido en varias máquinas ni una base de datos real. En producción eso exige una transacción con verificación de versión (o equivalente).
- **Aprobación humana.** La firma prueba que la llave del aprobador firmó la solicitud y las condiciones revisadas. No prueba qué vio realmente la persona, ni que tuvo información, tiempo o libertad suficientes para decir que no: la presencia humana no es intervención.
- **Lo que nunca se pidió.** El verificador solo ve decisiones que alguien solicitó. Una decisión que nunca se convirtió en solicitud no aparece como pendiente ni como vencida.
- **Coordinación entre organizaciones** (por ejemplo, médico, farmacia y aseguradora) y **cambio de proveedor de infraestructura**: fuera de la demo.
- **Sin sellado de tiempo externo.** Las fechas las registran el Execution Boundary y el libro.
- **El verificador comprueba que el efecto corresponde a una decisión firmada, no que la decisión se tomó con fuentes correctas.** En A7, A8, A10 y A12, la versión vulnerable firma decisiones basadas en lo que declaró el agente, y el verificador las da por CONSISTENT. Lo que cierra ese hueco es el gateway protegido y el control del libro, no el verificador.
- **Identidad del solicitante.** Se toma como autenticada (`requested_by.id`). La autenticación real queda fuera de la demo.
- **Cierre de caminos alternativos:** solo para los cuatro caminos modelados.
- **Verificador "independiente":** independiente del log del gateway; no es una corroboración independiente de que el libro diga la verdad.
- **Evidencia de no ejecución:** viene del libro simulado. Si el libro real omitió un pago desde el origen, el verificador no lo ve; haría falta una fuente externa (extracto o conciliación).
- **Tope acumulado:** se lleva por autorización (y sus derivadas de escalación). No hay límites diarios ni por destino.
- **Artefacto congelado:** esta publicación, con su fecha y `MANIFEST.sha256`, es la versión congelada de la v0.6.4. `resultados_v06.json` es la evidencia congelada; `out/` es lo que genera cada corrida.
- **El camino de cada asiento lo declara quien envía el pago.** No va firmado.
- **La versión del estado es una sola para todo** (señalado por Grok). Cualquier cambio de estado invalida las decisiones pendientes, aunque no les afecte. Es conservador (rechaza de más, nunca de menos). Un sistema real necesitaría una versión por cada dato relevante. Esto vale entre decidir y registrar; una escalación, en cambio, compara los valores de las condiciones revisadas al resolver: si un valor cambia y vuelve al revisado (bajo → alto → bajo) antes de resolver, la aprobación sigue valiendo.
- **Si las condiciones cambian durante una escalación, se rechaza** (incluido el cambio de las condiciones que el aprobador revisó). No existe un camino para que el humano apruebe explícitamente bajo las condiciones nuevas: hay que hacer una solicitud nueva.
- **Respuestas falsas a una escalación:** se rechazan sin cerrar el ticket. Limitar cuántas puede mandar cada remitente corresponde al canal de transporte, fuera de la demo.
- **Datos del beneficiario y destinos permitidos:** solo se exigen si la autorización los fijó. Una autorización sin ellos no los controla.
- **El catálogo de operaciones** es una tabla simulada con dos tipos. En un sistema real lo define el sistema que ejecuta la operación.
- **Límites sin unidad de moneda.** Los topes de la autorización y el umbral de revisión humana son números; la moneda va firmada y se compara al registrar, pero los topes no se separan por moneda.
- **La recuperación de una confirmación perdida depende de la consulta de estado del libro.** Si el envío falla con una excepción y la consulta también falla, el resultado es OUTCOME_UNKNOWN (nunca "no enviado"); mientras la consulta siga caída, los intentos siguientes conservan la marca `ledger_status_unknown`; cuando responda, se informa el pago ya hecho. Una respuesta de estado mal formada cuenta como desconocida.
- **Profundidad de la entrada:** hasta 32 niveles; una entrada más profunda se rechaza como INPUT_INVALID antes de calcular su hash.
- **Evidencia mal formada del libro:** nunca se lee como ausencia. Un asiento que cita una decisión conocida con firma válida deja esa solicitud en MALFORMED_POSTING; uno que no se puede atribuir deja los resultados favorables en INCONCLUSIVE_MALFORMED_EVIDENCE.
- **Mutantes.** Los 58 mutantes muestran que esos controles rotos se detectan; no prueban una cobertura adversarial completa.
- **Reintentos de una escalación aprobada:** el ticket sigue abierto si el libro rechaza el pago. Que se pague una sola vez depende del control del libro, no del ticket.

## Historial

- v0.1 → v0.2: fallos de la primera revisión de ChatGPT del 11-oct-2026 (vencimiento inválido, estado en el futuro, condiciones vacías, campos faltantes, valores fuera de dominio; hash de la entrada completa; firma).
- v0.2 → v0.3: escalación corregida tras la segunda revisión (aprobador sin autoridad, ticket de otra solicitud, ticket reutilizado, fecha límite inválida, reclasificación del ejecutor).
- v0.3 → v0.4: una aprobación que tarda se re-evalúa con estado fresco.
- v0.4 → v0.5 (13-oct-2026): caminos alternativos, sistema objetivo con control propio, verificador independiente y meta-prueba de mutantes.
- v0.5 → v0.6 (13-oct-2026): los cuatro fallos de la revisión de ChatGPT con Astra, escalación integrada de punta a punta y package.json (sugerido por la revisión de Grok).
- v0.6 → v0.6.1 (13-oct-2026): irreversibilidad desde un catálogo, escalación con fuentes vigentes, cola robusta, respuestas no autenticadas que no gastan el ticket, ticket cerrado solo cuando el libro acepta, y manifiesto de hashes (revisiones asistidas por IA de ChatGPT y Grok sobre la v0.6).
- v0.6.1 → v0.6.2 (13-oct-2026): solo se corrigió el manifiesto (un salto de línea agregado por el editor web de GitHub cambiaba el hash de un archivo). El código no cambió.
- v0.6.2 → v0.6.3 (16-oct-2026): los nueve hallazgos de la revisión asistida por IA del 14-oct-2026, confirmación perdida, datos del beneficiario, concurrencia con procesos reales, cobertura en el informe del verificador, integración continua y licencia completa.
- v0.6.3 → v0.6.4 (16-oct-2026): hallazgos F1–F3 de la revisión asistida por IA de la v0.6.3 (autorización derivada de un solo uso, fechas en el verificador, confirmación perdida), segunda revisión antes de publicar (conciliar primero; conflicto de identificador) y precisión de los límites. Primera corrida de CI en Node 18 y 20: la comprobación que atrapa al mutante M55 dependía de desbordar la pila, algo que cambia según la versión de Node; ahora comprueba que una entrada de 100 niveles se rechaza por su profundidad.

La primera versión pública (v0.1, cuatro casos) está en https://github.com/germanandres41-netizen/samaia-proof-surface.
