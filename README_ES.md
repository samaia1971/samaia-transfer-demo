# Demo: caso transferencia / reembolso — propuesta experimental v0.6.1 (13-oct-2026)

**En cinco líneas.** Un agente de IA quiere pagar 4.000 USD con una autorización que ya tiene.
La demo decide en el último momento si puede hacerlo (CONTINUE), si debe ir a un humano (ESCALATE) o si no (REJECT).
Corre todo contra una versión **vulnerable** y una **protegida**, por cuatro caminos hacia el pago.
Un verificador independiente revisa el **libro contable**, no el log del agente, y muestra casos en que el log dice "rechazado" y el dinero salió igual.
Todo es simulado. Los límites están al final.

```
node --test       → 104/104  (40 de la v0.4 + 36 comprobaciones + 28 controles rotos a propósito)
node run-v06.js   → tabla vulnerable vs. protegida, informe del verificador y meta-prueba
node run.js       → los 10 escenarios de la v0.4 y la latencia de decide()
```
(o `npm test` / `npm run demo`; requiere Node 18 o superior, sin dependencias)

## Cómo está armado

```
 agente ──► GATEWAY ───────────────────────────────────────────────► LIBRO CONTABLE (objetivo)
            caminos: herramienta · API legacy · cola · escalación      controla al registrar:
            protegida: arma la entrada desde fuentes controladas        decisión firmada y fresca,
              (agentes, autorizaciones, política, catálogo, estado),    pago = acción autorizada,
              decide y firma una vez por intento                        autorización vigente e intacta,
            vulnerable: cree lo que declara la solicitud, la API        estado sin cambios desde la decisión,
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

## Archivos

- `decide.js` — la decisión. Las reglas son las de la v0.4. Desde la v0.6, el registro firmado incluye la acción autorizada.
- `escalation.js` — ciclo de vida de ESCALATE: ticket ligado a la solicitud, un solo uso, plazo, directorio de autoridad y aprobación firmada.
- `sources.js` (v0.6) — fuentes controladas simuladas: estado actual con número de versión y registro de autorizaciones.
- `gateway.js` — capa de ejecución en versión vulnerable y protegida, con los cuatro caminos y el catálogo de operaciones (v0.6.1).
- `ledger.js` — el sistema objetivo, con sus controles al registrar y la cadena de hashes.
- `verify.js` — verificador independiente. No da un PASS/FAIL global: informa por solicitud y declara lo que no puede verificar.
- `checks.js` — 10 escenarios y 36 comprobaciones: P (protegida), L (libro), V (verificador) y R (revisiones externas y escalación).
- `mutants.js` — meta-prueba del "detector roto": 28 controles rotos a propósito (decide, libro, gateway, escalación, verificador y cadena), todos detectados.
- `MANIFEST.sha256` — hash de cada archivo. Se comprueba con `sha256sum -c MANIFEST.sha256`.
- `baselines.js`, `scenarios.js`, `run.js`, `test.js` — lo de la v0.4.
- `package.json` — solo scripts, sin dependencias.
- `RELATED_WORK.md` — quién más hace esto (en inglés).

## Lo que mostró la meta-prueba

- El control en el libro puede **tapar** una regresión del gateway. M10 (la API legacy deja de pasar por decide) solo lo detecta P3, que exige una decisión firmada en ese camino. Por eso se comprueba la mediación además del resultado.
- Un mutante mal construido (la primera versión de M11) quedó "ciego" porque no cambiaba nada. También hay que revisar los mutantes.

## Límites (lo que esta versión NO prueba)

- **Todo es simulado.** El libro, las fuentes y los caminos viven en memoria. Un sistema real tiene caminos que nadie inventarió.
- **Concurrencia.** El chequeo y el registro en el libro ocurren en un solo paso porque la simulación no tiene concurrencia real. En producción eso exige una transacción con verificación de versión (o equivalente). No se prueban carreras entre dos liberaciones simultáneas.
- **El verificador comprueba que el efecto corresponde a una decisión firmada, no que la decisión se tomó con fuentes correctas.** En A7, A8 y A10, la versión vulnerable firma decisiones basadas en lo que declaró el agente, y el verificador las da por CONSISTENT. Lo que cierra ese hueco es el gateway protegido y el control del libro, no el verificador.
- **Identidad del solicitante.** Se toma como autenticada (`requested_by.id`). La autenticación real queda fuera de la demo.
- **Cierre de caminos alternativos:** solo para los cuatro caminos modelados.
- **Evidencia de no ejecución:** viene del libro simulado. Si el libro real omitió un pago desde el origen, el verificador no lo ve; haría falta una fuente externa (extracto o conciliación).
- **Tope acumulado:** se lleva por autorización (y sus derivadas de escalación). No hay límites diarios ni por destino.
- **Artefacto congelado:** esta publicación, con su fecha y `MANIFEST.sha256`, es la versión congelada de la v0.6.1.
- **El camino de cada asiento lo declara quien envía el pago.** No va firmado.
- **La versión del estado es una sola para todo** (señalado por Grok). Cualquier cambio de estado invalida las decisiones pendientes, aunque no les afecte. Es conservador (rechaza de más, nunca de menos). Un sistema real necesitaría una versión por cada dato relevante.
- **Si las condiciones cambian durante una escalación, se rechaza.** No existe un camino para que el humano apruebe explícitamente bajo las condiciones nuevas: hay que hacer una solicitud nueva.
- **El catálogo de operaciones** es una tabla simulada con dos tipos. En un sistema real lo define el sistema que ejecuta la operación.
- **Reintentos de una escalación aprobada:** el ticket sigue abierto si el libro rechaza el pago. Que se pague una sola vez depende del control del libro, no del ticket.

## Historial

- v0.1 → v0.2: fallos de la primera revisión de ChatGPT del 11-oct-2026 (vencimiento inválido, estado en el futuro, condiciones vacías, campos faltantes, valores fuera de dominio; hash de la entrada completa; firma).
- v0.2 → v0.3: escalación corregida tras la segunda revisión (aprobador sin autoridad, ticket de otra solicitud, ticket reutilizado, fecha límite inválida, reclasificación del ejecutor).
- v0.3 → v0.4: una aprobación que tarda se re-evalúa con estado fresco.
- v0.4 → v0.5 (13-oct-2026): caminos alternativos, sistema objetivo con control propio, verificador independiente y meta-prueba de mutantes.
- v0.5 → v0.6 (13-oct-2026): los cuatro fallos de la revisión de ChatGPT con Astra, escalación integrada de punta a punta y package.json (sugerido por la revisión de Grok).
- v0.6 → v0.6.1 (13-oct-2026): irreversibilidad desde un catálogo, escalación con fuentes vigentes, cola robusta, respuestas no autenticadas que no gastan el ticket, ticket cerrado solo cuando el libro acepta, y manifiesto de hashes (revisiones de ChatGPT y Grok sobre la v0.6).
