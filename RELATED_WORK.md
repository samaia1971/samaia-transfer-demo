# Related work (reviewed 10–13 Oct 2026)

Deciding, before execution, whether an AI agent's action may proceed is neither new nor exclusive to SAMAIA. This demo does not claim novelty of the mechanism.

| Work | What it does | What it has that this demo lacks | What this demo has that it does not declare |
|---|---|---|---|
| **EBL-Core** ([arXiv 2609.11596](https://arxiv.org/abs/2609.11596), Sep 2026) | Intent → execution-permit conformance profile; permit re-checked at use ("CurrentConditionsHold"), single use; reference artifact is a financial transfer | Conformance levels, concurrency tests, formal release contract | Human escalation with authority directory; Ed25519 signatures |
| **Faramesh** ([arXiv 2601.17744](https://arxiv.org/abs/2601.17744), Jan 2026) | Mandatory authorization boundary: PERMIT / DEFER / DENY, fail-closed, signed artifact bound to the action hash; human approval updates state and the action is re-evaluated | General control-plane model, chained log | A concrete escalation lifecycle (ticket, deadline, directory, approver cap) |
| **APort – Open Agent Passport** ([arXiv 2603.20953](https://arxiv.org/abs/2603.20953), Mar 2026; open source) | `before_tool_call` hook: ALLOW / DENY / ESCALATE, Ed25519-signed decisions, chained audit | Published product, agent passports, framework integrations | Implemented ESCALATE (the paper states theirs is not implemented yet); grant-time vs. current-state comparison |
| **Harmonic** – Tim Zlomke (public GitHub repositories, Apache-2.0) | Runtime governance call before each consequential execution; "temporal standing" (T₀ → ΔN → Tₙ); PERMITTED / CONSTRAINED / REFUSED with evidence records | Several public repositories and published empirical examinations | Signed human-approval escalation cycle in this specific case |
| **Kyvvu / TU Eindhoven** ([arXiv 2603.16586](https://arxiv.org/abs/2603.16586), Mar 2026) | Policies over the agent's action sequence | Conceptual sequence framework | Executable code |

## Method credit

The test method of this demo comes from public LinkedIn posts by **Akhilesh Warik (DecisionAssure / ControlProof)**, 12–13 Oct 2026: compare a deliberately vulnerable implementation with an alternate execution path and a protected one under the same adversarial scenario (revoke authorization, attempt the operation through both paths, inspect the target's state, and report what the evidence supports and what it cannot verify); and check that the tests catch a known broken control. The vulnerable and protected gateways (`gateway.js`), the alternate paths, the ledger as target (`ledger.js`), the independent verifier (`verify.js`) and the mutation meta-test (`mutants.js`) follow that method. The implementation is this demo's own; he has not reviewed it.

Large platforms: AWS Bedrock AgentCore Policy; Microsoft Agent Governance Toolkit and Entra runtime authorization; Google AP2 signed mandates; Visa and Mastercard agentic tokens; IETF draft-jiang-intent-security and Transaction Tokens for Agents; authorization and monitoring vendors (Cerbos, Permit.io, Oso, Zenity, Astrix and others).

Sources: arxiv.org/abs/2609.11596 · arxiv.org/abs/2601.17744 · arxiv.org/abs/2603.20953 · arxiv.org/abs/2603.16586 · docs.aws.amazon.com/bedrock-agentcore · ietf.org/archive/id/draft-jiang-intent-security-03.html
