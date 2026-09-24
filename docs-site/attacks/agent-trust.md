# Agent & Trust Attacks

Multi-agent infection simulation and trust boundary exploitation.

---

## MAIC

**Multi-Agent Infection Chain** — simulates how a compromised agent infects others.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0052 |
| Interface | Protocol simulation (framework-agnostic) |
| Concept | Infection propagates via prompt injection in inter-agent messages |

### How It Works

1. Define agent topology (linear, star, mesh)
2. Inject infection payload at the first agent
3. Simulate message passing between agents
4. Measure how far infection propagates
5. Test quarantine effectiveness (if enabled)

### Agent Topologies

```
Linear (3 agents):     orchestrator → researcher → executor
Star (4 agents):       hub → agent_a, agent_b, agent_c
Mesh (5 agents):       planner ↔ coder ↔ reviewer ↔ tester ↔ deployer
```

### Infection Payload Types

| Type | Mechanism |
|------|-----------|
| `prompt_injection` | Hidden instructions in inter-agent messages |
| `tool_poisoning` | Malicious tool call payloads passed between agents |
| `context_manipulation` | False context/memory injected into shared state |

### Parameters

```yaml
type: maic
params:
  topology: linear_3_agent     # linear_3_agent, star_4_agent, mesh_5_agent
  payloads: [prompt_injection, tool_poisoning, context_manipulation]
  propagation_hops: 3
  quarantine_enabled: false
  samples: 30
```

### Metrics

- `avg_hops_to_infection` — mean propagation distance
- `avg_agents_infected` — mean infected agent count
- `infection_reached_target` — did infection reach the final agent?

---

## Cross-Trust

**Cross-Trust Boundary Simulation** — tests security at domain interfaces.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0024 |
| Interface | Black-box |
| Concept | Different security domains have different privilege levels |

### How It Works

1. Define trust boundaries (user→agent, agent→tool, tool→API)
2. Attempt privilege escalation across each boundary
3. Test data exfiltration vectors
4. Simulate confused deputy attacks
5. Measure boundary integrity

### Trust Boundaries

| Boundary | From → To | Risk |
|----------|-----------|------|
| `user_agent` | User prompt → AI agent | Prompt injection, privilege claims |
| `agent_tool` | Agent → Tool execution | Tool abuse, unauthorized access |
| `tool_api` | Tool → Backend API | SSRF, credential leakage, injection |

### Attack Scenarios

| Scenario | Description |
|----------|-------------|
| `privilege_escalation` | Claim higher privileges to access restricted functions |
| `data_exfiltration` | Extract sensitive data across boundary |
| `confused_deputy` | Trick agent into using elevated privileges on attacker's behalf |

### Parameters

```yaml
type: cross_trust
params:
  boundaries: [user_agent, agent_tool, tool_api]
  scenarios: [privilege_escalation, data_exfiltration, confused_deputy]
  samples: 30
```

### Metrics

- `per_boundary_breach_rate` — breach rate per boundary type
- `total_breach_rate` — overall boundary integrity failure rate
