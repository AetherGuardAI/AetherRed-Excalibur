# Infrastructure Attacks

API security testing and multi-tenant isolation validation.

---

## API Key Impersonation

**Static API Key Exploitation** — tests detection of stolen/misused API credentials.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0040 |
| Interface | HTTP |
| Concept | Test if system detects abnormal key usage patterns |

### How It Works

1. Simulate API key usage from abnormal contexts
2. Test replay attacks from different IPs/geolocations
3. Attempt concurrent usage (key sharing detection)
4. Try expired/revoked key reuse
5. Enumerate keys via brute-force patterns
6. Measure detection rates and time-to-detection

### Attack Scenarios

| Scenario | Description |
|----------|-------------|
| `replay` | Use key from completely different IP/geo |
| `geo_mismatch` | Key used from geographically impossible location |
| `concurrent` | Same key used from multiple locations simultaneously |
| `expired` | Attempt to use revoked or expired keys |
| `enumeration` | Brute-force key patterns |
| `header_injection` | X-Forwarded-For spoofing with stolen keys |

### Parameters

```yaml
type: api_key_impersonation
params:
  scenarios: [replay, geo_mismatch, concurrent, expired, enumeration, header_injection]
  geo_locations: [US, CN, RU, BR]    # Simulated origins
  concurrent_count: 5                 # Simultaneous uses
  samples: 50
```

### Metrics

- `detection_rate` — fraction of impersonation attempts detected
- `bypass_success_rate` — fraction that evaded detection
- `time_to_detection` — avg time before system flags abuse
- `false_positive_rate` — legitimate uses flagged incorrectly

---

## Cross-Contamination

**Multi-Tenant Isolation Testing** — detects data leakage between tenants.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0024 |
| Interface | HTTP + protocol |
| Concept | Shared infrastructure must maintain strict tenant isolation |

### How It Works

1. Create simulated tenants (or use staging environment)
2. Attempt data access across tenant boundaries
3. Test shared resource exploitation (caches, GPU memory, connection pools)
4. Inject prompts targeting other tenants' contexts
5. Probe timing side-channels to infer other tenants' activity
6. Attempt model cache poisoning across boundaries

### Attack Scenarios

| Scenario | Description |
|----------|-------------|
| `shared_cache` | Attempt to read/poison shared cache entries |
| `prompt_injection_crossover` | Inject content visible to other tenants |
| `timing_side_channel` | Infer other tenants' activity via response timing |
| `namespace_traversal` | Attempt to access other tenants' data/schemas |
| `gpu_memory_leak` | Probe GPU memory for residual data from other tenants |
| `connection_pool_abuse` | Exhaust shared connection pools |

### Parameters

```yaml
type: cross_contamination
params:
  tenant_count: 3
  scenarios: [shared_cache, prompt_injection_crossover, timing_side_channel]
  isolation_type: simulated     # simulated or real (staging)
  samples: 30
```

### Metrics

- `contamination_events` — number of cross-tenant data leakage events
- `isolation_breach_severity` — severity per breach (low/medium/high/critical)
- `data_leakage_vectors` — which vectors successfully leaked data
- `side_channel_success_rate` — timing/resource inference success rate
