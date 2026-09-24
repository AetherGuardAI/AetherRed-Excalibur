# RAG & Embedding Attacks

Vector store poisoning, embedding privacy attacks, and document injection.

---

## KB Poisoning

**Knowledge Base Poisoning** — inject malicious documents to manipulate RAG retrieval.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0020 |
| Interface | Vector store adapter |
| Targets | Pinecone, Weaviate, ChromaDB, pgvector |

### How It Works

1. Generate poisoned documents crafted to match target queries
2. Compute embeddings that cluster near target query vectors
3. Inject poisoned documents into the vector store
4. Measure retrieval hijack rate (how often poisoned docs are retrieved)
5. Measure output influence (how much model output changes)
6. Assess stealth (can scanners detect the poisoned content?)

### Parameters

```yaml
type: kb_poisoning
params:
  strategy: embedding_cluster    # embedding_cluster, keyword_stuff, semantic_match
  injection_count: 20            # Number of poisoned docs to inject
  target_queries: 10             # Queries to attempt hijacking
  stealth_level: high            # low, medium, high
  samples: 30
```

### Metrics

- `retrieval_hijack_rate` — fraction of queries that return poisoned docs
- `output_influence_score` — how much model output changes
- `stealth_score` — how detectable the poisoned content is
- `detection_evasion_rate` — bypass rate against content scanners

---

## Embedding Inversion

**Embedding Privacy Attack** — reconstruct original text from embedding vectors.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0024 |
| Interface | Embedding API |
| Risk | PII leakage from embeddings stored in vector databases |

### How It Works

1. Train an inversion model on public embedding API outputs
2. Feed target embedding vectors through the inversion model
3. Measure reconstruction quality (BLEU/ROUGE scores)
4. Test membership inference (was text X in training data?)
5. Test attribute inference (extract attributes from embeddings)

### Parameters

```yaml
type: embedding_inversion
params:
  training_corpus_size: 1000     # Corpus for training inversion model
  test_samples: 50               # Target embeddings to invert
  reconstruction_method: mlp_decoder  # mlp_decoder, transformer_decoder
  samples: 50
```

### Metrics

- `reconstruction_quality` — BLEU/ROUGE between original and reconstructed
- `membership_inference_accuracy` — can we tell if text was in training?
- `attribute_leakage_rate` — sensitive attributes extractable from embeddings
- `privacy_risk_score` — composite privacy risk (0-1)

---

## Doc Injection

**Poisoned Document Injection** — hidden adversarial content in document formats.

| Property | Value |
|----------|-------|
| ATLAS ID | AML.T0020.001 |
| Interface | Document generation (no target needed) |
| Formats | PDF, DOCX, HTML, Markdown, CSV, JSON |

### How It Works

1. Take clean document templates
2. Inject hidden content using various steganographic techniques
3. Test if document processing pipelines detect the payloads
4. Measure scanner bypass rates

### Injection Techniques

| Technique | Description |
|-----------|-------------|
| `invisible_text` | Zero-width characters, white-on-white text |
| `metadata_payload` | PDF metadata, EXIF, OOXML custom properties |
| `unicode_confusable` | Homoglyphs, bidirectional overrides |
| `macro_embed` | PDF JavaScript, DOCX VBA stubs |
| `polyglot` | File valid in multiple formats simultaneously |
| `steganographic` | Hidden data in whitespace/formatting |

### Parameters

```yaml
type: doc_injection
params:
  formats: [pdf, docx, markdown, html]
  techniques: [invisible_text, metadata_payload, unicode_confusable]
  stealth_level: high
  samples: 30
```

### Metrics

- `detection_evasion_rate` — fraction of payloads undetected by scanners
- `payload_execution_success` — fraction of payloads that execute as intended
- `scanner_bypass_rates` — per-scanner bypass rates
