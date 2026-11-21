# SKYLA PRIME — Memory Architecture

## Implemented

- **Conversational/task memory:** task + step records (full history).
- **Preference/project memory:** `memories` table with `kind`, `key`,
  `value`, `source`, `reliability` (0–1), timestamps.
- **Semantic knowledge:** FTS5 document store with provenance + hashes.
- **Recall:** keyword search ordered by reliability.

## Rules

- Model-generated statements are stored at low reliability and never
  treated as facts without user/source confirmation.
- Memory inherits permissions from its source; deletion is supported.
- Retrieval data is never auto-promoted to training data.

## Roadmap

Vector embeddings (Qdrant), knowledge graph (Neo4j), episodic summaries,
expiration policies, semantic dedup, held-out retrieval evaluation
(target: 90% per docs/BENCHMARK_STRATEGY.md).
