"""D030 first read-only ingestion architecture (Fireflies, synthetic v1).

See DECISIONS.md D030. Nothing under this package makes a real network
call, holds a real credential, or calls a real LLM in this milestone -
`zacai.ingestion.fireflies` and `zacai.ingestion.extraction` operate
entirely on caller-supplied, Fireflies-shaped synthetic fixtures and a
caller-supplied extraction function.
"""
