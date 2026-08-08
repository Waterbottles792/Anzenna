# Detection Engine Interface

The engine package (`engine/`) must expose exactly one public entrypoint:

    def scan(text: str, direction: str, context: dict | None = None) -> ScanResult

Where `ScanResult` is a dataclass/pydantic model matching the API_CONTRACT.md
response shape (minus `latency_ms`, which the API layer adds).

This function must:
- Have zero dependency on FastAPI, Postgres, Stripe, or any web/DB code
- Be fully testable by calling it directly with a string in a unit test
- Be deterministic given the same input EXCEPT for the llm_judge layer, which
  should be injectable/mockable (pass a judge_fn callable, default to the real
  one) so tests don't need network calls

This is the ONLY contract the API layer (Phase 7) relies on. As long as this
function signature and return shape stay stable, the internals of the engine
(Phases 1-5) can be rebuilt, retuned, or swapped freely.
