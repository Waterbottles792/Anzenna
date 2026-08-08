# Anzenna API Contract v1

## POST /v1/scan
Auth: `Authorization: Bearer <api_key>`

### Request
```
{
  "text": "string, required, the prompt or completion to scan",
  "direction": "input" | "output",   // required
  "context": {                        // optional
    "system_prompt": "string, optional, helps detect prior-context leakage",
    "conversation_id": "string, optional, for grouping logs"
  }
}
```

### Response 200
```
{
  "verdict": "allow" | "flag" | "block",
  "risk_score": 0-100,
  "categories": ["prompt_injection", "jailbreak", "pii_leak", "exfiltration"],
  "reasons": ["short human-readable strings explaining the flags"],
  "layer_results": {
    "heuristics": { "triggered": bool, "matches": [...] },
    "classifier": { "score": 0.0-1.0, "label": string },
    "llm_judge": { "triggered": bool, "score": 0.0-1.0, "reasoning": string } | null
  },
  "latency_ms": number
}
```

### Error responses
- 401: invalid/missing API key
- 429: rate limit or usage cap exceeded — body includes `{ "error": "usage_limit_exceeded", "reset_at": ISO8601 }`
- 400: malformed request (missing `text` or invalid `direction`)
- 500: internal error — never blocks the customer's request silently; always return a clear error so SDKs can fail open/closed per customer config

## GET /v1/usage
Auth: same as above. Returns current billing period usage count and plan limit.

## Dashboard-internal endpoints (Phase 7/9, same API, separate auth via session not API key)
- GET /v1/keys — list API keys for logged-in org
- POST /v1/keys — create new key
- DELETE /v1/keys/:id — revoke key
- GET /v1/logs?limit=&cursor= — paginated scan history
