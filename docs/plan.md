# Anzenna — LLM Prompt-Injection & Jailbreak Firewall
## Detailed Build Plan for Claude Code

---

## How to use this document

This plan is split into **phases**. Each phase has:
- **Depends on:** which earlier phases must be *finished* before this one starts
- **Context needed:** exactly what Claude Code needs to have open/read to do this phase — usually just this plan section plus one or two contract files, NOT the full codebase history
- **Can run in a fresh/cleared context:** yes/no — if yes, you can `/clear` in Claude Code, paste only the phase section + the contract files listed, and it has everything required

The trick that makes phases independent is **Phase 0**: it produces a set of small "contract" files (API shape, DB schema, detection engine interface) that never change after Phase 0. Every later phase is written against those contracts, not against each other's source code. That's what lets you build the dashboard without the detection engine's code in context, build the detection engine without the billing code in context, etc.

Suggested repo layout (create this in Phase 0):

```
anzenna/
├── docs/
│   ├── contracts/
│   │   ├── API_CONTRACT.md        # request/response shapes, error codes
│   │   ├── DB_SCHEMA.sql          # full schema, source of truth
│   │   └── DETECTION_INTERFACE.md # function signature + I/O contract for the engine
│   └── plan.md                    # this file
├── engine/                        # Phase 1-5: detection pipeline (pure Python, no web framework)
├── api/                           # Phase 6-8: FastAPI service, DB, billing
├── dashboard/                     # Phase 9: Next.js frontend
├── sdks/
│   ├── python/                    # Phase 10a
│   └── node/                      # Phase 10b
├── docs-site/                     # Phase 11: public docs + landing page
└── infra/                         # Phase 12: deploy configs
```

---

## Dependency graph (at a glance)

```
Phase 0 (Scaffold + Contracts)
   │
   ├──► Phase 1 (Heuristics/Regex Layer)         ──┐
   ├──► Phase 2 (ML Classifier Layer)             ──┼──► Phase 5 (Unified Pipeline + Scoring)
   ├──► Phase 3 (Eval Dataset)                    ──┤        │
   ├──► Phase 4 (LLM-as-Judge Layer)              ──┘        │
   │                                                          ▼
   ├──► Phase 6 (DB Schema + Models)  ─────────► Phase 7 (FastAPI Service + Auth)
   │                                                          │
   │                                              ┌───────────┼───────────────┐
   │                                              ▼           ▼               ▼
   │                                       Phase 8 (Billing) Phase 9 (Dashboard) Phase 10 (SDKs)
   │                                                                              │
   └──► Phase 11 (Docs + Landing Page) — can start anytime after Phase 0 ────────┘
                                                                                  │
                                                                                  ▼
                                                                          Phase 12 (Deploy + Launch)
```

Phases 1, 2, 3, 4 can be built in **any order, in parallel, in separate cleared contexts** — they don't depend on each other, only on Phase 0. Phase 9 (dashboard) and Phase 10 (SDKs) can also be built in parallel once Phase 7's API contract is stable, even before Phase 7's actual code is finished, because they're built against `API_CONTRACT.md`, not against Phase 7's source.

---

## Phase 0 — Scaffold + Contracts

**Depends on:** nothing
**Can run in a fresh/cleared context:** yes (this is the starting context)

### Tasks
1. Create the repo structure shown above.
2. Set up `pyproject.toml` (or `requirements.txt`) for the `engine/` and `api/` Python projects — use Python 3.11+, `pytest` for testing.
3. Write `docs/contracts/API_CONTRACT.md` with the full request/response contract (see spec below — copy it in verbatim, it's the source of truth).
4. Write `docs/contracts/DB_SCHEMA.sql` with the full schema (see spec below — copy it in verbatim).
5. Write `docs/contracts/DETECTION_INTERFACE.md` defining the exact Python function signature the engine must expose (see spec below).
6. Set up `.env.example` listing every environment variable used across the whole project (fill in as later phases add more, but create the file now).
7. Initialize git, set up `.gitignore` for Python/Node.
8. Set up CI skeleton (GitHub Actions) that runs `pytest` on push — even with zero tests it should pass, so later phases just add tests into a working pipeline.

### Definition of Done
- [ ] Repo structure exists and is pushed to git
- [ ] All three contract files exist under `docs/contracts/`
- [ ] `.env.example` created
- [ ] CI runs and passes (even with no real tests yet)

---

## Phase 1 — Heuristics & Regex Detection Layer

**Depends on:** Phase 0
**Context needed:** `docs/contracts/DETECTION_INTERFACE.md` only
**Can run in a fresh/cleared context:** yes

### Tasks
1. In `engine/heuristics.py`, build a ruleset-driven matcher:
   - Load rules from `engine/rules/jailbreak_phrases.yaml` (not hardcoded — a YAML/JSON list of pattern → category → severity, so rules can be updated without code changes)
   - Seed it with common patterns: "ignore previous/above instructions", "you are now DAN", "developer mode enabled", "pretend you have no restrictions", "repeat the words above starting with...", "print your system prompt", etc. (research current public jailbreak prompt collections for more — there are open datasets/repos to pull from)
2. In `engine/pii.py`, build PII detectors:
   - Regex for emails, phone numbers, SSN-shaped strings
   - Credit card detection with Luhn checksum validation (regex alone gives too many false positives)
   - API key pattern detection (`sk-`, `ghp_`, `AKIA`, etc. — maintain as an extensible list)
3. In `engine/encoding.py`, build encoding-trick detection:
   - Detect and decode base64 blobs, then recursively re-scan decoded content through the same heuristics
   - Flag excessive unicode homoglyphs / zero-width characters / unusual character density
4. In `engine/layer1.py`, combine the above into one function `run_layer1(text: str) -> Layer1Result` returning matched categories, severities, and a preliminary score contribution.
5. Unit tests for every rule category, including deliberate edge cases (benign text that contains trigger words in an innocuous way, e.g. "ignore" used normally in a sentence) to track false-positive rate from day one.

### Definition of Done
- [ ] `run_layer1()` works standalone with no external dependencies
- [ ] Rules are in an editable YAML/JSON file, not hardcoded strings
- [ ] Test suite covers true positives, true negatives, and known tricky edge cases
- [ ] README in `engine/` explains how to add a new rule

---

## Phase 2 — ML Classifier Layer

**Depends on:** Phase 0
**Context needed:** `docs/contracts/DETECTION_INTERFACE.md` only
**Can run in a fresh/cleared context:** yes

### Tasks
1. Pick a pretrained prompt-injection/jailbreak classifier from Hugging Face (research current best options — models purpose-built for this exist and are actively maintained; don't train from scratch for v1).
2. In `engine/classifier.py`, wrap it behind `run_layer2(text: str) -> Layer2Result` returning a 0.0–1.0 score and label.
3. Handle model loading efficiently (load once at process start, not per-request — this matters a lot for latency).
4. Add a config flag to swap the underlying model easily (interface, not implementation, should be stable) so it can be upgraded later without touching callers.
5. Benchmark inference latency on CPU vs GPU and note it in the README — this affects hosting decisions in Phase 12.
6. Unit tests using a small fixed set of known injection/benign strings, asserting the classifier separates them with a reasonable margin.

### Definition of Done
- [ ] `run_layer2()` works standalone, loads model once, returns consistent shape
- [ ] Latency benchmark documented
- [ ] Tests pass with a fixed test set

---

## Phase 3 — Evaluation Dataset & Harness

**Depends on:** Phase 0 (can be built before Phases 1/2 finish — it just needs the interface to test against once they exist)
**Context needed:** `docs/contracts/DETECTION_INTERFACE.md` only
**Can run in a fresh/cleared context:** yes

### Tasks
1. Build `engine/eval/dataset.jsonl` — a labeled set of prompts: attack examples (injection, jailbreak, exfiltration attempts) and benign examples (including tricky benign ones that resemble attacks superficially). Pull from public jailbreak/injection prompt collections to seed this, then hand-add more.
2. Build `engine/eval/run_eval.py` — runs the full `scan()` function (once Phase 5 exists) or individual layers against the dataset and outputs precision, recall, F1, and a confusion matrix.
3. Store eval results over time in `engine/eval/results/` (one file per run, timestamped) so you can track whether tuning changes help or hurt — this history is also valuable resume/portfolio material.
4. Add a `make eval` or `poetry run eval` shortcut command.

### Definition of Done
- [ ] Dataset has at least 150-200 labeled examples across all categories, with a reasonable benign/attack balance
- [ ] Eval script runs and outputs metrics
- [ ] Results are saved and diffable across runs

---

## Phase 4 — LLM-as-Judge Layer

**Depends on:** Phase 0
**Context needed:** `docs/contracts/DETECTION_INTERFACE.md` only
**Can run in a fresh/cleared context:** yes

### Tasks
1. In `engine/llm_judge.py`, build `run_layer3(text: str, context: dict) -> Layer3Result` that calls a small/fast LLM with a structured prompt asking it to classify intent (injection/jailbreak/benign) and return JSON with a score + short reasoning string.
2. Design the judge prompt carefully — include a few labeled examples (few-shot) to stabilize output format, and force structured JSON output.
3. Make the actual API call function injectable (`judge_fn` parameter, defaulting to the real implementation) per the interface doc, so tests can mock it without network calls or cost.
4. Add response caching keyed on a hash of the input text, to avoid re-paying for identical repeated inputs (use an in-memory LRU for now; Redis comes in Phase 7 if needed at scale).
5. Add timeout + graceful failure handling — if the judge call fails or times out, the function must return a clear "judge_unavailable" state rather than crashing, so Phase 5 can decide how to score without it.
6. Unit tests using a mocked `judge_fn`.

### Definition of Done
- [ ] `run_layer3()` works with a mocked judge function in tests (no real API calls in test suite)
- [ ] Real implementation tested manually against a handful of real prompts
- [ ] Caching and timeout/failure handling both covered by tests

---

## Phase 5 — Unified Pipeline + Scoring

**Depends on:** Phases 1, 2, 3, 4 all complete
**Context needed:** all of `engine/` code (this is the one phase that does need the prior engine work in context, since it's wiring them together) plus `DETECTION_INTERFACE.md`
**Can run in a fresh/cleared context:** no — needs Phases 1-4's actual code present

### Tasks
1. In `engine/pipeline.py`, implement the public `scan()` function from the interface doc:
   - Always run Layer 1 (cheap)
   - Run Layer 2 unless Layer 1 already gave a high-confidence verdict
   - Only run Layer 3 (LLM judge) if Layers 1+2 combined land in an "ambiguous" score band — this is the cost/latency control that makes the product viable
2. Combine layer outputs into the final 0-100 `risk_score` and `verdict` using a documented, tunable scoring formula (write the formula and its rationale in `engine/SCORING.md` — this is worth having clearly documented for both maintainability and for explaining the design in interviews).
3. Make block/flag/allow thresholds configurable per call (so Phase 7 can later make them configurable per customer).
4. Run the Phase 3 eval harness against the full pipeline and record baseline metrics.
5. Tune thresholds based on eval results, re-run, document the before/after.

### Definition of Done
- [ ] `scan()` matches the interface doc exactly
- [ ] Baseline eval metrics recorded in `engine/eval/results/`
- [ ] `engine/SCORING.md` explains how the final score is computed

---

## Phase 6 — Database Schema + Models

**Depends on:** Phase 0
**Context needed:** `docs/contracts/DB_SCHEMA.sql` only
**Can run in a fresh/cleared context:** yes

### Tasks
1. Set up Postgres locally (or Supabase project) and apply `DB_SCHEMA.sql`.
2. In `api/models.py`, write ORM models (SQLAlchemy or similar) matching the schema exactly.
3. Write a migrations setup (Alembic) so schema changes are tracked going forward.
4. Write basic CRUD helper functions for each table (`create_org`, `create_api_key`, `log_scan`, `increment_usage`, etc.) in `api/db.py` — these will be called by Phase 7, but can be written and unit-tested against a test DB independently of the API layer.

### Definition of Done
- [ ] Schema applies cleanly to a fresh Postgres DB
- [ ] Models match schema exactly
- [ ] CRUD helpers have passing tests against a test/local DB

---

## Phase 7 — FastAPI Service + Auth + Rate Limiting

**Depends on:** Phase 5 (engine) and Phase 6 (DB) both complete
**Context needed:** `docs/contracts/API_CONTRACT.md`, the `engine.scan()` function signature, and `api/models.py` / `api/db.py` from Phase 6
**Can run in a fresh/cleared context:** partially — needs Phase 6's DB code present, but does NOT need Phases 1-4's internal engine code, only the `scan()` function signature

### Tasks
1. Set up FastAPI app in `api/main.py`.
2. Implement API key auth middleware: hash incoming key, look up `api_keys` table, reject if revoked/missing (401).
3. Implement `POST /v1/scan`: validate request against contract, call `engine.scan()`, log result to `scan_logs`, increment `usage_counters`, return response per contract.
4. Implement usage cap enforcement: before processing, check current period usage against the org's plan limit; return 429 with `usage_limit_exceeded` if over.
5. Implement `GET /v1/usage`.
6. Implement basic per-key rate limiting (requests/second) using an in-memory or Redis-backed limiter — protects against abuse independent of billing caps.
7. Add structured request logging and error handling per the contract (never a silent 500 with no body).
8. Integration tests hitting the real endpoints against a test DB, including auth failure, rate limit, and usage cap scenarios.

### Definition of Done
- [ ] All endpoints in API_CONTRACT.md implemented and match the contract exactly
- [ ] Auth, rate limiting, and usage cap enforcement all covered by integration tests
- [ ] p95 latency measured locally and documented

---

## Phase 8 — Billing (Stripe)

**Depends on:** Phase 6 (DB) and Phase 7 (API) — needs `orgs.stripe_customer_id` and usage counters to exist
**Context needed:** `DB_SCHEMA.sql`, the `/v1/usage` endpoint contract, Stripe's metered billing docs
**Can run in a fresh/cleared context:** yes, as an isolated module — only needs the DB schema and the shape of `usage_counters`, not the rest of the API code

### Tasks
1. Create Stripe products/prices for each plan tier (free, pro, scale) — metered usage price for pro/scale.
2. In `api/billing.py`, implement: create Stripe customer on org signup, report usage to Stripe on a schedule (daily batch job reading `usage_counters`, or real-time via Stripe usage records API).
3. Implement Stripe webhook handler (`POST /webhooks/stripe`) for subscription created/updated/canceled/payment_failed events, updating `orgs.plan` accordingly.
4. Implement a simple checkout/upgrade flow endpoint that returns a Stripe Checkout session URL.
5. Test using Stripe's test mode and CLI webhook forwarding.

### Definition of Done
- [ ] Org can upgrade from free to paid via Stripe Checkout in test mode
- [ ] Usage reporting to Stripe verified against Stripe dashboard test data
- [ ] Webhook handler covered by tests using Stripe's test event payloads

---

## Phase 9 — Dashboard (Next.js)

**Depends on:** Phase 0 only for the contract; real integration needs Phase 7's API running, but UI can be built against a mocked API first
**Context needed:** `docs/contracts/API_CONTRACT.md` only
**Can run in a fresh/cleared context:** yes — build against a mock server or fixture JSON matching the contract, wire to the real API last

### Tasks
1. Set up Next.js + Tailwind app in `dashboard/`.
2. Auth: login/signup (Supabase Auth or Clerk — pick one, wire to `orgs`/`users` tables).
3. API keys page: list, create, revoke keys (calls `/v1/keys` endpoints).
4. Scan logs page: paginated table of recent scans with verdict, risk score, category badges, timestamp (calls `/v1/logs`).
5. Overview page: usage-vs-plan chart, block-rate trend over time chart, top attack categories chart.
6. Billing/upgrade page: shows current plan, usage, and a link to Stripe Checkout (from Phase 8).
7. Responsive, clean UI — this is a customer-facing product, worth spending real design effort here (see the frontend-design skill/guidance if generating this with Claude Code, for good visual defaults rather than generic template look).

### Definition of Done
- [ ] All pages functional against the real API once Phase 7 is live
- [ ] Charts render correctly with real log data
- [ ] Mobile-responsive

---

## Phase 10 — SDKs

**Depends on:** Phase 0 (contract) only
**Context needed:** `docs/contracts/API_CONTRACT.md` only
**Can run in a fresh/cleared context:** yes, and Python/Node SDKs can each be their own cleared-context session

### Phase 10a — Python SDK
- `sdks/python/anzenna/client.py`: thin wrapper, `Anzenna(api_key).scan(text, direction="input")`
- Handle retries, timeouts, and a configurable `fail_open`/`fail_closed` behavior if the API is unreachable (critical design decision — document it clearly, since customers need to choose whether an outage blocks their app or lets traffic through unscanned)
- Package for PyPI (`pyproject.toml`, README, examples)

### Phase 10b — Node SDK
- Same behavior, idiomatic JS/TS, published to npm
- TypeScript types matching the API contract exactly

### Definition of Done (each)
- [ ] Installable locally (`pip install -e .` / `npm link`)
- [ ] Example script demonstrating a full scan call
- [ ] fail_open/fail_closed behavior implemented and tested

---

## Phase 11 — Docs Site + Landing Page

**Depends on:** Phase 0 (contract) for docs content; can start anytime
**Context needed:** `docs/contracts/API_CONTRACT.md`, pricing tiers from Phase 8 plan
**Can run in a fresh/cleared context:** yes

### Tasks
1. Landing page: problem statement (LLM apps are shipping with no protection against prompt injection), how it works, pricing, signup CTA.
2. Docs: quickstart (curl example + both SDKs), full API reference generated from the contract, integration guides for common frameworks (LangChain, raw OpenAI/Anthropic SDK usage).
3. A short public write-up of the detection architecture (Layers 1-3, scoring) — good for credibility and SEO, and doubles as portfolio content.

### Definition of Done
- [ ] Landing page live with clear CTA
- [ ] Docs cover quickstart + full API reference
- [ ] Architecture write-up published

---

## Phase 12 — Deploy + Launch Prep

**Depends on:** all previous phases functionally complete
**Context needed:** `infra/` configs, deployment target docs
**Can run in a fresh/cleared context:** yes, as an ops-focused session

### Tasks
1. Deploy API to Fly.io/Railway, DB via Supabase (or managed Postgres), dashboard + docs site to Vercel.
2. Set up environment variables/secrets in each hosting platform per `.env.example`.
3. Set up uptime monitoring and error alerting (e.g. a simple health-check endpoint + an uptime monitor, plus error tracking like Sentry).
4. Load-test the `/v1/scan` endpoint to confirm latency holds under concurrent load; decide if Layer 2's model needs GPU hosting based on Phase 2's benchmark.
5. Final security pass on the product itself: rotate any test secrets, confirm API keys are hashed not stored plaintext, confirm rate limiting is active, confirm scan text isn't over-retained (per the DB schema's privacy note).
6. Launch: post with a working demo link in relevant communities, publish the architecture write-up from Phase 11.

### Definition of Done
- [ ] Production deployment live and passing health checks
- [ ] Monitoring/alerting configured
- [ ] Security self-review complete
- [ ] Launch post published
