# ETIS Frontend — Phase 7 scaffold

Vite + React + TypeScript + MUI, set up per the three decisions made for Phase 7:

1. **Authentication** — since 2026-10-26 the dashboard holds no API key (a
   `VITE_` value is public). It gets an HttpOnly session cookie from
   `POST /session`, after a Cloudflare Turnstile check when the backend has
   one configured (`src/api/session.ts`, `src/api/turnstile.ts`), and retries
   once when a call comes back `SessionRequiredError`. `VITE_API_BASE_URL` is
   the only setting; empty means "same origin".
2. **Arabic-first with English toggle** — `src/i18n/` (i18next, default `ar`),
   `src/theme/` (MUI theme + RTL-aware emotion cache). The `AppBar` toggle
   button flips both language and layout direction together — see
   `App.tsx`'s `toggleLanguage()`.
3. **Tab-based navigation, not React Router** — three pages (`ScanPage`,
   `ThreatFeedPage`, `StatsPage`) switched via MUI `Tabs` in `App.tsx`.

## Structure

```
src/
  api/          — empty, next step: typed client for /analyze, /threats, /stats
  i18n/         — i18next config + en.json / ar.json (structural UI strings only)
  theme/        — MUI theme factory + RTL/LTR emotion cache factory
  pages/        — ScanPage, ThreatFeedPage, StatsPage (placeholders — no API
                  calls wired yet, on purpose, per "prove the client works
                  before building UI on top of it")
  App.tsx       — shell: AppBar, language toggle, tab navigation
  main.tsx      — entry point, loads i18n before rendering
```

## Setup

```
cp .env.example .env.local
npm install
npm run dev
```

Verified before handoff: `npx tsc --noEmit` (clean) and `npm run build` (clean,
415KB JS / 133KB gzipped — MUI is the bulk of that, expected at this stage).

## API client (`src/api/`)

- `types.ts` — TypeScript types mirroring the Pydantic models in
  `analyze.py` / `threats.py` / `stats.py` / `scan.py` / `blacklist.py`.
- `client.ts` — `analyzeScan()`, `getThreats()`, `getStats()`. Reads
  `VITE_API_BASE_URL` from env and sends the session cookie (`credentials: 'include'`).

**Two things in here are marked UNVERIFIED and need confirming against the
real backend, not guessed:**
1. The API key header name (`X-API-Key` in `client.ts` — a guess, since
   `app/core/security.py` wasn't shared yet).
2. `EngineDetail`'s exact fields beyond `score` (matched keywords, matched
   domain, etc. — unknown until seen), and the shape of an `ETISException`
   error response.

### Verify before building UI on top of this

```
node scripts/smoke-test-api.mjs
```

Run this with your backend up (`uvicorn app.main:app --reload` from
`backend/`). It hits `/stats`, `/threats`, and `/analyze` (both text-only
and url-only) directly and prints the raw JSON — no Vite, no env vars
needed. Paste the output back so `types.ts` can be corrected against real
shapes instead of assumptions, same pattern used for Phase 6.

## Not yet done (next steps, in order)

- Confirm `EngineDetail` shape and API key header name via the smoke test
  above, correct `types.ts` / `client.ts` if they're wrong
- Wire `ScanPage` / `ThreatFeedPage` / `StatsPage` to the real client
- UI design pass (palette/type/layout — Streamline dashboard screenshot
  noted as a style reference: rounded stat cards, gradient accent, soft
  gray section backgrounds — adapted, not copied, and reworked for
  RTL + verdict semantics instead of business metrics)
- Deployment config (`tensorflow-cpu` in backend requirements, CORS on
  FastAPI for the split frontend/backend hosting, Render/Railway env vars)
