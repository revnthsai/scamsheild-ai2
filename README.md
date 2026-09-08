# ScamShield AI

A live, explainable scam-detection dashboard. Point a camera at a QR code
or narrate a call in your own words, and get a plain-language risk verdict
— with the exact reasons behind it, not just a red flag.

ScamShield AI is a **heuristic demo**: every check is a transparent,
named rule (e.g. "uses a raw IP address," "impersonates a bank domain,"
"asks for a gift card") rather than a trained black-box model. It's built
to show *how* scam detection reasoning works, not to replace your bank's
or carrier's official fraud tools.

## What it does

- **QR & link scanner** — decode a QR code with your camera or an
  uploaded image (entirely on-device, via [jsQR](https://github.com/cozmo/jsQR)),
  or paste a link directly. The content is scored against link-structure
  heuristics: raw IPs, Punycode, URL shorteners, brand impersonation,
  suspicious TLDs, and pressure language like "verify" or "suspended."
- **Call & voice analyzer** — listen live (via the Web Speech API) or
  paste a transcript. Text is scored against scam-script patterns:
  authority impersonation, manufactured urgency, requests for
  untraceable payment (gift cards, wire transfers, crypto), requests for
  secrecy, and credential harvesting.
- **Threat signal log** — a running, session-local history of everything
  checked, stored in your browser only.
- **Works with or without the backend.** If the FastAPI service isn't
  reachable, the frontend falls back to an equivalent on-device JS
  heuristic engine so the demo still works standalone.

## Project structure

```
scamshield-ai/
├── frontend/
│   ├── index.html            # Dashboard & live interactive simulator
│   ├── css/styles.css        # Glassmorphism UI & threat-pulse animations
│   └── js/
│       ├── app.js            # Core application logic & state controller
│       ├── qrScanner.js      # On-device QR overlay & decode engine
│       └── audioAnalyzer.js  # WebAudio visualizer & scam-keyword engine
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI REST endpoints & health check
│   │   ├── models.py         # Pydantic request/response schemas
│   │   └── services/
│   │       ├── qr_service.py     # Link risk-scoring heuristics
│   │       └── voice_service.py  # Transcript risk-scoring heuristics
│   ├── requirements.txt
│   └── .env.example
├── .gitignore
├── vercel.json                # Static frontend + Python API deployment config
├── build_project_zip.py       # Packages the whole project into a .zip
└── README.md
```

## Running the backend

Requires Python 3.10+.

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then edit ALLOWED_ORIGINS as needed
uvicorn app.main:app --reload --port 8000
```

The API is now live at `http://localhost:8000` (interactive docs at
`/docs`). Health check: `GET /api/health`.

### Endpoints

| Method | Path                 | Body                              | Description                       |
|--------|----------------------|------------------------------------|------------------------------------|
| GET    | `/api/health`        | —                                   | Liveness check                     |
| POST   | `/api/analyze/qr`    | `{ "content": "<decoded text>" }`  | Score a QR/link payload            |
| POST   | `/api/analyze/voice` | `{ "transcript": "<text>" }`       | Score a call transcript snippet    |

## Running the frontend

The frontend is static HTML/CSS/JS — no build step. Serve it with any
static file server so the camera and microphone APIs (which require a
secure context) work correctly:

```bash
cd frontend
python3 -m http.server 5500
# then open http://localhost:5500
```

By default the app tries `/api` (same-origin, for production) and then
`http://localhost:8000/api` (for local dev) to find the backend. If
neither responds within a couple seconds, it automatically switches to
the on-device JS heuristics and shows "Backend offline" in the footer —
the dashboard stays fully functional either way.

## Deploying

`vercel.json` is configured to deploy the static frontend and the
FastAPI backend (via `@vercel/python`) together as one Vercel project:

```bash
vercel deploy
```

`/api/*` routes to the Python backend; everything else is served as
static assets from `frontend/`.

## Packaging a distributable zip

```bash
python3 build_project_zip.py
```

Writes `scamshield-ai.zip` next to the script, excluding caches, virtual
environments, and your local `.env` file.

## Notes on the heuristics

- Every finding is a named, explainable rule with a fixed weight —
  intentionally simple so the reasoning is auditable, not a trained
  model.
- The QR/link engine never fetches the decoded URL; it only inspects
  the text itself, so scanning a malicious code can't trigger an
  outbound request from the server.
- The keyword lists (impersonation targets, payment red flags, TLDs)
  are a reasonable starting set for a demo, not exhaustive threat
  intelligence — extend `backend/app/services/` for production use.
- The frontend's local fallback logic in `js/app.js` and
  `js/audioAnalyzer.js` is deliberately kept in sync with the backend
  services so verdicts don't contradict each other depending on
  whether the API is reachable.

## License

Provided as-is for demonstration and educational purposes.
