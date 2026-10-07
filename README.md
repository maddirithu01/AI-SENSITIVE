# AI Sensitive Data Detection and Privacy Protection System

This project implements a privacy-focused text analysis workflow for detecting likely sensitive data such as names, email addresses, phone numbers, addresses, government identifiers, payment data, and credentials. The system is intentionally conservative: it highlights likely matches and explains that detection is heuristic rather than a guarantee of no sensitive content.

## Architecture

- Frontend: Next.js + TypeScript
- Backend: Python + FastAPI
- Data model: PostgreSQL/Supabase migration files
- Privacy: server-side masking and redaction before returning results

## Quick start

### 1) Install the frontend dependencies

```bash
npm install
```

### 2) Install the Python backend dependencies

```bash
cd backend
python -m pip install -r requirements.txt
```

### 3) Start the backend

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4) Start the frontend

```bash
npm run dev
```

Then open http://localhost:3000 and paste text to review.

## Sensitive-data categories supported

- Person names
- Email addresses
- Phone numbers
- Government identifiers (SSN-style patterns)
- Payment cards
- Password or secret-like strings
- Addresses
- Medical signal phrases

## Privacy behavior

- The backend performs detection and redaction server-side.
- Raw sensitive values are not intentionally logged.
- The API returns masked replacements rather than exposing the original value in the response payload.

## Supabase PostgreSQL

The repository includes migration SQL under `supabase/migrations` for analysis and audit records. A local Supabase instance can be connected through `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` environment variables.
