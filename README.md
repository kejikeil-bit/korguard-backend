# KorGuard Backend - Medical Mode Risk Evaluator

FastAPI backend for centralized medical/PHI risk evaluation.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
cd backend
uvicorn main:app --reload --port 8000
```

For production:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## API Endpoints

### POST /evaluate
Evaluate text for medical/PHI risk.

**Request:**
```json
{
  "text": "Patient name is John Smith, DOB is 05/15/1980",
  "vertical": "medical",
  "sensitivityLevel": 50,
  "site": "chatgpt",
  "extensionVersion": "2.5.0"
}
```

**Response:**
```json
{
  "severity": "red",
  "matchedCategories": ["PHI / HIPAA"],
  "matchedKeywords": ["patient name is", "John Smith", "DOB is", "05/15/1980"],
  "counts": {
    "high": 2,
    "medium": 0
  },
  "explanations": [
    "PHI detected: identifiers found near medical content",
    "Found DOB: 05/15/1980"
  ]
}
```

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "evaluator": "loaded"
}
```

## Configuration

Edit `config.json` to modify:
- Proximity window (default: 15 words)
- PHI identifier patterns (DOB, SSN, MRN, Insurance ID)
- Medical term categories
- Severity rules

Changes take effect immediately (no restart required for config changes if using file watching).

## Testing

Run the acceptance tests:
```bash
cd tests
python test_hipaa.py
```

Or use pytest:
```bash
pytest tests/test_hipaa.py -v
```

## Development

Set environment variables for local development:
```bash
export API_HOST=127.0.0.1
export API_PORT=8000
```

The extension will use `http://127.0.0.1:8000` by default during development.

## Production Deployment

Deploy to `https://api.korguard.app` (or update the endpoint in `src/backendClient.js`).

The backend uses CORS middleware to allow requests from Chrome extensions.

# korguard-backend
# korguard-backend
