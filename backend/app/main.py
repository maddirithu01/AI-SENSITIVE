from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.detector import detect_sensitive_data

app = FastAPI(title='Sensitive Data Detection API', version='1.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)


class AnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)
    mode: str = 'mask'


@app.get('/health')
def health() -> dict:
    return {'status': 'ok', 'service': 'sensitive-data-detector'}


@app.post('/analyze')
def analyze(request: AnalysisRequest) -> dict:
    payload = request.text.strip()
    if not payload:
        raise HTTPException(status_code=400, detail='Input text is required.')

    mode = request.mode.lower()
    if mode not in {'mask', 'redact'}:
        raise HTTPException(status_code=400, detail='Mode must be either "mask" or "redact".')

    return detect_sensitive_data(payload, mode=mode)
