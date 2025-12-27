from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional

from medical_evaluator import MedicalEvaluator

app = FastAPI()

# ---- CORS (lets the extension talk to backend) ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # you can lock down later
    allow_credentials=True,
    allow_methods=["*"],          # IMPORTANT: allows OPTIONS + POST
    allow_headers=["*"],
)

evaluator = MedicalEvaluator()

# ---- Models expected by the extension ----
class EvaluateRequest(BaseModel):
    text: str
    vertical: str = "medical"
    sensitivityLevel: int = 50
    site: Optional[str] = None
    clientVersion: Optional[str] = None

class EvaluateResponse(BaseModel):
    severity: str
    matchedCategories: List[str]
    matchedKeywords: List[str]
    counts: Dict[str, int]
    explanations: List[str]


# ---- Simple health check ----
@app.get("/health")
async def health():
    return {"status": "ok", "evaluator": "loaded"}


# ---- Main evaluate endpoint ----
@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest):
    """
    Called by the KorGuard extension.
    For medical vertical: use MedicalEvaluator.
    For other verticals: return green for now (local logic can handle them).
    """

    if req.vertical.lower() in ["medical", "healthcare"]:
        result = evaluator.evaluate_text(req.text, req.sensitivityLevel)
        return EvaluateResponse(
            severity=result.severity,
            matchedCategories=result.matched_categories,
            matchedKeywords=result.matched_keywords,
            counts=result.counts,
            explanations=result.explanations,
        )

    # Non-medical verticals – keep simple
    return EvaluateResponse(
        severity="green",
        matchedCategories=[],
        matchedKeywords=[],
        counts={"high": 0, "medium": 0},
        explanations=["Non-medical vertical – defaulting to green from backend."],
    )




# (Optional) explicit OPTIONS handler – usually not needed with CORSMiddleware
@app.options("/evaluate")
async def options_evaluate():
    return {"status": "ok"}


