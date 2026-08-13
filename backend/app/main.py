from fastapi import FastAPI
from pydantic import BaseModel, Field
from .security_lab import triage
from .security_analysis import analyze_event

app = FastAPI(title="CyberGuardianAI", version="0.1.0")


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class AnalyzeResponse(BaseModel):
    risk: str
    indicators: list[str]
    recommendations: list[str]


class TriageResponse(AnalyzeResponse):
    iocs: dict
    mitre: list
    log_summary: dict


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "CyberGuardianAI"}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze_event(request.text)
    return AnalyzeResponse(
        risk=result.get("risk", "low"),
        indicators=result.get("indicators", []),
        recommendations=result.get("recommendations", []),
    )


@app.post("/api/v1/triage", response_model=TriageResponse)
def api_triage(request: AnalyzeRequest) -> TriageResponse:
    result = triage(request.text)
    return TriageResponse(
        risk=result.get("risk", "low"),
        indicators=result.get("indicators", []),
        recommendations=result.get("recommendations", []),
        iocs=result.get("iocs", {}),
        mitre=result.get("mitre", []),
        log_summary=result.get("log_summary", {}),
    )
