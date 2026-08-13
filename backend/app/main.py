from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="CyberGuardianAI", version="0.1.0")


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class AnalyzeResponse(BaseModel):
    risk: str
    indicators: list[str]
    recommendations: list[str]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "CyberGuardianAI"}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    text = request.text.lower()
    indicators: list[str] = []

    keywords = {
        "powershell": "PowerShell reference",
        "cmd.exe": "Windows command shell reference",
        "curl": "curl/network utility reference",
        "wget": "wget/network utility reference",
        "base64": "Base64 encoding reference",
        "credential": "Credential-related reference",
        "password": "Password-related reference",
    }

    for keyword, description in keywords.items():
        if keyword in text:
            indicators.append(description)

    risk = "low" if not indicators else "medium"
    recommendations = [
        "Validate the event against trusted logs and endpoint telemetry.",
        "Do not treat keyword matches alone as proof of compromise.",
    ]

    return AnalyzeResponse(
        risk=risk,
        indicators=indicators,
        recommendations=recommendations,
    )
