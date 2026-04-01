from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class VulnerabilityResponse(BaseModel):
    id: str
    published: Optional[str] = None
    last_modified: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    score: Optional[float] = None
    weaknesses: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class ExtractRequest(BaseModel):
    text: str


class QueryRequest(BaseModel):
    question: str


class ExtractedEntities(BaseModel):
    cve_ids: List[str] = Field(default_factory=list)
    software: List[str] = Field(default_factory=list)
    severity: List[str] = Field(default_factory=list)
    attack_type: List[str] = Field(default_factory=list)


class QueryInterpretation(BaseModel):
    intent: Literal[
        "lookup_cve",
        "lookup_software",
        "lookup_severity",
        "lookup_attack_type",
        "mitigation_lookup",
        "unknown",
    ]
    cve_ids: List[str] = Field(default_factory=list)
    software: List[str] = Field(default_factory=list)
    severity: List[str] = Field(default_factory=list)
    attack_type: List[str] = Field(default_factory=list)


class QueryResponse(BaseModel):
    interpretation: QueryInterpretation
    results: List[VulnerabilityResponse] = Field(default_factory=list)
    explanation: Optional[str] = None