from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class FormField:
    tag: str
    name: str
    input_type: str
    id_value: str = ""
    placeholder: str = ""


@dataclass(slots=True)
class FormContext:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)


@dataclass(slots=True)
class DomSink:
    sink: str
    source: str
    location: str
    confidence: float


@dataclass(slots=True)
class ScriptVariable:
    name: str
    kind: str
    expression: str


@dataclass(slots=True)
class ParsedContext:
    source: str
    source_type: str
    title: str = ""
    frameworks: list[str] = field(default_factory=list)
    forms: list[FormContext] = field(default_factory=list)
    inputs: list[FormField] = field(default_factory=list)
    event_handlers: list[str] = field(default_factory=list)
    dom_sinks: list[DomSink] = field(default_factory=list)
    variables: list[ScriptVariable] = field(default_factory=list)
    objects: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    parser_plugins: list[str] = field(default_factory=list)
    auth_notes: list[str] = field(default_factory=list)
    """Redacted notes about active authentication (e.g. 'Authorization header present').
    Never contains credential values — informational for the LLM prompt only."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PayloadCandidate:
    payload: str
    title: str
    explanation: str
    test_vector: str
    tags: list[str] = field(default_factory=list)
    target_sink: str = ""
    framework_hint: str = ""
    risk_score: int = 0
    source: str = "heuristic"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GenerationResult:
    engine: str
    model: str
    used_fallback: bool
    context: ParsedContext
    payloads: list[PayloadCandidate]

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "model": self.model,
            "used_fallback": self.used_fallback,
            "context": self.context.to_dict(),
            "payloads": [payload.to_dict() for payload in self.payloads],
        }
