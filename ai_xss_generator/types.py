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
    enctype: str = ""
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
    waf_knowledge: dict[str, Any] | None = None
    """Redacted notes about active authentication (e.g. 'Authorization header present').
    Never contains credential values — informational for the LLM prompt only."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StrategyProfile:
    attack_family: str = ""
    delivery_mode_hint: str = ""
    encoding_hint: str = ""
    session_hint: str = ""
    follow_up_hint: str = ""
    coordination_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class WafKnowledgeProfile:
    source_type: str = "local_repo"
    source_ref: str = ""
    engine_name: str = ""
    confidence: float = 0.0
    normalization: dict[str, Any] = field(default_factory=dict)
    matching: dict[str, Any] = field(default_factory=dict)
    likely_pressure_points: list[str] = field(default_factory=list)
    likely_blind_spots: list[str] = field(default_factory=list)
    preferred_strategies: list[str] = field(default_factory=list)
    avoid_strategies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

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
    bypass_family: str = ""
    risk_score: int = 0
    source: str = "heuristic"
    strategy: StrategyProfile | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PostFormTarget:
    """A POST form discovered during crawling that has testable parameters."""

    action_url: str
    """Absolute URL to POST the form to."""

    source_page_url: str
    """Page where the form was found — GET this to get a fresh CSRF token."""

    param_names: list[str]
    """Injectable parameter names (CSRF fields excluded)."""

    csrf_field: str | None
    """Name of the detected CSRF token hidden field, or None."""

    hidden_defaults: dict[str, str]
    """All hidden field name→value pairs from the form as discovered.
    Used as fallback when a fresh CSRF fetch fails."""


@dataclass(slots=True)
class UploadTarget:
    """A multipart/form-data upload form discovered during crawling."""

    action_url: str
    """Absolute URL to submit the upload form to."""

    source_page_url: str
    """Page where the upload form was found."""

    file_field_names: list[str]
    """File input names present in the form."""

    companion_field_names: list[str]
    """Non-file injectable companion fields submitted alongside the file."""

    csrf_field: str | None
    """Detected CSRF token field, if present."""

    hidden_defaults: dict[str, str]
    """Hidden field defaults captured from the form."""


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
