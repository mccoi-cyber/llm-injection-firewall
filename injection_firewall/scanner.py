"""
Core scoring engine.

scan_prompt(): evaluate untrusted input (user message, or text pulled from a tool/
               document/webpage) before it reaches the model.
scan_output(): evaluate the model's own output before it reaches the user or a
               downstream action, to catch system-prompt leakage and attempts at
               self-generated exfiltration instructions.

Score is 0-100. Signature weights are additive but capped at 100, with diminishing
returns past the first few hits (see _combine) so that one long message padded with
ten weak signals doesn't automatically outrank one message with a single strong,
unambiguous signature.
"""

import difflib
from dataclasses import dataclass, field

from .patterns import SIGNATURES, Signature
from .normalize import normalize, decode_embedded_payloads
from .semantic import best_semantic_match


@dataclass
class Match:
    signature_id: str
    category: str
    weight: int
    description: str
    matched_text: str


@dataclass
class ScanVerdict:
    score: int
    action: str  # "allow" | "flag" | "block"
    matches: list[Match] = field(default_factory=list)

    def categories(self) -> set:
        return {m.category for m in self.matches}


def _combine(weights: list[int]) -> int:
    """Diminishing-returns combination instead of a flat sum, so stacking many weak
    signals can't trivially out-score one strong, specific one, and so score doesn't
    blow past 100 the moment a message has more than ~4 matches."""
    weights = sorted(weights, reverse=True)
    score = 0.0
    for i, w in enumerate(weights):
        score += w * (0.6 ** i)
    return min(100, round(score))


def _classify(score: int, block_threshold: int, flag_threshold: int) -> str:
    if score >= block_threshold:
        return "block"
    if score >= flag_threshold:
        return "flag"
    return "allow"


def _signature_matches(text: str) -> list[Match]:
    matches = []
    for sig in SIGNATURES:
        m = sig.pattern.search(text)
        if m:
            matches.append(Match(sig.id, sig.category, sig.weight, sig.description,
                                  m.group(0)[:120]))
    return matches


def scan_prompt(text: str, block_threshold: int = 70, flag_threshold: int = 35,
                 deep: bool = True) -> ScanVerdict:
    """Scan text for injection/jailbreak signals.

    When deep=True (the default), this runs three layers instead of one:
      1. Normalization — Unicode/zero-width/homoglyph normalization, so evasion tricks
         (invisible characters, lookalike letters) don't dodge the signature regexes.
      2. Signature matching — on both the normalized text AND any base64-decoded
         payloads found embedded in it (decode_embedded_payloads), since an attacker
         can hide a plaintext payload inside an innocent-looking encoded blob.
      3. Semantic similarity — lightweight local paraphrase detection (semantic.py)
         against a small library of known-attack exemplars, to catch attacks that
         don't hit any exact regex.

    deep=False skips layers 1 and 3 (normalization + semantic) for a faster, purely
    signature-based scan — useful for high-throughput paths where the extra layers'
    cost isn't justified, or for reproducing exact v1 behavior.
    """
    if not deep:
        matches = _signature_matches(text)
        score = _combine([m.weight for m in matches])
        return ScanVerdict(score=score, action=_classify(score, block_threshold, flag_threshold),
                            matches=matches)

    normalized = normalize(text)
    matches = _signature_matches(normalized)

    for decoded in decode_embedded_payloads(text):
        decoded_matches = _signature_matches(normalize(decoded))
        for m in decoded_matches:
            matches.append(Match(
                m.signature_id, m.category, m.weight,
                m.description + " (found inside a decoded base64 payload)",
                m.matched_text,
            ))

    sem = best_semantic_match(normalized)
    if sem:
        matches.append(Match(
            "SEMANTIC_PARAPHRASE_MATCH", sem.category, sem.weight,
            f"Text is lexically similar (Jaccard={sem.similarity}) to a known attack "
            f"pattern: {sem.exemplar!r}. No exact signature matched, but the phrasing "
            f"is a close paraphrase.",
            text[:120],
        ))

    score = _combine([m.weight for m in matches])
    return ScanVerdict(score=score, action=_classify(score, block_threshold, flag_threshold),
                        matches=matches)


def scan_output(output_text: str, system_prompt: str | None = None,
                 block_threshold: int = 70, flag_threshold: int = 35) -> ScanVerdict:
    """Check model output for (a) generic injection/jailbreak-adjacent content it may have
    been tricked into producing, and (b) verbatim or near-verbatim leakage of the real
    system prompt, which is the highest-value signal available when the real prompt is
    known to the firewall."""
    verdict = scan_prompt(output_text, block_threshold, flag_threshold)

    if system_prompt:
        leak_score, leaked_span = _detect_leak(output_text, system_prompt)
        if leak_score > 0:
            verdict.matches.append(Match(
                "SYSTEM_PROMPT_LEAK", "prompt_extraction", leak_score,
                "Model output contains a long overlapping span with the real system "
                "prompt, suggesting the system prompt was leaked.",
                leaked_span[:120],
            ))
            new_score = _combine([m.weight for m in verdict.matches])
            verdict = ScanVerdict(score=new_score,
                                   action=_classify(new_score, block_threshold, flag_threshold),
                                   matches=verdict.matches)
    return verdict


def _detect_leak(output_text: str, system_prompt: str, min_run: int = 40) -> tuple[int, str]:
    """Find the longest contiguous substring shared between output and the real system
    prompt. A long match is a strong leak signal; short incidental overlaps are ignored."""
    sm = difflib.SequenceMatcher(None, output_text, system_prompt, autojunk=False)
    match = sm.find_longest_match(0, len(output_text), 0, len(system_prompt))
    if match.size < min_run:
        return 0, ""
    span = output_text[match.a: match.a + match.size]
    # scale weight with how much of the system prompt leaked
    frac = match.size / max(1, len(system_prompt))
    weight = min(100, round(40 + frac * 60))
    return weight, span
