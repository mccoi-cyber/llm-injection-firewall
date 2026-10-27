"""
Multi-turn conversation tracking — catches "slow drip" injection, where an attacker
spreads a jailbreak across several individually-innocuous-looking messages specifically
to stay under a single-message block threshold. A ConversationState accumulates a
decayed running score across turns; the running score can push the conversation into
flag/block even when no single message would have.
"""

from dataclasses import dataclass, field

from .scanner import scan_prompt, ScanVerdict


@dataclass
class ConversationState:
    session_id: str
    decay: float = 0.7  # how much of the previous running score carries into the next turn
    running_score: float = 0.0
    turn_count: int = 0
    history: list[tuple[str, int]] = field(default_factory=list)  # (text_snippet, turn_score)

    def record_turn(self, text: str, block_threshold: int = 70,
                     flag_threshold: int = 35) -> tuple[ScanVerdict, "ConversationState"]:
        """Scan a single turn, fold its score into the running conversation score with
        decay, and return (this turn's own verdict, updated running verdict info)."""
        turn_verdict = scan_prompt(text, block_threshold, flag_threshold)
        self.running_score = self.decay * self.running_score + turn_verdict.score
        self.running_score = min(100.0, self.running_score)
        self.turn_count += 1
        self.history.append((text[:80], turn_verdict.score))
        return turn_verdict, self

    @property
    def running_action(self) -> str:
        if self.running_score >= 70:
            return "block"
        if self.running_score >= 35:
            return "flag"
        return "allow"

    def summary(self) -> str:
        lines = [f"Conversation '{self.session_id}': {self.turn_count} turn(s), "
                 f"running_score={round(self.running_score, 1)}, action={self.running_action}"]
        for i, (snippet, score) in enumerate(self.history, 1):
            lines.append(f"  turn {i} (score {score}): {snippet!r}")
        return "\n".join(lines)


class ConversationStore:
    """In-memory store of ConversationState keyed by session_id, for a CLI demo or a
    simple single-process integration. A real deployment would back this with Redis or
    similar so state survives across requests/processes -- see README."""

    def __init__(self):
        self._sessions: dict[str, ConversationState] = {}

    def get(self, session_id: str) -> ConversationState:
        if session_id not in self._sessions:
            self._sessions[session_id] = ConversationState(session_id=session_id)
        return self._sessions[session_id]
