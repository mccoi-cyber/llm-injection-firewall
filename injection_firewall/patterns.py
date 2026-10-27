"""
Signature library for prompt-injection / jailbreak detection.

Organized by technique category so the scoring layer (scanner.py) can weight and explain
*why* something was flagged, rather than returning an opaque single number.
"""

import re
from dataclasses import dataclass


@dataclass
class Signature:
    id: str
    category: str
    weight: int  # 0-100 contribution to risk score
    pattern: "re.Pattern"
    description: str


SIGNATURES: list[Signature] = [

    # --- Direct instruction override ---------------------------------------------------
    Signature(
        "OVERRIDE_INSTRUCTIONS", "instruction_override", 35,
        re.compile(r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|earlier|"
                    r"all)\b.{0,30}\b(instructions?|prompts?|rules?|context)\b", re.I),
        "Attempts to make the model discard its system prompt or prior instructions.",
    ),
    Signature(
        "NEW_INSTRUCTIONS_CLAIM", "instruction_override", 25,
        re.compile(r"\b(new|updated|real|actual|true)\s+(instructions?|rules?|system "
                    r"prompt|directive)s?\b", re.I),
        "Claims to supply replacement instructions that supersede the real system prompt.",
    ),

    # --- Persona / jailbreak framing -----------------------------------------------------
    Signature(
        "DAN_STYLE_JAILBREAK", "persona_jailbreak", 40,
        re.compile(r"\b(DAN|do anything now|jailbreak(ed)?|no restrictions|unfiltered "
                    r"mode|developer mode|without (any )?(restrictions|limitations|"
                    r"filters?|guardrails?))\b", re.I),
        "Named or described jailbreak persona / 'no restrictions' mode framing.",
    ),
    Signature(
        "ROLEPLAY_OVERRIDE", "persona_jailbreak", 20,
        re.compile(r"\b(pretend|act as|roleplay as|you are now|from now on you are)\b.{0,40}"
                    r"\b(no rules|no filters?|not bound by|without restrictions|evil|"
                    r"unrestricted)\b", re.I),
        "Roleplay framing specifically aimed at shedding safety constraints.",
    ),

    # --- System prompt extraction --------------------------------------------------------
    Signature(
        "SYSTEM_PROMPT_LEAK_REQUEST", "prompt_extraction", 30,
        re.compile(r"\b(repeat|print|reveal|show|output|what (is|was)|tell me)\b.{0,30}"
                    r"\b(system prompt|initial instructions?|your instructions?|"
                    r"the (prompt|rules) (above|you were given))\b", re.I),
        "Directly asks the model to disclose its system prompt or hidden instructions.",
    ),
    Signature(
        "VERBATIM_REPEAT_REQUEST", "prompt_extraction", 36,
        re.compile(r"\brepeat (the )?(text|words|everything) (above|before this)\b.{0,20}"
                    r"\bverbatim\b", re.I),
        "Asks the model to echo everything preceding this message verbatim, a common "
        "technique to exfiltrate a hidden system prompt.",
    ),

    # --- Delimiter / context-boundary attacks --------------------------------------------
    Signature(
        "FAKE_SYSTEM_DELIMITER", "delimiter_injection", 30,
        re.compile(r"(\[/?(system|SYS)\]|<\|?(system|im_start|im_end)\|?>|"
                    r"###\s*(system|instruction)s?\b)", re.I),
        "Injects a fake system/role delimiter token to impersonate a privileged message.",
    ),
    Signature(
        "END_OF_PROMPT_MARKER", "delimiter_injection", 15,
        re.compile(r"\b(end of (prompt|context|document|instructions?))\b.{0,40}"
                    r"\b(now|new task|instead|actually)\b", re.I),
        "Claims the legitimate prompt/document has ended, to introduce new 'instructions' "
        "that follow.",
    ),

    # --- Encoded / obfuscated payloads ---------------------------------------------------
    Signature(
        "BASE64_BLOB", "obfuscation", 15,
        re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
        "A long base64-looking blob — a common way to smuggle instructions past naive "
        "keyword filters.",
    ),
    Signature(
        "EXCESSIVE_UNICODE_ESCAPES", "obfuscation", 12,
        re.compile(r"(\\u[0-9a-fA-F]{4}){4,}"),
        "Multiple consecutive unicode escape sequences, sometimes used to hide keywords "
        "from naive string-matching filters.",
    ),

    # --- Indirect injection markers (content pulled from tools/documents/web) -----------
    Signature(
        "INDIRECT_TOOL_INSTRUCTION", "indirect_injection", 28,
        re.compile(r"\b(assistant|AI|model|agent)[,:]?\s+(you must|please|now)\b.{0,40}"
                    r"\b(send|email|post|exfiltrate|upload|forward)\b", re.I),
        "Content formatted as an instruction directed at the AI/agent itself — a hallmark "
        "of indirect prompt injection embedded in a document, webpage, or tool output.",
    ),
    Signature(
        "HIDDEN_INSTRUCTION_MARKER", "indirect_injection", 22,
        re.compile(r"\b(do not (tell|mention|reveal) (the )?(user|human))\b", re.I),
        "Instructs the model to conceal an action from the end user — a strong signal of "
        "malicious indirect injection rather than a legitimate user request.",
    ),
]
