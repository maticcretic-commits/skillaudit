#!/usr/bin/env python3
"""
SkillAudit — "Read the skill before the skill reads you."

Agent skills are instruction packages: a SKILL.md plus bundled scripts
and references that an agent will follow and run, usually installed
from a stranger's repository with a friendly README. Existing skill
scanners are enterprise products or need a hosted account and a token.
SkillAudit is the small, offline, deterministic auditor that was
missing: pattern checks over the markdown *and* the bundled code,
a quality pass over the packaging, a 0–100 score, and a verdict.

    skillaudit audit <skill-dir-or-SKILL.md|-> [--format text|json|sarif]
                         [--profile default|owasp-agentic|ci-fast|release]
    skillaudit audit-all <dir-of-skills> [--format text|json|sarif]
                         [--profile ...]
    skillaudit init

Every finding carries its OWASP Agentic Skills Top 10 mapping
(`owasp`, e.g. AST01) where one honestly applies. Profiles change
only how findings gate the verdict — never what is detected.

Exit codes: 0 = PASS or WARN only, 1 = FAIL (a critical or high
security finding), 2 = usage / IO error. Stdlib only, no network.
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import tempfile
import unicodedata
from pathlib import Path

VERSION = "1.1.0"

SCAN_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".py", ".sh", ".bash", ".zsh",
    ".js", ".mjs", ".cjs", ".ts", ".json", ".yaml", ".yml",
    ".toml", ".ps1", ".rb",
}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}
MAX_FILE_BYTES = 2_000_000

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                  "low": "🔵", "info": "⚪"}
DEDUCTIONS = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 2}
QUALITY_DEDUCTION = 3

ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"
PLACEHOLDER_WORDS = ("todo", "tbd", "placeholder", "lorem", "xxx",
                     "coming soon", "your description here")


# Family severity tiers (see CONVENTIONS.md): critical -> CRITICAL,
# high -> HIGH, medium/low/info -> INFO. Findings carry both labels.
SEVERITY_TIER = {"critical": "CRITICAL", "high": "HIGH",
                 "medium": "INFO", "low": "INFO", "info": "INFO"}


def severity_tier(severity):
    return SEVERITY_TIER.get(str(severity).lower(), "INFO")


# OWASP Agentic Skills Top 10 (2026) mapping. Every security check
# maps to the risk it evidences; quality checks that describe the
# package rather than an attack map only where the OWASP list has a
# genuine home for them (AST04 insecure metadata). Checks with no
# honest mapping carry None — an untagged finding is reported as
# untagged, never force-fit.
OWASP_SKILLS = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}
OWASP_MAP = {
    # AST01 — the skill itself is the payload.
    "override-instructions": "AST01",
    "exfiltration": "AST01",
    "destructive-shell": "AST01",
    "credential-handling": "AST01",
    "hidden-content": "AST01",
    "unicode-tag-smuggling": "AST01",
    "bidi-control": "AST01",
    "homoglyph-mixing": "AST01",
    "encoded-instruction": "AST01",
    "persistence-instruction": "AST01",
    # AST03 — broader privilege than the job needs.
    "sensitive-file-access": "AST03",
    "scope-escape": "AST03",
    # AST04 — the metadata an installer trusts.
    "frontmatter": "AST04",
    "frontmatter-name": "AST04",
    "frontmatter-description": "AST04",
    "name-mismatch": "AST04",
    "description-trivial": "AST04",
    "missing-reference": "AST04",
    # AST05 — instructions arriving from outside the package.
    "remote-instruction": "AST05",
    "external-url": "AST05",
    # AST09 — delegation with no accountable trail.
    "handoff-delegation": "AST09",
    "handoff-unattested": "AST09",
    "handoff-malformed": "AST09",
}


def owasp_for(check):
    return OWASP_MAP.get(check)


def finding(check, severity, category, path, line, message, snippet=""):
    return {"check": check, "severity": severity,
            "tier": severity_tier(severity), "category": category,
            "owasp": owasp_for(check),
            "path": path, "line": line, "message": message,
            "snippet": snippet}


# Audit profiles (item: OWASP workstream). A profile changes only
# how findings gate the verdict — never what is detected, scored or
# reported.
PROFILES = ("default", "owasp-agentic", "ci-fast", "release")


def compute_verdict_profile(findings, profile):
    if profile == "default":
        return compute_verdict(findings)
    if profile == "ci-fast":
        # Gate on security only; quality findings are still listed
        # and scored, they just cannot fail the build.
        sec = [f for f in findings if f["category"] == "security"]
        if any(f["severity"] in ("critical", "high") for f in sec):
            return "FAIL"
        if any(f["severity"] != "info" for f in sec):
            return "WARN"
        return "PASS"
    if profile == "release":
        # Nothing ships with an open medium: any security finding at
        # medium or above, or any quality finding at all, fails.
        if any(f["category"] == "security"
               and f["severity"] in ("critical", "high", "medium")
               for f in findings):
            return "FAIL"
        if any(f["category"] == "quality" for f in findings):
            return "FAIL"
        if findings:
            return "WARN"
        return "PASS"
    if profile == "owasp-agentic":
        tagged = [f for f in findings if f.get("owasp")]
        if any(f["category"] == "security"
               and f["severity"] in ("critical", "high", "medium")
               for f in tagged):
            return "FAIL"
        if any(f["severity"] != "info" for f in findings):
            return "WARN"
        return "PASS"
    raise ValueError(f"unknown profile: {profile}")


def owasp_summary(findings):
    """Per-AST-code rollup: {code, title, count, highest_severity}."""
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3,
            "critical": 4}
    by_code = {}
    for f in findings:
        code = f.get("owasp")
        if not code:
            continue
        entry = by_code.setdefault(code, {
            "code": code, "title": OWASP_SKILLS[code], "count": 0,
            "highest_severity": "info"})
        entry["count"] += 1
        if rank[f["severity"]] > rank[entry["highest_severity"]]:
            entry["highest_severity"] = f["severity"]
    return [by_code[c] for c in sorted(by_code)]


def make_snippet(line):
    """A short, display-safe excerpt of an offending line."""
    s = line.strip()
    # Never echo a long encoded blob back in full.
    s = re.sub(r"[A-Za-z0-9+/]{40,}={0,2}",
               lambda m: m.group(0)[:12] + "…", s)
    if len(s) > 120:
        s = s[:117] + "..."
    return s


# ---------------------------------------------------------------------------
# Line rules: (check, severity, message, [patterns])
# ---------------------------------------------------------------------------

def _rx(p):
    return re.compile(p, re.IGNORECASE)


OVERRIDE_RULES = [
    _rx(r"\bignore\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+"
        r"(instructions?|prompts?|rules?|directions?)\b"),
    _rx(r"\bdisregard\s+(your\s+|the\s+|all\s+)?"
        r"(instructions?|rules?|system\s+prompt|guidelines?)\b"),
    _rx(r"\bforget\s+(your|all|the)\s+(previous\s+)?"
        r"(instructions?|rules?|training)\b"),
    _rx(r"\bdo\s+not\s+follow\s+(your|the)\s+(original\s+)?instructions?\b"),
    _rx(r"\byou\s+are\s+now\s+(in\s+)?"
        r"(developer\s+mode|dan|unrestricted|jailbroken)\b"),
]
CONCEALMENT_RULES = [
    _rx(r"\b(do\s+not|don'?t|never)\s+(tell|inform)\s+the\s+user\b"),
    _rx(r"\bnever\s+mention\s+this\b"),
    _rx(r"\bdo\s+not\s+(mention|reveal|disclose)\b"),
    _rx(r"\bwithout\s+(telling|informing|notifying)\s+the\s+user\b"),
    _rx(r"\bkeep\s+this\s+(hidden|secret)\s+from\s+the\s+user\b"),
]
SYSTEM_PROMPT_RULES = [
    _rx(r"\b(reveal|print|repeat|output|show|leak|extract|dump)\b"
        r"[^.\n]{0,40}\bsystem\s+prompt\b"),
    _rx(r"\bsystem\s+prompt\b[^.\n]{0,40}\b"
        r"(reveal|print|repeat|verbatim|word\s+for\s+word)\b"),
]

EXFIL_SEND_RULES = [
    _rx(r"\b(send|post|upload|transmit|forward|exfiltrate|ship)\b"
        r"[^.\n]{0,80}?\b(https?://|www\.|webhook)"),
    _rx(r"\bemail\b[^.\n]{0,60}?\b(to|at)\b[^.\n]{0,40}@"),
]
EXFIL_CURL_RULES = [
    _rx(r"\b(curl|wget)\b[^\n]*"
        r"(--data\b|--data-binary|--data-raw|--upload-file|\s-d\s|\s-F\s|\s-T\s)"),
    _rx(r"requests\.(post|put|patch)\s*\([^)\n]*(data\s*=|files\s*=)"),
]

SENSITIVE_TOKEN = _rx(
    r"(~|\$HOME|/home/[\w.-]+)?/?\.ssh\b|\bid_rsa\b|\bid_ed25519\b"
    r"|~/\.aws\b|\.aws/credentials|\.gnupg\b|/etc/passwd\b|/etc/shadow\b"
    r"|\bLogin Data\b|\.env\b"
    r"|browser\s+(cookies|history|passwords|stored\s+data)")
SENSITIVE_VERB = _rx(
    r"\b(cat|read|open|copy|cp|upload|send|post|base64|encode|print|echo|"
    r"include|attach|contents?\s+of)\b")
ENV_EXAMPLE = re.compile(r"\.env\.(example|sample|template|dist)\b",
                         re.IGNORECASE)
PROHIBITION = _rx(r"\b(never|do\s+not|don'?t|must\s+not|should\s+not|"
                  r"avoid|prohibited|forbidden)\b")

DESTRUCTIVE_RULES = [
    _rx(r"\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b"),
    _rx(r"\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
    _rx(r"\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
    _rx(r"\bchmod\s+(-R\s+|--recursive\s+)?0?777\b"),
    _rx(r"\b(disable|turn\s+off|deactivate|kill)\b[^.\n]{0,40}"
        r"\b(antivirus|firewall|windows\s+defender|defender|selinux|"
        r"apparmor|security\s+software)\b"),
    _rx(r"\bmkfs\b|\bdd\b[^\n]*\bof=/dev/"),
    _rx(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    _rx(r"\b(eval|exec)\s*\(\s*[^)\n]*(requests\.|urllib|fetch|http)"),
]

CREDENTIAL_RULES = [
    _rx(r"\b(ask|prompt|request)\b[^.\n]{0,40}"
        r"\b(password|api[\s_-]?key|secret|access\s+token|credentials?)\b"),
    _rx(r"\b(paste|type|enter|input|provide|share|send|give)\b[^.\n]{0,50}"
        r"\b(password|api[\s_-]?key|secret\s+key|access\s+token)\b"),
    _rx(r"\b(password|api[\s_-]?key)\b[^.\n]{0,30}"
        r"\b(in|into|via)\s+(the\s+)?(chat|a\s+file|this\s+file|plain\s?text)\b"),
]

REMOTE_INSTRUCTION_RULES = [
    _rx(r"\b(fetch|download|retrieve|load|pull)\b[^.\n]{0,50}"
        r"\binstructions?\b[^.\n]{0,40}\b(from|at)\b[^.\n]{0,30}"
        r"(https?://|www\.)"),
    _rx(r"\bfollow\s+(the\s+)?instructions?\s+(at|from|on|in)\b"
        r"[^.\n]{0,40}(https?://|www\.|the\s+(web\s?page|url|link|"
        r"document|file|pastebin))"),
    _rx(r"\binstructions?\s+(at|from)\s+https?://"),
    _rx(r"\bcheck\s+(the\s+)?(url|link|page|website|gist)\b"
        r"[^.\n]{0,40}\bfor\s+(new|updated|further|more)\s+"
        r"instructions?\b"),
]
PERSISTENCE_RULES = [
    _rx(r"\bin\s+all\s+future\s+(sessions?|conversations?|chats?)\b"),
    _rx(r"\b(always|permanently)\s+(remember|store|keep|retain)\b"
        r"[^.\n]{0,50}\b(this|that|it|the\s+following)\b"),
    _rx(r"\bremember\s+this\s+(forever|permanently|across\s+"
        r"sessions?|for\s+all\s+future)\b"),
    _rx(r"\b(write|add|append|save|store)\b[^.\n]{0,50}\bto\s+"
        r"(your\s+|the\s+)?(long[\s-]?term\s+)?(memory|memories|"
        r"config(uration)?|profile|instructions?\s+file|"
        r"system\s+prompt)\b"),
    _rx(r"\bmake\s+this\s+(a\s+)?permanent\s+(rule|instruction|"
        r"behaviour|behavior)\b"),
]
HANDOFF_RULES = [
    _rx(r"\bhand\s+off\s+(this|the\s+(conversation|task|session|"
        r"chat))\b[^.\n]{0,40}\bto\b"),
    _rx(r"\b(forward|pass|relay|transfer|send)\b[^.\n]{0,60}"
        r"\b(conversation|chat\s+history|transcript|context|"
        r"everything|all\s+files)\b[^.\n]{0,40}\bto\b[^.\n]{0,40}"
        r"\b(another|other|external|a\s+different|third[\s-]?party)"
        r"\b[^.\n]{0,25}\b(agent|assistant|model|service|system|api)\b"),
    _rx(r"\bdelegate\s+(this|the\s+task|everything|all\s+tasks?)\b"
        r"[^.\n]{0,40}\bto\b[^.\n]{0,30}\b(another\s+)?"
        r"(agent|assistant|model)\b"),
]

SCOPE_BROAD_RULES = [
    _rx(r"\ball\s+files\s+on\s+(the\s+)?(system|computer|disk|machine|device)\b"),
    _rx(r"\bevery\s+file\s+on\s+(the\s+)?(system|computer|machine)\b"),
    _rx(r"\bentire\s+(file\s?system|disk|home\s+directory)\b"),
]
SCOPE_PATH_RULES = [
    _rx(r"(?:^|[\s'\"`(=])/(home|Users|etc|var|root)/[\w./-]*"),
    _rx(r"(\.\./){2,}|~/\.\.|(\$HOME|\$\{HOME\})/\.\."),
]

URL_RE = re.compile(r"https?://[^\s'\"<>\])}*]+")

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
COMMENT_DIRECTIVES = _rx(
    r"\b(ignore|instructions?|must|always|never|run|execute|send|upload|"
    r"do\s+not|don'?t|silently|secret|before\s+answering)\b")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{200,}={0,2}"
                       r"(?![A-Za-z0-9+/=])")
# Shorter candidates for the decode test: long enough that ordinary
# prose words cannot qualify, short enough to catch real payloads.
B64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}"
                              r"={0,2}(?![A-Za-z0-9+/=])")
WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
# What a decoded blob must contain to count as a payload: the same
# override/concealment/system-prompt families the plain-text rules
# hunt, plus credential vocabulary.
DECODED_PAYLOAD_RULES = (
    OVERRIDE_RULES + CONCEALMENT_RULES + SYSTEM_PROMPT_RULES
    + [_rx(r"\b(password|api[\s_-]?key|secret|access\s+token|"
           r"credentials?)\b")])
WHITE_ON_WHITE = [
    _rx(r"color\s*:\s*(#fff\b|#ffffff\b|white\b)[^}]{0,80}?"
        r"background(-color)?\s*:\s*(#fff\b|#ffffff\b|white\b)"),
    _rx(r"background(-color)?\s*:\s*(#fff\b|#ffffff\b|white\b)[^}]{0,80}?"
        r"color\s*:\s*(#fff\b|#ffffff\b|white\b)"),
    _rx(r"font-size\s*:\s*0(px|pt|em)?\b"),
]

# Line-rule table: (check, severity, message, rules, guard_prohibition)
LINE_RULES = [
    ("override-instructions", "critical",
     "Instruction-override phrasing: tells the agent to ignore or "
     "disregard its real instructions", OVERRIDE_RULES, False),
    ("override-instructions", "critical",
     "Concealment phrasing: tells the agent to hide behaviour from "
     "the user", CONCEALMENT_RULES, False),
    ("override-instructions", "critical",
     "Asks for the system prompt to be revealed or repeated",
     SYSTEM_PROMPT_RULES, False),
    ("exfiltration", "critical",
     "Instructs sending/uploading data to an external destination",
     EXFIL_SEND_RULES, False),
    ("exfiltration", "high",
     "Uploads data with curl/wget or an HTTP POST of file content",
     EXFIL_CURL_RULES, False),
    ("destructive-shell", "high",
     "Destructive or unsafe shell pattern (recursive delete, "
     "pipe-to-shell, world-writable chmod, disabling security tools)",
     DESTRUCTIVE_RULES, False),
    ("credential-handling", "high",
     "Asks the user to hand over a password, key or token in chat "
     "or in a file", CREDENTIAL_RULES, True),
    ("scope-escape", "high",
     "Claims scope over the whole system rather than the skill's "
     "own files", SCOPE_BROAD_RULES, False),
    ("scope-escape", "medium",
     "References paths outside the skill directory (absolute system "
     "paths or ../ traversal)", SCOPE_PATH_RULES, False),
    ("remote-instruction", "high",
     "Tells the agent to fetch or follow instructions from an "
     "external source at runtime — the package the user reviewed "
     "is not the package that runs", REMOTE_INSTRUCTION_RULES, True),
    ("persistence-instruction", "high",
     "Tells the agent to remember or apply this beyond the current "
     "session — memory poisoning that outlives the review",
     PERSISTENCE_RULES, True),
    ("handoff-delegation", "medium",
     "Tells the agent to hand the conversation, context or files "
     "to another agent or service — delegation outside the user's "
     "view", HANDOFF_RULES, True),
]


def scan_line(line, path, is_markdown):
    """Security line rules + hidden-content checks for one line."""
    out = []
    for check, severity, message, rules, guarded in LINE_RULES:
        for rule in rules:
            m = rule.search(line)
            if m:
                if guarded and PROHIBITION.search(line[:m.end()]):
                    break
                out.append(finding(check, severity, "security", path, 0,
                                   message, make_snippet(line)))
                break
    # Sensitive-file access: token + verb = high; token alone in a
    # script = medium. Prohibitions ("never read .env") are respected.
    scrubbed = ENV_EXAMPLE.sub("", line)
    if scrubbed != line:
        # The line is about an .env.example-style template; a bare
        # ".env" next to it is the file the template creates, which
        # is the normal, benign workflow.
        scrubbed = re.sub(r"\.env\b", "", scrubbed)
    tok = SENSITIVE_TOKEN.search(scrubbed)
    if tok and not PROHIBITION.search(scrubbed[:tok.end()]):
        if SENSITIVE_VERB.search(scrubbed):
            out.append(finding(
                "sensitive-file-access", "high", "security", path, 0,
                "Reads or moves a sensitive file (SSH keys, .env, "
                "credential stores, browser data)", make_snippet(line)))
        elif not is_markdown:
            out.append(finding(
                "sensitive-file-access", "medium", "security", path, 0,
                "References a sensitive path (SSH, .env, credentials, "
                "browser data)", make_snippet(line)))
    # Zero-width / invisible unicode.
    zw = [c for c in line if c in ZERO_WIDTH_CHARS]
    if zw:
        sev = "high" if is_markdown else "medium"
        out.append(finding(
            "hidden-content", sev, "security", path, 0,
            f"Contains {len(zw)} invisible zero-width/format "
            f"character(s) — text a reader cannot see", make_snippet(line)))
    # Unicode tag characters (U+E0000–U+E007F): an entire invisible
    # ASCII channel — the documented "ASCII smuggling" carrier.
    tags = [c for c in line if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        out.append(finding(
            "unicode-tag-smuggling", "critical", "security", path, 0,
            f"Contains {len(tags)} Unicode tag character(s) — an "
            "invisible smuggling channel that can carry whole "
            "hidden instructions", make_snippet(line)))
    # Bidi override / isolate controls: reorder rendered text so a
    # reviewer reads a different line than the agent does.
    bidi = [c for c in line
            if c in "\u202a\u202b\u202c\u202d\u202e"
                    "\u2066\u2067\u2068\u2069"]
    if bidi:
        out.append(finding(
            "bidi-control", "high", "security", path, 0,
            f"Contains {len(bidi)} bidirectional text-control "
            "character(s) — rendered text can differ from the raw "
            "text a reviewer approved", make_snippet(line)))
    # Homoglyph mixing: Latin + Cyrillic/Greek inside one word.
    for word in WORD_RE.findall(line):
        scripts = set()
        for ch in word:
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                pass
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            out.append(finding(
                "homoglyph-mixing", "medium", "security", path, 0,
                f"Word {word!r} mixes Latin with "
                f"{'/'.join(sorted(scripts - {'LATIN'}))} letters — "
                "look-alike characters that defeat keyword review",
                make_snippet(line)))
            break
    # Encoded instructions: a base64 blob that DECODES to override /
    # exfiltration phrasing is not obfuscation, it is the payload.
    for m in B64_CANDIDATE_RE.finditer(line):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(
                blob + "=" * (-len(blob) % 4),
                validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if any(rx.search(decoded) for rx in DECODED_PAYLOAD_RULES):
            out.append(finding(
                "encoded-instruction", "critical", "security", path,
                0, "Base64 blob decodes to instruction-override or "
                "exfiltration phrasing — an encoded payload a "
                "reviewer cannot read in place", make_snippet(line)))
            break
    if is_markdown:
        # Long base64-like blobs in prose.
        for m in BASE64_RE.finditer(line):
            blob = m.group(0)
            if (any(c.islower() for c in blob)
                    and any(c.isupper() for c in blob)
                    and any(c.isdigit() for c in blob)):
                out.append(finding(
                    "hidden-content", "medium", "security", path, 0,
                    "Suspiciously long base64-like blob in prose "
                    f"({len(blob)} chars) — encoded content a reader "
                    "cannot review", make_snippet(line)))
                break
        # White-on-white / zero-size text.
        for rule in WHITE_ON_WHITE:
            if rule.search(line):
                out.append(finding(
                    "hidden-content", "medium", "security", path, 0,
                    "CSS trick that hides text from a human reader "
                    "(white-on-white or zero font size)",
                    make_snippet(line)))
                break
    return out


def scan_file_security(display_path, text, is_markdown):
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        for f in scan_line(line, display_path, is_markdown):
            f["line"] = i
            out.append(f)
    if is_markdown:
        # Instructions hidden inside HTML comments.
        for m in COMMENT_RE.finditer(text):
            body = m.group(1)
            if COMMENT_DIRECTIVES.search(body):
                line_no = text[:m.start()].count("\n") + 1
                out.append(finding(
                    "hidden-content", "high", "security", display_path,
                    line_no,
                    "Instruction-like text hidden inside an HTML "
                    "comment — invisible when the page is rendered",
                    make_snippet(body)))
    return out


def collect_urls(files):
    """url -> (display_path, line) of first occurrence."""
    urls = {}
    for display_path, text in files:
        for i, line in enumerate(text.splitlines(), start=1):
            for m in URL_RE.finditer(line):
                url = m.group(0).rstrip(".,;")
                if url not in urls:
                    urls[url] = (display_path, i)
    return urls


# ---------------------------------------------------------------------------
# Frontmatter + quality checks
# ---------------------------------------------------------------------------

def parse_frontmatter(text):
    """Parse the --- ... --- block of a SKILL.md.

    Returns (meta, body_start_line, errors). Minimal, line-oriented:
    ``key: value`` pairs, quoted values, and ``>`` / ``|`` block
    scalars. Anything it cannot read is reported in errors — it never
    crashes on malformed frontmatter.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, 1, ["no frontmatter block (file does not start "
                       "with '---')"]
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
    if end is None:
        return {}, 1, ["frontmatter block is never closed with '---'"]
    meta = {}
    errors = []
    key_lines = {}
    i = 1
    while i < end:
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", raw)
        if not m:
            if raw[:1] in (" ", "\t"):
                continue  # continuation of a previous value; tolerated
            errors.append(f"frontmatter line {i} is not a "
                          f"'key: value' pair: {raw.strip()[:40]!r}")
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        key_lines[key] = i
        if value in (">", "|", ">-", "|-", ">+", "|+"):
            block = []
            while i < end and (lines[i].startswith((" ", "\t"))
                               or not lines[i].strip()):
                block.append(lines[i].strip())
                i += 1
            value = " ".join(b for b in block if b)
        elif len(value) >= 2 and value[0] == value[-1] \
                and value[0] in ("\"", "'"):
            value = value[1:-1]
        meta[key] = value
    meta["_key_lines"] = key_lines
    return meta, end + 2, errors


REF_EXTS = r"(?:py|sh|md|js|json|txt|yaml|yml|toml|csv)"
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
BACKTICK_RE = re.compile(r"`([^`\n]+)`")


def quality_checks(root, skill_md_display, text):
    out = []
    meta, body_start, errors = parse_frontmatter(text)

    def q(check, line, message, severity="low"):
        out.append(finding(check, severity, "quality",
                           skill_md_display, line, message,
                           make_snippet(
                               text.splitlines()[line - 1])
                           if 0 < line <= len(text.splitlines()) else ""))

    if errors:
        for e in errors:
            q("frontmatter", 1, f"Frontmatter problem: {e}")
    key_lines = meta.get("_key_lines", {})
    name = meta.get("name", "").strip()
    if not name:
        q("frontmatter-name", 1,
          "Frontmatter has no 'name' — agents cannot identify the skill")
    elif root.name and name != root.name:
        q("name-mismatch", key_lines.get("name", 1),
          f"Frontmatter name {name!r} does not match the skill "
          f"directory name {root.name!r}")
    desc = meta.get("description", "").strip()
    if not desc:
        q("frontmatter-description", key_lines.get("name", 1),
          "Frontmatter has no 'description' — agents cannot tell when "
          "to use this skill")
    else:
        low = desc.lower()
        if len(desc) < 40:
            q("description-trivial", key_lines.get("description", 1),
              f"Description is only {len(desc)} characters — too "
              "short to say what the skill does or when to use it")
        elif any(re.search(rf"\b{w}\b", low) for w in PLACEHOLDER_WORDS):
            q("description-trivial", key_lines.get("description", 1),
              "Description still contains placeholder text")
    # Referenced relative files must exist.
    body_lines = text.splitlines()[body_start - 1:]
    for j, line in enumerate(body_lines):
        line_no = body_start + j
        refs = [m.group(1) for m in LINK_RE.finditer(line)]
        refs += [m.group(1) for m in BACKTICK_RE.finditer(line)
                 if re.search(rf"(/|\.{REF_EXTS}$)", m.group(1))]
        for ref in refs:
            ref = ref.split("#")[0].strip()
            if not ref or "://" in ref or ref.startswith(
                    ("#", "mailto:", "/", "~", "$")):
                continue
            if not re.search(rf"\.{REF_EXTS}$", ref) and "/" not in ref:
                continue
            target = (root / ref.lstrip("./")).resolve()
            if not target.exists():
                q("missing-reference", line_no,
                  f"Referenced file does not exist: {ref}")
    # Size sanity.
    n_lines = len(text.splitlines())
    if n_lines > 500 or len(text.encode("utf-8")) > 65536:
        q("skill-size", 1,
          f"SKILL.md is {n_lines} lines / "
          f"{len(text.encode('utf-8'))} bytes — oversized skills "
          "bloat every run's context")
    return out, meta


def placeholder_checks(display_path, text):
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        if re.search(r"\b(TODO|FIXME|XXX|TBD)\b", line) \
                or "lorem ipsum" in line.lower():
            out.append(finding(
                "placeholder-text", "low", "quality", display_path, i,
                "Placeholder text left in the package (TODO/FIXME/"
                "lorem ipsum)", make_snippet(line)))
    return out


def python_syntax_checks(display_path, text):
    try:
        compile(text, display_path, "exec")
    except SyntaxError as e:
        return [finding(
            "script-syntax", "medium", "quality", display_path,
            e.lineno or 1,
            f"Python script does not parse: {e.msg}",
            make_snippet((e.text or "").rstrip("\n")))]
    return []


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def collect_files(root, skill_md):
    """[(display_path, Path)] — SKILL.md first, then sorted."""
    found = []
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in SCAN_EXTENSIONS \
                and p.stat().st_size <= MAX_FILE_BYTES:
            found.append(p)
    found.sort(key=lambda p: (p != skill_md, str(p)))
    return [(str(p), p) for p in found]


def read_text(path):
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        return None  # binary; not auditable text
    return data.decode("utf-8", errors="replace")


def compute_score(findings):
    score = 100
    for f in findings:
        if f["category"] == "quality":
            score -= QUALITY_DEDUCTION
        else:
            score -= DEDUCTIONS[f["severity"]]
    return max(0, score)


def compute_verdict(findings):
    if any(f["category"] == "security"
           and f["severity"] in ("critical", "high") for f in findings):
        return "FAIL"
    if any(f["category"] in ("security", "quality")
           and not (f["category"] == "security"
                    and f["severity"] == "info")
           for f in findings):
        return "WARN"
    return "PASS"


def _findings_summary(findings):
    if any(f["severity"] == "critical" for f in findings):
        highest = "CRITICAL"
    elif any(f["severity"] == "high" for f in findings):
        highest = "HIGH"
    elif findings:
        highest = "INFO"
    else:
        highest = "NONE"
    return {"count": len(findings), "highest_severity": highest}


def _print_error(message, code):
    print(f"error: {message}", file=sys.stderr)
    print(json.dumps({"error": {"code": code, "message": message}}),
          file=sys.stderr)


def scan_tape_handoffs(root):
    """Audit handoff events on TraceTape tapes bundled in the skill.

    A skill that ships recorded runs ships recorded delegation.
    Returns (findings, tapes_scanned). Implements TraceTape's
    handoff convention directly: an event whose data.handoff is an
    object with from/to (+ a context hash for attestation).
    Malformed lines elsewhere on the tape are TraceTape's own
    validate job — here only handoffs are judged.
    """
    out = []
    tapes = 0
    for p in sorted(root.rglob("*.jsonl")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        text = read_text(p)
        if text is None:
            continue
        tapes += 1
        display = str(p)
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            data = obj.get("data")
            if not isinstance(data, dict) or "handoff" not in data:
                continue
            payload = data["handoff"]
            if not isinstance(payload, dict) \
                    or not isinstance(payload.get("from"), str) \
                    or not payload.get("from") \
                    or not isinstance(payload.get("to"), str) \
                    or not payload.get("to"):
                out.append(finding(
                    "handoff-malformed", "medium", "security",
                    display, i,
                    "Bundled tape carries a malformed handoff event "
                    "(data.handoff needs non-empty 'from' and 'to') "
                    "— the delegation record cannot be trusted",
                    make_snippet(line)))
                continue
            ctx = payload.get("context_sha256",
                              payload.get("sha256"))
            if not (isinstance(ctx, str) and ctx):
                out.append(finding(
                    "handoff-unattested", "medium", "security",
                    display, i,
                    f"Bundled tape records a handoff from "
                    f"{payload['from']!r} to {payload['to']!r} with "
                    "no context hash — the tape proves a handoff "
                    "happened, not what was handed over",
                    make_snippet(line)))
    return out, tapes


def audit_skill(path, profile="default"):
    """Audit one skill. `path` is a skill dir or its SKILL.md file.

    Raises FileNotFoundError / ValueError for usage errors (exit 2).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no such path: {path}")
    if path.is_file():
        skill_md, root = path, path.parent
    else:
        root = path
        skill_md = path / "SKILL.md"
        if not skill_md.is_file():
            raise ValueError(f"no SKILL.md found in {path}")
    files = collect_files(root, skill_md)
    texts = {}
    for display, p in files:
        t = read_text(p)
        if t is not None:
            texts[display] = t
    findings = []
    skill_text = texts.get(str(skill_md), "")
    for display, text in texts.items():
        is_md = display.lower().endswith((".md", ".markdown"))
        findings.extend(scan_file_security(display, text, is_md))
        findings.extend(placeholder_checks(display, text))
        if display.lower().endswith(".py"):
            findings.extend(python_syntax_checks(display, text))
    q_findings, meta = quality_checks(root, str(skill_md), skill_text)
    findings.extend(q_findings)
    tape_findings, tapes_scanned = scan_tape_handoffs(root)
    findings.extend(tape_findings)
    urls = collect_urls(list(texts.items()))
    for url, (display, line) in urls.items():
        findings.append(finding(
            "external-url", "info", "security", display, line,
            f"External URL referenced: {url}"))
    order = {display: i for i, (display, _) in enumerate(files)}
    findings.sort(key=lambda f: (order.get(f["path"], 99), f["line"],
                                 SEVERITY_RANK[f["severity"]]))
    result = {
        "tool": "skillaudit", "version": VERSION, "schema_version": 1,
        "findings_summary": _findings_summary(findings),
        "skill": str(path),
        "name": meta.get("name") or root.name,
        "files_scanned": len(texts),
        "tapes_scanned": tapes_scanned,
        "profile": profile,
        "score": compute_score(findings),
        "verdict": compute_verdict_profile(findings, profile),
        "urls": sorted(urls),
        "findings": findings,
    }
    if profile == "owasp-agentic":
        result["owasp_summary"] = owasp_summary(findings)
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

VERDICT_EMOJI = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}


def print_audit_text(result):
    print("=" * 68)
    print("SkillAudit — audit report")
    print("=" * 68)
    print(f"Skill:   {result['skill']} (name: {result['name']})")
    print(f"Scanned: {result['files_scanned']} file(s) · "
          f"{result.get('tapes_scanned', 0)} tape(s) · "
          f"{len(result['findings'])} finding(s)")
    print(f"Profile: {result.get('profile', 'default')}")
    print(f"Score:   {result['score']}/100 — "
          f"{VERDICT_EMOJI[result['verdict']]} {result['verdict']}")
    if result.get("owasp_summary"):
        print("\nOWASP Agentic Skills Top 10:")
        for e in result["owasp_summary"]:
            print(f"  {e['code']} {e['title']:<28} "
                  f"{e['count']} finding(s), worst "
                  f"{e['highest_severity'].upper()}")
    by_file = {}
    for f in result["findings"]:
        by_file.setdefault(f["path"], []).append(f)
    for path, fs in by_file.items():
        print(f"\n## {path}")
        for f in fs:
            tag = "quality " if f["category"] == "quality" else ""
            ow = f" {{{f['owasp']}}}" if f.get("owasp") else ""
            print(f"  line {f['line']:<5} "
                  f"{SEVERITY_EMOJI[f['severity']]} "
                  f"{f['severity'].upper():<8} "
                  f"[{tag}{f['check']}]{ow} {f['message']}")
            if f["snippet"]:
                print(f"             {f['snippet']}")
    bad = [f for f in result["findings"]
           if f["category"] == "security"
           and f["severity"] in ("critical", "high")]
    print()
    if result["verdict"] == "FAIL":
        print(f"❌ FAIL — {len(bad)} critical/high security "
              f"finding(s). Do not install this skill as-is.")
    elif result["verdict"] == "WARN":
        print("⚠️ WARN — no critical/high security findings, but "
              "review the items above before installing.")
    else:
        print("✅ PASS — no security or quality problems found.")


def print_audit_all_text(results):
    print("=" * 68)
    print("SkillAudit — audit-all report")
    print("=" * 68)
    ordered = sorted(results,
                     key=lambda r: (r["score"], r["name"]))
    print(f"{'skill':<28} {'score':>5}  {'verdict':<6} findings")
    for r in ordered:
        print(f"{r['name']:<28} {r['score']:>5}  "
              f"{VERDICT_EMOJI[r['verdict']]} {r['verdict']:<5} "
              f"{len(r['findings'])}")
    fails = [r for r in ordered if r["verdict"] == "FAIL"]
    for r in fails:
        print(f"\n--- findings for FAILING skill {r['name']} "
              f"({r['skill']}) ---")
        for f in r["findings"]:
            print(f"  {f['path']}:{f['line']} "
                  f"{SEVERITY_EMOJI[f['severity']]} "
                  f"{f['severity'].upper():<8} [{f['check']}] "
                  f"{f['message']}")
    print()
    if fails:
        print(f"❌ FAIL — {len(fails)} of {len(results)} skill(s) "
              "failed the audit.")
    else:
        print(f"✅ No failures — {len(results)} skill(s) audited.")


# ---------------------------------------------------------------------------
# init scaffold
# ---------------------------------------------------------------------------

SAMPLE_SKILL = """\
---
name: sample-skill
description: Adds two numbers from a CSV export and prints the total, for quick checks of spreadsheet sums before sharing them.
---

# Sample Skill

A tiny, well-behaved example skill. It reads a CSV file the user
points it at, adds the values in the `amount` column, and prints
the total. It touches nothing else: no network, no other files,
no settings.

## Steps

1. Ask the user for the path of the CSV file.
2. Read the file and sum the `amount` column.
3. Print the total with two decimal places.
"""

EXPECTED_TEMPLATE = """\
# What to expect

`sample-skill/` is a small, clean skill: valid frontmatter, a name
that matches its directory, a real description, no bundled scripts,
no external URLs, and no instructions beyond its stated job.

Run:

    skillaudit audit sample-skill

Expected: score 100/100, verdict PASS, exit code 0.

Then audit a skill you did not write — that is what this tool is
for:

    skillaudit audit path/to/any-skill
    skillaudit audit-all path/to/a-folder-of-skills

FAIL (exit 1) means a critical or high security finding: instruction
overrides, data exfiltration, destructive shell patterns, hidden
content, scope escapes, or requests for the user's credentials.
"""


# ---------------------------------------------------------------------------
# SARIF output (SARIF 2.1.0 — see CONVENTIONS.md)
# ---------------------------------------------------------------------------

def _sarif_level(tier, severity):
    """Tier CRITICAL/HIGH -> error; native medium -> warning; else note."""
    if tier in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_rule_name(rule_id):
    return "".join(p.capitalize() for p in re.split(
        r"[^A-Za-z0-9]+", rule_id) if p) or "Finding"


def build_sarif(findings):
    """Build a SARIF 2.1.0 log from SkillAudit finding dicts."""
    rules, seen = [], set()
    results = []
    for f in findings:
        level = _sarif_level(f["tier"], f["severity"])
        if f["check"] not in seen:
            seen.add(f["check"])
            rules.append({
                "id": f["check"],
                "name": _sarif_rule_name(f["check"]),
                "shortDescription": {
                    "text": f"SkillAudit check: {f['check']} "
                            f"({f['category']})"},
                "defaultConfiguration": {"level": level},
                "properties": {"severity": f["severity"],
                               "tier": f["tier"],
                               "category": f["category"],
                               "owasp": f.get("owasp")},
            })
        res = {"ruleId": f["check"], "level": level,
               "message": {"text": f["message"]},
               "properties": {"owasp": f.get("owasp"),
                              "severity": f["severity"],
                              "tier": f["tier"]}}
        if f.get("path"):
            loc = {"artifactLocation": {"uri": f["path"]}}
            if f.get("line"):
                loc["region"] = {"startLine": f["line"]}
            res["locations"] = [{"physicalLocation": loc}]
        results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "skillaudit",
                "version": VERSION,
                "informationUri":
                    "https://github.com/maticcretic-commits/skillaudit",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def cmd_init(args):
    base = Path(args.dir) if args.dir else Path.cwd()
    skill_dir = base / "sample-skill"
    targets = {skill_dir / "SKILL.md": SAMPLE_SKILL,
               base / "EXPECTED.md": EXPECTED_TEMPLATE}
    for p, content in targets.items():
        if p.exists() and not args.force:
            print(f"{p} exists — use --force to overwrite")
            return 2
    for p, content in targets.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    print(f"created sample-skill/ and EXPECTED.md in {base}")
    print("try it:  skillaudit audit sample-skill")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_audit(args):
    tmpdir = None
    try:
        if args.path == "-":
            # Pipe composability (CONVENTIONS.md): a lone SKILL.md
            # arrives on stdin; materialize it as a one-file skill dir.
            tmpdir = tempfile.mkdtemp(prefix="skillaudit-stdin-")
            (Path(tmpdir) / "SKILL.md").write_text(
                sys.stdin.read(), encoding="utf-8")
            result = audit_skill(tmpdir, profile=args.profile)
            result["skill"] = "<stdin>"
            if result["name"] == Path(tmpdir).name:
                result["name"] = "<stdin>"
            for f in result["findings"]:
                f["path"] = f["path"].replace(tmpdir, "<stdin>")
        else:
            result = audit_skill(args.path, profile=args.profile)
    except FileNotFoundError as e:
        _print_error(str(e), "file_not_found")
        return 2
    except ValueError as e:
        _print_error(str(e), "invalid_input")
        return 2
    finally:
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
    if args.format == "sarif":
        print(json.dumps(build_sarif(result["findings"]), indent=2,
                         ensure_ascii=False))
    elif args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_audit_text(result)
    return 1 if result["verdict"] == "FAIL" else 0


def cmd_audit_all(args):
    base = Path(args.path)
    if not base.is_dir():
        _print_error(f"not a directory: {base}", "not_a_directory")
        return 2
    results = []
    for child in sorted(base.iterdir()):
        if child.is_dir() and (child / "SKILL.md").is_file():
            results.append(audit_skill(child, profile=args.profile))
    if not results:
        _print_error(f"no skills found under {base} "
                     "(no subdirectory contains a SKILL.md)",
                     "no_skills_found")
        return 2
    if args.format == "sarif":
        print(json.dumps(build_sarif(
            [f for r in results for f in r["findings"]]),
            indent=2, ensure_ascii=False))
    elif args.format == "json":
        all_findings = [f for r in results for f in r["findings"]]
        print(json.dumps(
            {"tool": "skillaudit", "version": VERSION,
             "schema_version": 1,
             "findings_summary": _findings_summary(all_findings),
             "profile": args.profile,
             "root": str(base),
             "skills": results,
             "summary": {
                 "audited": len(results),
                 "failed": sum(1 for r in results
                               if r["verdict"] == "FAIL"),
                 "worst_score": min(r["score"] for r in results)}},
            indent=2, ensure_ascii=False))
    else:
        print_audit_all_text(results)
    return 1 if any(r["verdict"] == "FAIL" for r in results) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="skillaudit",
        description="Offline security + quality audit for agent "
                    "skill packages. Read the skill before the "
                    "skill reads you.")
    ap.add_argument("--version", action="version",
                    version=f"skillaudit {VERSION}")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI color output (this tool emits "
                         "no color; accepted harmlessly)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit one skill directory "
                                     "or SKILL.md file")
    a.add_argument("path", help="skill directory or SKILL.md file "
                                  "('-' reads a lone SKILL.md from stdin)")
    a.add_argument("--format", choices=("text", "json", "sarif"),
                   default="text")
    a.add_argument("--profile", choices=PROFILES, default="default",
                   help="gating profile: default verdicts, "
                        "owasp-agentic (fail on AST-mapped findings), "
                        "ci-fast (security gates only), release "
                        "(nothing medium-or-above ships)")
    a.set_defaults(fn=cmd_audit)

    aa = sub.add_parser("audit-all", help="audit every skill in a "
                                          "directory")
    aa.add_argument("path", help="directory containing skill "
                                 "subdirectories")
    aa.add_argument("--format", choices=("text", "json", "sarif"),
                    default="text")
    aa.add_argument("--profile", choices=PROFILES, default="default",
                    help="gating profile (see `audit --help`)")
    aa.set_defaults(fn=cmd_audit_all)

    i = sub.add_parser("init", help="scaffold a clean sample skill "
                                    "+ EXPECTED.md")
    i.add_argument("--force", action="store_true")
    i.add_argument("--dir", help="directory to write the sample "
                                 "files into")
    i.set_defaults(fn=cmd_init)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
