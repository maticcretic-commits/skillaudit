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

    skillaudit audit <skill-dir-or-SKILL.md> [--format text|json]
    skillaudit audit-all <dir-of-skills> [--format text|json]
    skillaudit init

Exit codes: 0 = PASS or WARN only, 1 = FAIL (a critical or high
security finding), 2 = usage / IO error. Stdlib only, no network.
"""

import argparse
import json
import re
import sys
from pathlib import Path

VERSION = "1.0.0"

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


def finding(check, severity, category, path, line, message, snippet=""):
    return {"check": check, "severity": severity, "category": category,
            "path": path, "line": line, "message": message,
            "snippet": snippet}


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


def audit_skill(path):
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
    urls = collect_urls(list(texts.items()))
    for url, (display, line) in urls.items():
        findings.append(finding(
            "external-url", "info", "security", display, line,
            f"External URL referenced: {url}"))
    order = {display: i for i, (display, _) in enumerate(files)}
    findings.sort(key=lambda f: (order.get(f["path"], 99), f["line"],
                                 SEVERITY_RANK[f["severity"]]))
    return {
        "tool": "skillaudit", "version": VERSION, "schema_version": 1,
        "findings_summary": _findings_summary(findings),
        "skill": str(path),
        "name": meta.get("name") or root.name,
        "files_scanned": len(texts),
        "score": compute_score(findings),
        "verdict": compute_verdict(findings),
        "urls": sorted(urls),
        "findings": findings,
    }


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
          f"{len(result['findings'])} finding(s)")
    print(f"Score:   {result['score']}/100 — "
          f"{VERDICT_EMOJI[result['verdict']]} {result['verdict']}")
    by_file = {}
    for f in result["findings"]:
        by_file.setdefault(f["path"], []).append(f)
    for path, fs in by_file.items():
        print(f"\n## {path}")
        for f in fs:
            tag = "quality " if f["category"] == "quality" else ""
            print(f"  line {f['line']:<5} "
                  f"{SEVERITY_EMOJI[f['severity']]} "
                  f"{f['severity'].upper():<8} "
                  f"[{tag}{f['check']}] {f['message']}")
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
    try:
        result = audit_skill(args.path)
    except FileNotFoundError as e:
        _print_error(str(e), "file_not_found")
        return 2
    except ValueError as e:
        _print_error(str(e), "invalid_input")
        return 2
    if args.format == "json":
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
            results.append(audit_skill(child))
    if not results:
        _print_error(f"no skills found under {base} "
                     "(no subdirectory contains a SKILL.md)",
                     "no_skills_found")
        return 2
    if args.format == "json":
        all_findings = [f for r in results for f in r["findings"]]
        print(json.dumps(
            {"tool": "skillaudit", "version": VERSION,
             "schema_version": 1,
             "findings_summary": _findings_summary(all_findings),
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
    a.add_argument("path", help="skill directory or SKILL.md file")
    a.add_argument("--format", choices=("text", "json"),
                   default="text")
    a.set_defaults(fn=cmd_audit)

    aa = sub.add_parser("audit-all", help="audit every skill in a "
                                          "directory")
    aa.add_argument("path", help="directory containing skill "
                                 "subdirectories")
    aa.add_argument("--format", choices=("text", "json"),
                    default="text")
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
