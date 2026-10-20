# SkillAudit 🕵️

**Read the skill before the skill reads you.**

Agent skills are instruction packages: a `SKILL.md` plus bundled
scripts and references that an agent will follow and run — usually
installed from a stranger's repository on the strength of a friendly
README. The scanners that exist for this are enterprise products, or
need a hosted account and a token. The small, offline, deterministic
auditor was missing.

SkillAudit is that auditor. It pattern-checks the markdown *and* the
bundled code for instruction overrides, data exfiltration, destructive
shell commands, hidden content, scope escapes and credential fishing;
runs a quality pass over the packaging; inventories every external
URL the package phones home to; and reports a 0–100 score with a
PASS / WARN / FAIL verdict.

Offline and dependency-free: stdlib-only Python, no network, no
account. The checks are documented below, exactly as enforced.

```bash
python src/skillaudit.py audit path/to/skill
python src/skillaudit.py audit-all path/to/skills-folder
```

## The commands

| Command | What it does |
|---------|--------------|
| `audit <path>` | Audit one skill — a directory containing `SKILL.md`, or the `SKILL.md` file itself. Findings grouped by severity with `file:line` locations, a score, and a verdict. |
| `audit-all <dir>` | Audit every subdirectory that contains a `SKILL.md`. Summary table, worst first, with the failing skills' findings in full. |
| `audit … --format json` | Machine-readable findings: check id, severity, category, path, line, message, snippet (encoded blobs truncated, never echoed in full). |
| `init` | Scaffold a clean sample skill + `EXPECTED.md`. |

Exit codes everywhere: `0` = PASS or WARN only, `1` = FAIL (any
critical or high **security** finding), `2` = usage or IO error —
including pointing `audit` at a directory with no `SKILL.md`. Drop
it in CI and a hostile skill fails the build like a test would.

## Security checks

Applied to `SKILL.md` and every bundled text file (`.py`, `.sh`,
`.js`, `.md`, `.json`, `.yaml`, …):

| Check | Finds | Severity |
|-------|-------|----------|
| `override-instructions` | "Ignore previous instructions", "disregard your rules", concealment ("never tell the user", "do not mention this"), system-prompt extraction asks, jailbreak phrasing | 🔴 critical |
| `exfiltration` | Instructions to send/post/upload data to a URL, email or webhook; `curl`/`wget` uploads; HTTP POSTs of file content | 🔴 critical / 🟠 high |
| `sensitive-file-access` | Reading or moving SSH keys, `.env`, credential stores, browser data — a sensitive path plus a read/move verb; the bare path in a script is medium | 🟠 high / 🟡 medium |
| `destructive-shell` | `rm -rf`, `curl \| bash`, `base64 -d \| sh`, `chmod 777`, disabling the firewall/antivirus, `mkfs`, fork bombs, eval of remote content | 🟠 high |
| `hidden-content` | Zero-width unicode in instructions, directive text inside HTML comments, base64 blobs over 200 chars in prose, white-on-white / zero-size CSS text | 🟠 high / 🟡 medium |
| `scope-escape` | "All files on the system" claims (high); absolute paths outside the skill dir, `../` traversal toward home/system dirs (medium) | 🟠 high / 🟡 medium |
| `credential-handling` | Asking the user to paste a password, API key or token into chat or a file | 🟠 high |
| `external-url` | **Inventory:** every unique `http(s)` URL in the package, listed with its first location — see where a skill phones home before you install it | ⚪ info |

Two deliberate kindnesses: prohibitions are respected — "never read
the user's `.env`" is a safety instruction, not an attack, and does
not fire — and `.env.example`-style templates are not flagged for
the `.env` they create.

## Quality checks

Packaging problems are warnings (`-3` points each) — they can make a
verdict WARN, never FAIL on their own:

- Frontmatter exists and parses (malformed frontmatter is *reported*,
  never a crash), with `name` and `description` present.
- `name` matches the skill's directory name.
- Description is real: at least 40 characters, no placeholder text.
- Every relative file the body references actually exists.
- No `TODO` / `FIXME` / lorem ipsum left in the package.
- `SKILL.md` size sanity (over 500 lines or 64 KiB is flagged —
  oversized skills bloat every run's context).
- Bundled `.py` scripts pass a syntax sniff (`compile()`); a script
  that doesn't parse is a quality error.

## Scoring

Start at 100. Critical −40, high −20, medium −8, low/info −2,
quality warning −3. Floor 0. **FAIL is a rule, not a score:** any
critical or high security finding fails the audit no matter what
the arithmetic says. WARN means findings worth a human look; PASS
means clean (an info-level URL listing can still PASS).

## Quick start

```bash
# 1. Scaffold a clean sample skill and see a passing audit:
skillaudit init
skillaudit audit sample-skill

# 2. Audit a skill before installing it:
skillaudit audit ~/Downloads/some-skill

# 3. Sweep a whole folder of skills:
skillaudit audit-all ~/skills
```

## Example

From `examples/` — two fixture skills. `clean-skill` is well-formed
and does its one stated job. `hostile-skill` claims to format
meeting notes; its fine print trips the override, exfiltration,
hidden-content and destructive-shell checks. (Both are fictional
detector fixtures — the hostile one's instructions are test data,
with obviously fake destinations.)

```
$ skillaudit audit examples/clean-skill
====================================================================
SkillAudit — audit report
====================================================================
Skill:   examples/clean-skill (name: clean-skill)
Scanned: 3 file(s) · 1 finding(s)
Score:   98/100 — ✅ PASS

## examples/clean-skill/references/sources.md
  line 6     ⚪ INFO     [external-url] External URL referenced: https://example.org/market-bulletin

✅ PASS — no security or quality problems found.
```

```
$ skillaudit audit examples/hostile-skill
====================================================================
SkillAudit — audit report
====================================================================
Skill:   examples/hostile-skill (name: hostile-skill)
Scanned: 2 file(s) · 18 finding(s)
Score:   0/100 — ❌ FAIL

## examples/hostile-skill/SKILL.md
  line 18    🔴 CRITICAL [override-instructions] Instruction-override phrasing: tells the agent to ignore or disregard its real instructions
  line 18    🔴 CRITICAL [override-instructions] Concealment phrasing: tells the agent to hide behaviour from the user
  line 22    🔴 CRITICAL [override-instructions] Asks for the system prompt to be revealed or repeated
  line 24    🟠 HIGH     [credential-handling] Asks the user to hand over a password, key or token in chat or in a file
  line 27    🟠 HIGH     [sensitive-file-access] Reads or moves a sensitive file (SSH keys, .env, credential stores, browser data)
  line 28    🟠 HIGH     [exfiltration] Uploads data with curl/wget or an HTTP POST of file content
  line 30    🟠 HIGH     [scope-escape] Claims scope over the whole system rather than the skill's own files
  line 31    🟡 MEDIUM   [scope-escape] References paths outside the skill directory (absolute system paths or ../ traversal)
  line 33    🟠 HIGH     [hidden-content] Instruction-like text hidden inside an HTML comment — invisible when the page is rendered
  line 35    🟠 HIGH     [hidden-content] Contains 1 invisible zero-width/format character(s) — text a reader cannot see
  line 38    🟡 MEDIUM   [hidden-content] Suspiciously long base64-like blob in prose (560 chars) — encoded content a reader cannot review

## examples/hostile-skill/scripts/helper.sh
  line 3     🟠 HIGH     [destructive-shell] Destructive or unsafe shell pattern (recursive delete, pipe-to-shell, world-writable chmod, disabling security tools)
  line 4     🟠 HIGH     [destructive-shell] Destructive or unsafe shell pattern (recursive delete, pipe-to-shell, world-writable chmod, disabling security tools)
  line 5     🟠 HIGH     [destructive-shell] Destructive or unsafe shell pattern (recursive delete, pipe-to-shell, world-writable chmod, disabling security tools)

❌ FAIL — 14 critical/high security finding(s). Do not install this skill as-is.
```

And the whole folder at once, worst first:

```
$ skillaudit audit-all examples
====================================================================
SkillAudit — audit-all report
====================================================================
skill                        score  verdict findings
hostile-skill                    0  ❌ FAIL  18
clean-skill                     98  ✅ PASS  1

❌ FAIL — 1 of 2 skill(s) failed the audit.
```

## Why

A skill is a stranger's instructions plus a stranger's code, granted
your agent's tools and your user's trust. People skim the rendered
page; the zero-width characters, the HTML comments, the helpful
shell script and the one line about your SSH keys are all still
there. SkillAudit reads the package the way an attacker wrote it —
all of it, including the parts that don't render — in the thirty
seconds before you install, not in the incident review after.

It is a pattern auditor, not a sandbox: it will not catch a
sufficiently novel attack, and it says so. What it catches is the
known shape of skill abuse, deterministically, offline, for free.

## Part of AgentForge

SkillAudit is the seventh tool in the [AgentForge](https://github.com/maticcretic-commits)
trust layer for AI agents:

- **AgentProof** — verify agent work — [github.com/maticcretic-commits/agentproof](https://github.com/maticcretic-commits/agentproof)
- **PromptRE** — reverse-engineer agent prompts — [github.com/maticcretic-commits/promptre](https://github.com/maticcretic-commits/promptre)
- **AgentCI** — regression harness for agents — [github.com/maticcretic-commits/agentci](https://github.com/maticcretic-commits/agentci)
- **SecretScan** — scan agent outputs for leaked secrets — [github.com/maticcretic-commits/secretscan](https://github.com/maticcretic-commits/secretscan)
- **CostLedger** — cost accounting for agent runs — [github.com/maticcretic-commits/costledger](https://github.com/maticcretic-commits/costledger)
- **SchemaGuard** — validate agent outputs against their contracts — [github.com/maticcretic-commits/schemaguard](https://github.com/maticcretic-commits/schemaguard)
- **SkillAudit** — audit agent skills for hidden instructions and quality (this repo)
- **PromptDiff** — diff prompt versions — [github.com/maticcretic-commits/promptdiff](https://github.com/maticcretic-commits/promptdiff)
- **TraceTape** — the canonical run tape — [github.com/maticcretic-commits/tracetape](https://github.com/maticcretic-commits/tracetape)
- **PromptLint** — lint prompts for quality defects — [github.com/maticcretic-commits/promptlint](https://github.com/maticcretic-commits/promptlint)
- **ClaimCheck** — audit agent reports against their evidence — [github.com/maticcretic-commits/claimcheck](https://github.com/maticcretic-commits/claimcheck)

AgentProof checks what an agent *did*; PromptRE checks what it was *told*; AgentCI checks it still *works* after you change it; SecretScan checks that nothing *leaked*; CostLedger checks what it *cost*; SchemaGuard checks the output still *fits the contract*; SkillAudit checks the skill was *safe to install*; PromptDiff checks what the prompt change *changed*; TraceTape keeps the whole run on *tape*; PromptLint keeps the prompt itself *linted clean*; ClaimCheck makes sure every claim is *backed*.

## License

MIT
