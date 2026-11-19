"""X-32 synthetic TEST seeds: lint, check, rank, overlay and the Airtable rows (specs/X-32-exemplars.md sections 1, 2 and 10).

Usage (from the repo root):
    python scripts/x32_seeds.py lint                 every seed file against the skeleton rules and the tag vocabulary
    python scripts/x32_seeds.py check                lint, then the seed digests (eval/x32/seeds/manifest.json) and the
                                                     overlay against the reference ranker
    python scripts/x32_seeds.py manifest             rewrite eval/x32/seeds/manifest.json (a reviewed commit)
    python scripts/x32_seeds.py overlay              rewrite eval/x32/overlay/v1.json from the golden expected labels
    python scripts/x32_seeds.py rows                 print the Exemplars rows for the Airtable MCP create (go-ahead 7)

The seeds are synthetic: no client, letter or case behind them, names and places invented, codes ZZ-TEST-EX-<visa>-<NNN>.
A seed's terms (its Residual Quasi-Identifiers) and its shadow terms (canaries the term list leaves out, held only here
for the F-F14 X2 metric) never occur in a golden case, so a leak the harness counts can only come from the exemplar.

rank() is the reference implementation of steps 4 to 7 of ff13.rank_exemplars in test mode (the database function is
written in the X-32 migration, which is not applied yet). The overlay records what it picks for each golden case from the
case's expected support labels, so the PGlite tests of the migration can be held to the same answers.

Standard library only. Nothing here calls Airtable, Make or Supabase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEEDS = os.path.join(REPO, "eval", "x32", "seeds", "v1")
SEED_MANIFEST = os.path.join(REPO, "eval", "x32", "seeds", "manifest.json")
OVERLAY = os.path.join(REPO, "eval", "x32", "overlay", "v1.json")
GOLDEN = os.path.join(REPO, "eval", "ff14", "golden", "v1")
VOCAB = os.path.join(REPO, "ref", "exemplar_tags.json")
CITATION_MAP = os.path.join(REPO, "ref", "citation_map.json")
VISA_TYPES = os.path.join(REPO, "ref", "visa_types.json")

EXCLUDED = ("REF-CLAIM", "REF-RESETTLE", "HC-PR")   # V1 excludes refugee and H&C cells (decisions doc, X-32)
DOC = "SUBMISSION-LETTER"
FIRST_LINE = "Draft for review by RCIC [RCIC OF RECORD]. Not for submission until the RCIC of record has reviewed and signed it."
HEADINGS = ("Introduction", "Background", "Legal framework", "Submissions", "Conclusion")
LAST_LINE = "[RCIC OF RECORD]"
TAG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
PLACEHOLDER_RE = re.compile(r"\[[A-Z][A-Z ]*[A-Z]\]")
SEED_KEYS = ("code", "visa_code", "document_code", "source_type", "tags", "terms", "shadow_terms", "note", "skeleton_lines")
# Citation-like text the skeleton must not hold (citations are stripped to [CITATION]): an IRPA or IRPR key, a section
# word with a number, a parenthesised paragraph reference, the Act or the Regulations named with a number.
CITATION_RES = (
    re.compile(r"\b(IRPA|IRPR)\b", re.I),
    re.compile(r"\b(section|subsection|paragraph|subparagraph|regulation|clause|article|schedule|part|division|rule)s?\s+\d", re.I),
    re.compile(r"\b(s|ss|r|para|reg|art)\.\s*\d", re.I),
    re.compile(r"\b\d+(\.\d+)?\s*\(\s*[0-9a-z.]+\s*\)", re.I),
    re.compile(r"\b(Act|Regulations)\b[^.\n]{0,20}\d"),
)
FORBIDDEN_CHARS = ("<", ">", "{", "}", "_", "–", "—", "§", "*", "#", "|", "`")
# The TEST mark every seed skeleton carries once (finding 2026-11-16): the Status formula's FIND("ZZ-TEST", {Skeleton})
# then marks the row TEST, and stripping a seed into a real exemplar needs a Skeleton edit, which Content Modified tracks.
# It is bracketed, so a draft that copies it hard-fails the validator's square-bracket check (c_placeholder).
MARKER = "[ZZ-TEST SEED]"
# A seed models a compliant letter: the draft band of draft@1 (900 to 1,800 words).
MIN_WORDS, MAX_WORDS = 900, 1800
# Universal conclusions draft@1 forbids (F-F10 review finding 5, "never draw a conclusion wider than the facts").
UNIVERSAL_RES = (
    re.compile(r"\b(nothing|none|no part)\s+(in|of)\s+the\s+(record|file|evidence|material|materials|application|documents)\b", re.I),
    re.compile(r"\bnothing\b[^.]{0,40}\b(suggests?|indicates?|points?|shows?)\b", re.I),
    re.compile(r"\bno\s+(reason|indication|suggestion)\s+(to|that|of)\b", re.I),
    re.compile(r"\b(always|certainly|undoubtedly|unquestionably|guarantees?|guaranteed)\b", re.I),
)
# Review findings of 2026-11-16 (part 2): more draft@1 rules a seed must model, each checked outside Legal framework
# (which states the law in the provisions' own terms, such as "in the three years before the application").
# A conclusion wider than the facts: admissibility from police and medical records, permanent residence from one class.
WIDER_RES = (
    re.compile(r"\bnot inadmissible\b", re.I),
    re.compile(r"\bmeets? the requirements for permanent residence\b", re.I),
)
# Durations (draft@1: never compute a duration, an age, a count of years or the time between two dates, never say how
# long ago something happened). A stated duration is the placeholder [DURATION], a start date [START DATE] or [YEAR].
DURATION_RES = (
    re.compile(r"\[(NUMBER|AGE)\]\s+(years?|months?|weeks?|days?|decades?|generations?)\b", re.I),
    re.compile(r"\[AGE\]"),
    re.compile(r"\b(less|more)\s+than\s+\S+\s+(years?|months?|weeks?|days?)\s+old\b", re.I),
    re.compile(r"\bexceed(s|ing)?\s+(\S+\s+)?(years?|months?|weeks?|days?|the minimum period)\b", re.I),
    re.compile(r"\bwithin\s+the\s+\S+\s+(years?|months?)\b", re.I),
    re.compile(r"\bwell within\b", re.I),
    re.compile(r"\b(years?|months?|weeks?|days?)\s+(old|ago)\b", re.I),
    re.compile(r"\bago\b", re.I),
)
# Law from outside the provisions (draft@1: rely on no policy, program guideline or general knowledge of immigration law).
POLICY_RES = (
    re.compile(r"\bpublic\s+polic(y|ies)\b", re.I),
    re.compile(r"\b(program|programme|government|departmental|immigration)\s+polic(y|ies)\b", re.I),
    re.compile(r"\bguidelines?\b", re.I),
    re.compile(r"\b(program\s+delivery|operational)\s+instructions?\b", re.I),
)
# The Introduction holds who the applicant is and what the letter asks for (draft@1): no roadmap of the letter, no
# index of documents the case may not have, and no concern named as a weakness of the application.
INTRO_RES = (
    re.compile(r"\b(the|this)\s+letter\s+(first\s+)?(sets\s+out|addresses|explains|describes|covers)\b", re.I),
    re.compile(r"\b(calls?|call)\s+for\s+explanation\b", re.I),
    re.compile(r"\braises?\b", re.I),
    re.compile(r"\b(explain|explains|explanation|concerns?|weakness(es)?|gap|problems?|doubts?)\b", re.I),
)
# Every seed letter: no index of supporting documents, which no case is known to have (draft@1: never invent a document).
INDEX_RE = re.compile(r"\bindex\b", re.I)

# The Exemplar Code forms (finding 2026-11-16). The Status formula requires them for TEST and Active, the rankers drop any
# other code as candidate_malformed, so no other code text is ever stored, returned or written into a review note.
CODE_TEST_RE = "^ZZ-TEST-EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$"
CODE_ACTIVE_RE = "^EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}$"
CODE_ANY = re.compile(r"(ZZ-TEST-)?EX-[A-Z]+(-[A-Z]+)*-[0-9]{3}")


def code_ok(code: str, visa: str) -> bool:
    """A code of the form above whose visa part is exactly the row's visa code, so a name in capitals
    (EX-TR-VISIT-OKAFOR-001) is not a code. The Status formula holds the same rule with LEFT and LEN."""
    return bool(CODE_ANY.fullmatch(code) and re.fullmatch(r"[A-Z]+(-[A-Z]+)*", visa)
                and re.fullmatch(r"(ZZ-TEST-)?EX-" + re.escape(visa) + r"-[0-9]{3}", code))
# The ranker's answer when it selects nothing (finding 2026-11-16): a non-empty value no Airtable record ID can equal, so
# map(<agg>.array; key; "id"; <rank>.exemplar_record_id) always filters, whatever Make does with an empty filter value.
NO_PICK = "none"

# Residual Quasi-Identifiers rules of the Status formula (finding 2026-11-16), so Term Count (LF count plus one) equals
# the number of lines ff13.validate_draft keeps from @08. BLANK_LINE: a line holding nothing, or only characters the
# validator folds away (measured on PGlite 2026-11-16: space, underscore, U+00A0, U+1680, U+2000 to U+200A, U+202F,
# U+205F, U+3000), first and last lines included, so a trailing newline counts. SEPARATOR: any other character the
# validator splits on (CR, VT, FF, U+0085, U+2028, U+2029) and the tab. status_formula() puts both in the Status formula
# of specs/X-32-airtable-exemplars.json (the line feed as a backslash escape, every other character as itself, a test
# holds the plan equal), and RE2 reads these patterns as Python does here, apart from $ (the end of the text in RE2, see _py).
# scripts/ff14/x32.mjs mirrors them, and its PGlite test holds Term Count to the validator's own split of @08.
BLANK_CLASS = " _\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000"
TERMS_BLANK_LINE_RE = "(^|\n)[" + BLANK_CLASS + "]*(\n|$)"
TERMS_SEPARATOR_RE = "[\t\r\u000b\f\u0085\u2028\u2029]"


def _py(rx: str) -> str:
    """An Airtable (RE2) pattern of the formula in Python: $ is the end of the text only."""
    return rx.replace("$", r"\Z")


def terms_status_ok(text: object) -> bool:
    """The Residual Quasi-Identifiers clauses of the Status formula: not empty, no blank or fold-empty line, no other
    line separator."""
    return (isinstance(text, str) and text != "" and re.search(_py(TERMS_BLANK_LINE_RE), text) is None
            and re.search(TERMS_SEPARATOR_RE, text) is None)


def term_count(text: str) -> int:
    """The Term Count formula: 0 for an empty list, else the number of LF characters plus one."""
    return 0 if text == "" else text.count("\n") + 1


# --- the Exemplars Status formula (specs/X-32-airtable-exemplars.json step 6), built here so the plan, the code rule and
# the terms rule have one source. A test holds the plan's formula equal to status_formula().
# Who may attest. Airtable records who ticked Review Attestation (RCIC Attested By, a last modified by field), and Status
# compares it with these collaborator names. Until go-ahead 11 names the RCIC, the one entry matches nobody, so no row can
# be Active. Adding a name is a reviewed edit of the formula.
RCIC_ATTESTERS = ("RCIC NOT YET NAMED",)


def airtable_pattern(rx: str) -> str:
    """A pattern as the formula holds it: the line feed as the escape \\n, which the Term Count formula already relies
    on Airtable reading as a line feed. Every other character stays itself (no escape Airtable might misread)."""
    return rx.replace("\n", "\\n")


def _terms_clauses() -> list[str]:
    f = "{Residual Quasi-Identifiers}"
    return [f'{f} != ""', f'NOT(REGEX_MATCH({f}, "{airtable_pattern(TERMS_BLANK_LINE_RE)}"))',
            f'NOT(REGEX_MATCH({f}, "{airtable_pattern(TERMS_SEPARATOR_RE)}"))']


def status_formula(attesters: tuple = RCIC_ATTESTERS) -> str:
    """TEST, Active, Pending Review or Retired. A row with any TEST mark (source type, the code, the skeleton) is TEST or
    Pending Review, never Active, and TEST needs all three marks and the ZZ-TEST-EX-<its visa code>-NNN code. Active needs a code EX-<its visa code>-NNN, the RCIC's attestation ticked by a named
    RCIC collaborator after the last content change (Airtable times and records the tick, nobody types them), the
    consent for a de-identified draft, and a terms list whose Term Count equals the validator's line count."""
    who = ", ".join(f'{{RCIC Attested By}} = "{a}"' for a in attesters)
    terms = ",\n           ".join(_terms_clauses())
    return (
        'IF({Retired}, "Retired",\n'
        '  IF(OR({Source Type} = "Synthetic TEST", FIND("ZZ-TEST", {Exemplar Code}), FIND("ZZ-TEST", {Skeleton})),\n'
        f'    IF(AND({{Source Type}} = "Synthetic TEST", FIND("{MARKER}", {{Skeleton}}),\n'
        f'           REGEX_MATCH({{Exemplar Code}}, "{CODE_TEST_RE}"),\n'
        '           LEN({Exemplar Code}) = LEN({Visa Code}) + 15, LEFT({Exemplar Code}, LEN({Visa Code}) + 12) = "ZZ-TEST-EX-" & {Visa Code} & "-",\n'
        f'           {terms}),\n'
        '      "TEST", "Pending Review"),\n'
        f'    IF(AND(REGEX_MATCH({{Exemplar Code}}, "{CODE_ACTIVE_RE}"),\n'
        '           LEN({Exemplar Code}) = LEN({Visa Code}) + 7, LEFT({Exemplar Code}, LEN({Visa Code}) + 4) = "EX-" & {Visa Code} & "-",\n'
        '           {RCIC Reviewer} != "", {Review Attestation}, {RCIC Reviewed At},\n'
        f'           OR({who}),\n'
        '           IS_AFTER({RCIC Reviewed At}, {Content Modified}),\n'
        '           OR({Source Type} = "RCIC-written",\n'
        '              AND({Source Type} = "De-identified approved draft", {Consent Recorded}, {Consent Reference} != "")),\n'
        f'           {terms}),\n'
        '      "Active", "Pending Review")))')


# Content Modified tracks every field whose change must send an Active row back to Pending Review: the content, the
# cell keys, the provenance and consent, the code, the reviewer's name and Retired (so un-retiring needs a new
# attestation). It never tracks Review Attestation, whose own time is RCIC Reviewed At.
CONTENT_FIELDS = ("Skeleton", "Residual Quasi-Identifiers", "Fact Pattern Tags", "Visa Code", "Document Code", "Firm",
                  "Source Type", "Retired", "Consent Recorded", "Consent Reference", "Exemplar Code", "RCIC Reviewer")


class SeedError(Exception):
    pass


def _read(path: str) -> object:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def skeleton(seed: dict) -> str:
    """The Skeleton as the drafter sees it: each line of skeleton_lines is a paragraph or a fixed line, and they are
    separated by one blank line, the Form rule of draft@1 (finding 2026-11-16, a skeleton with no blank line modelled
    the opposite). The lint refuses a blank skeleton line, so the text has exactly one blank line between paragraphs and
    none at the start or the end. scripts/ff14/x32.mjs loadSeeds joins the same way."""
    return PARAGRAPH_SEP.join(seed["skeleton_lines"])


PARAGRAPH_SEP = "\n\n"


def _section(lines: list, start: str, end: str | None) -> list:
    """The paragraphs between the heading start and the heading end (or the closing lines), empty when either is missing."""
    if start not in lines:
        return []
    a = lines.index(start) + 1
    b = lines.index(end) if end and end in lines else len(lines) - 2
    return lines[a:b] if b >= a else []


def _term_parts(term: str) -> list:
    """The parts of a multi-word term a draft could copy without the whole: every run of two or more consecutive words
    shorter than the term (finding 2026-11-16: 'tea house' of 'rosewood tea house', 'cheese cave' of 'hillside cheese
    cave'). A single word is not checked, since most are ordinary words (the festival, the island). A distinctive single
    word written apart from its term is listed as a term of its own or reworded by hand."""
    words = term.split()
    parts = {" ".join(words[i:j]) for i in range(len(words)) for j in range(i + 2, len(words) + 1) if j - i < len(words)}
    return sorted(p for p in parts if p.split()[0].casefold() not in ("of", "the", "and")
                  and p.split()[-1].casefold() not in ("of", "the", "and"))


def _outside_terms(part: str, term: str, text: str) -> bool:
    """True when part occurs whole-word, case-blind, somewhere that is not inside an occurrence of the whole term."""
    spans = [m.span() for m in re.finditer(r"(?<![\w])" + re.escape(term) + r"(?![\w])", text, re.I)]
    for m in re.finditer(r"(?<![\w])" + re.escape(part) + r"(?![\w])", text, re.I):
        if not any(a <= m.start() and m.end() <= b for a, b in spans):
            return True
    return False


def _whole(term: str, text: str) -> bool:
    return re.search(r"(?<![\w])" + re.escape(term) + r"(?![\w])", text, re.I) is not None


def load_seeds(folder: str = SEEDS) -> list[dict]:
    out = []
    for name in sorted(os.listdir(folder)):
        if name.endswith(".json"):
            seed = _read(os.path.join(folder, name))
            if isinstance(seed, dict):
                seed["_file"] = name
            out.append(seed)
    return out


def load_vocab(path: str = VOCAB) -> list[dict]:
    data = _read(path)
    rows = data.get("exemplar_tags") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise SeedError(f"{os.path.basename(path)} has no exemplar_tags list")
    return rows


def vocab_problems(rows: list[dict], citation_map: list[dict], codes: list[str]) -> list[str]:
    """The vocabulary's own rules (section 2): tag form, a visa code that is supported and not excluded, addresses keys of
    the citation map for the same code and SUBMISSION-LETTER, unreviewed rows with no reviewer fields filled by Claude."""
    out = []
    keys = {(r["visa_code"], r["provision_key"]) for r in citation_map if r.get("document_type") == DOC}
    seen = set()
    for i, r in enumerate(rows):
        where = f"exemplar_tags[{i}]"
        if not isinstance(r, dict) or sorted(r) != sorted(("tag", "visa_code", "addresses", "label", "review_state",
                                                            "reviewer_licence", "reviewed_on")):
            out.append(f"{where} must have exactly tag, visa_code, addresses, label, review_state, reviewer_licence, reviewed_on")
            continue
        if not TAG_RE.fullmatch(str(r["tag"])):
            out.append(f"{where} tag {r['tag']!r} is not lowercase words joined by hyphens")
        if r["visa_code"] not in codes or r["visa_code"] in EXCLUDED:
            out.append(f"{where} visa_code {r['visa_code']!r} is not a supported, non-excluded code")
        if (r["tag"], r["visa_code"]) in seen:
            out.append(f"{where} repeats {r['tag']} for {r['visa_code']}")
        seen.add((r["tag"], r["visa_code"]))
        if not (isinstance(r["addresses"], list) and r["addresses"]):
            out.append(f"{where} addresses no provision key")
        else:
            for k in r["addresses"]:
                if (r["visa_code"], k) not in keys:
                    out.append(f"{where} addresses {k}, which ref/citation_map.json has no {DOC} row for {r['visa_code']}")
        if not (isinstance(r["label"], str) and 8 <= len(r["label"]) <= 120):
            out.append(f"{where} label must be a short phrase")
        if r["review_state"] != "unreviewed" or r["reviewer_licence"] is not None or r["reviewed_on"] is not None:
            out.append(f"{where} is not an unreviewed worksheet row (Claude never fills the review fields)")
    return out


def golden_text() -> str:
    """Every golden case's inputs and expected block as one lower-case text, for the disjointness test."""
    parts = []
    for name in sorted(os.listdir(GOLDEN)):
        if name.endswith(".json"):
            c = _read(os.path.join(GOLDEN, name))
            parts.append(json.dumps({"inputs": c.get("inputs"), "expected": c.get("expected")}, ensure_ascii=False))
    return "\n".join(parts)


def seed_problems(seed: object, vocab: list[dict], golden: str) -> list[str]:
    if not isinstance(seed, dict) or sorted(k for k in seed if k != "_file") != sorted(SEED_KEYS):
        return [f"a seed must have exactly {', '.join(SEED_KEYS)}"]
    out = []
    code, visa = seed["code"], seed["visa_code"]
    if not re.fullmatch(r"ZZ-TEST-EX-" + re.escape(str(visa)) + r"-\d{3}", str(code)) or "|" in str(code):
        out.append(f"code {code!r} is not ZZ-TEST-EX-<visa code>-<NNN>")
    if visa in EXCLUDED:
        out.append(f"{visa} is excluded in V1 (refugee and H&C)")
    if seed["document_code"] != DOC:
        out.append(f"document_code is not {DOC}")
    if seed["source_type"] != "Synthetic TEST":
        out.append("source_type is not Synthetic TEST")
    known = {r["tag"] for r in vocab if r.get("visa_code") == visa}
    tags = seed["tags"]
    # A seed may carry no tag: it models no weakness pattern of the vocabulary, scores 0 for every case and is still a
    # structure model where its cell has nothing better (section 2, a tag never addresses a ground the seed argues as met).
    if not (isinstance(tags, list) and all(isinstance(t, str) for t in tags) and len(set(tags)) == len(tags)):
        out.append("tags must be a list with no repeat")
    else:
        unknown = [t for t in tags if t not in known]
        if unknown:
            out.append(f"tags {unknown} are not in the vocabulary for {visa}")
    lines = seed["skeleton_lines"]
    if not (isinstance(lines, list) and all(isinstance(x, str) for x in lines) and len(lines) >= 12):
        return out + ["skeleton_lines must be a list of text lines"]
    text = skeleton(seed)
    if text.count(MARKER) != 1 or MARKER in lines[0] or MARKER in lines[-1] or any(MARKER == x for x in lines):
        out.append(f"the skeleton must hold the TEST mark {MARKER} exactly once, inside a body line")
    unmarked = text.replace(MARKER, " ")
    if lines[0] != FIRST_LINE:
        out.append("the first line is not the review line with [RCIC OF RECORD]")
    if not lines[1].startswith("Re: ") or not lines[1].endswith("[APPLICANT NAME]"):
        out.append("the second line is not a Re line that ends with [APPLICANT NAME]")
    if lines[2] != "Dear Officer,":
        out.append("the third line is not Dear Officer,")
    at = [lines.index(h) if h in lines else -1 for h in HEADINGS]
    if -1 in at or at != sorted(at) or any(lines.count(h) != 1 for h in HEADINGS):
        out.append(f"the headings {', '.join(HEADINGS)} are not each one line, once, in order")
    if lines[-2:] != ["Respectfully submitted,", LAST_LINE]:
        out.append("the letter does not end with Respectfully submitted, and [RCIC OF RECORD]")
    if any(not x.strip() for x in lines):
        out.append("a skeleton line is blank (paragraphs are lines)")
    for ch in FORBIDDEN_CHARS:
        if ch in text:
            out.append(f"the skeleton holds {ch!r} (plain text only, no markup, no less-than sign)")
    rest = PLACEHOLDER_RE.sub("", unmarked)
    if "[" in rest or "]" in rest:
        out.append("a square bracket that is not an [UPPER WORDS] placeholder")
    for rx in CITATION_RES:
        hit = rx.search(PLACEHOLDER_RE.sub(" ", unmarked))
        if hit:
            out.append(f"citation-like text {hit.group(0)!r} (citations are stripped to [CITATION])")
    words = len(re.findall(r"\S+", unmarked))
    if not MIN_WORDS <= words <= MAX_WORDS:
        out.append(f"the skeleton has {words} words ({MIN_WORDS} to {MAX_WORDS:,}, the draft band of draft@1)")
    for rx in UNIVERSAL_RES:
        hit = rx.search(unmarked)
        if hit:
            out.append(f"a conclusion wider than the facts, {hit.group(0)!r} (draft@1 forbids it, so a seed never models it)")
    legal_paras = _section(lines, "Legal framework", "Submissions")
    outside = PLACEHOLDER_RE.sub(lambda m: m.group(0) if m.group(0) in ("[NUMBER]", "[AGE]") else " ",
                                 "\n".join(x for x in lines if x not in legal_paras).replace(MARKER, " "))
    for rules, why in ((WIDER_RES, "a conclusion wider than the facts"),
                       (DURATION_RES, "a computed duration, age or interval (draft@1 states a start date or a stated duration only)"),
                       (POLICY_RES, "law from outside the provisions (draft@1 relies on no policy or program guideline)")):
        for rx in rules:
            hit = rx.search(outside)
            if hit:
                out.append(f"{why}, {hit.group(0)!r}")
    hit = INDEX_RE.search(unmarked)
    if hit:
        out.append(f"{hit.group(0)!r}: the letter names an index of supporting documents, which no case is known to have")
    for x in _section(lines, "Introduction", "Background"):
        for rx in INTRO_RES:
            hit = rx.search(x)
            if hit:
                out.append(f"the Introduction holds {hit.group(0)!r} (only who the applicant is and what the letter asks for, "
                           f"no roadmap and no concern named as a weakness)")
    if "Background" in lines and "Legal framework" in lines:
        bg = _section(lines, "Background", "Legal framework")
        if not bg:
            out.append("the Background section is empty")
    if all(h in lines for h in HEADINGS[2:4]):
        legal = lines[lines.index("Legal framework") + 1:lines.index("Submissions")]
        if not legal:
            out.append("the Legal framework section is empty")
        for i, x in enumerate(legal, 1):
            for sentence in re.split(r"(?<=[.])\s+", x.strip()):
                if "[CITATION]" not in sentence:
                    out.append(f"Legal framework paragraph {i} has a sentence with no [CITATION], {sentence[:60]!r} (every legal "
                               f"point is tied to a citation)")
    for kind in ("terms", "shadow_terms"):
        vals = seed[kind]
        if not (isinstance(vals, list) and vals and all(isinstance(t, str) and t.strip() == t and t and "\n" not in t
                                                        for t in vals) and len({t.casefold() for t in vals}) == len(vals)):
            out.append(f"{kind} must be a non-empty list of distinct one-line terms")
            continue
        for t in vals:
            if not _whole(t, text):
                out.append(f"{kind} {t!r} does not occur whole-word in the skeleton")
            if _whole(t, golden):
                out.append(f"{kind} {t!r} occurs in a golden case, so a leak would be indistinguishable from the facts")
            if PLACEHOLDER_RE.search(t):
                out.append(f"{kind} {t!r} is a placeholder")
            if "zz-test" in t.casefold():
                out.append(f"{kind} {t!r} holds the TEST mark, which every TEST applicant name also holds, so every draft would leak")
            # A part of the term written alone (finding 2026-11-16): a draft copying it passes the leak check and X2.
            listed = {x.casefold() for x in (seed["terms"] if isinstance(seed["terms"], list) else [])
                      + (seed["shadow_terms"] if isinstance(seed["shadow_terms"], list) else []) if isinstance(x, str)}
            for part in _term_parts(t):
                if part.casefold() not in listed and _outside_terms(part, t, text):
                    out.append(f"{kind} {t!r}: its part {part!r} occurs outside the whole term (list it as its own term or "
                               f"reword the skeleton)")
    if isinstance(seed["terms"], list) and isinstance(seed["shadow_terms"], list):
        both = {t.casefold() for t in seed["terms"]} & {t.casefold() for t in seed["shadow_terms"]}
        if both:
            out.append(f"{sorted(both)} are both terms and shadow terms")
        joined = "\n".join(seed["terms"])
        if not terms_status_ok(joined) or term_count(joined) != len(seed["terms"]):
            out.append("the terms do not make a Residual Quasi-Identifiers value the Status formula accepts with Term Count "
                       "equal to the number of terms")
    return out


def lint(folder: str = SEEDS, vocab_path: str = VOCAB) -> list[str]:
    cmap = _read(CITATION_MAP)["citation_map"]
    vt = _read(VISA_TYPES)
    codes = [v["code"] for v in (vt.get("visa_types") if isinstance(vt, dict) else vt)]
    vocab = load_vocab(vocab_path)
    out = [f"vocabulary: {p}" for p in vocab_problems(vocab, cmap, codes)]
    golden = golden_text()
    seeds = load_seeds(folder)
    if not 3 <= len(seeds) <= 40:
        out.append(f"{len(seeds)} seed files, expected 3 to 40")
    codes_seen = set()
    for s in seeds:
        name = s.get("_file", "?") if isinstance(s, dict) else "?"
        for p in seed_problems(s, vocab, golden):
            out.append(f"{name}: {p}")
        if isinstance(s, dict):
            if s.get("code") in codes_seen:
                out.append(f"{name}: code {s.get('code')} repeats")
            codes_seen.add(s.get("code"))
            if name != f"{s.get('code')}.json":
                out.append(f"{name}: the file name is not <code>.json")
    return out


def digest(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read().replace(b"\r\n", b"\n")).hexdigest()


def manifest_rows(folder: str = SEEDS) -> list[dict]:
    return [{"file": n, "sha256": digest(os.path.join(folder, n))} for n in sorted(os.listdir(folder)) if n.endswith(".json")]


# --- the reference ranker (ff13.rank_exemplars steps 4 to 7, test mode) -----------------------------------------------

def rank_key(record_id: str, seed: dict, status: str = "TEST") -> str:
    """The Rank Key formula of the Exemplars table (section 1): seven fields joined by a vertical bar, the tags as Airtable
    renders a multiple select in a formula (comma and space, not verified, the ranker trims either way)."""
    return "|".join([record_id, seed["code"], status, seed["visa_code"], seed["document_code"], str(len(seed["terms"])),
                     ", ".join(seed["tags"])])


def parse_candidates(text: str) -> tuple[list[dict], list[str]]:
    rows, flags = [], []
    for line in text.split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 7 or not re.fullmatch(r"rec[A-Za-z0-9]{14}", parts[0].strip()) \
                or not code_ok(parts[1].strip(), parts[3].strip()) or not re.fullmatch(r"[0-9]{1,9}", parts[5].strip()):
            flags.append("candidate_malformed")
            continue
        rows.append({"id": parts[0].strip(), "code": parts[1].strip(), "status": parts[2].strip(), "visa": parts[3].strip(),
                     "doc": parts[4].strip(), "terms": int(parts[5].strip()),
                     "tags": [t.strip() for t in parts[6].split(",") if t.strip()]})
    return rows, flags


def rank(candidates: str, weak_keys: list[str], visa: str, doc: str, vocab: list[dict], listed: set[str],
         mode: str = "test", strong_keys: list[str] | None = None) -> dict:
    """Steps 4 to 7: parse, keep the eligible rows of the cell, score each by the weak keys its tags address, count its
    conflicts (the supported keys its tags address, since a tag says the letter leaves those keys out), and pick the
    fewest conflicts, then the highest score, then the lower code, then the lower record ID (conflicts first, decided by
    Rizwan 2026-11-19). A score of 0 still selects. With no pick the record ID is NO_PICK, never empty."""
    if visa in EXCLUDED or doc != DOC:
        return {"exemplar_record_id": NO_PICK, "exemplar_code": "", "score": 0, "conflicts": 0, "flags": ["excluded_cell"]}
    rows, flags = parse_candidates(candidates)
    if len(rows) + flags.count("candidate_malformed") >= 100:
        flags.append("candidates_truncated")
    eligible = []
    for r in rows:
        if r["visa"] != visa or r["doc"] != doc:
            flags.append("cross_cell_candidate")
            continue
        if r["terms"] < 1:
            continue
        test_mark = r["status"] != "Active" or r["code"].startswith("ZZ-TEST-") or r["id"] in listed
        if mode == "production":
            if test_mark:
                return {"exemplar_record_id": NO_PICK, "exemplar_code": "", "score": 0, "conflicts": 0, "flags": flags + ["test_seed_in_production"]}
            eligible.append(r)
        elif r["status"] == "TEST" and r["code"].startswith("ZZ-TEST-") and r["id"] in listed:
            eligible.append(r)
    addresses = {}
    for v in vocab:
        if v["visa_code"] == visa and (mode == "test" or v["review_state"] == "reviewed"):
            addresses.setdefault(v["tag"], set()).update(v["addresses"])
    weak = set(weak_keys)
    strong = set(strong_keys or ())
    best = None
    for r in eligible:
        covered, conflicts = set(), set()
        for t in r["tags"]:
            if t not in addresses:
                flags.append("unknown_tag")
                continue
            covered |= addresses[t] & weak
            conflicts |= addresses[t] & strong
        key = (len(conflicts), -len(covered), r["code"], r["id"])
        if best is None or key < best[0]:
            best = (key, r, len(covered), len(conflicts))
    if best is None:
        return {"exemplar_record_id": NO_PICK, "exemplar_code": "", "score": 0, "conflicts": 0, "flags": sorted(set(flags))}
    return {"exemplar_record_id": best[1]["id"], "exemplar_code": best[1]["code"], "score": best[2], "conflicts": best[3],
            "flags": sorted(set(flags)) + (["test_mode"] if mode == "test" else [])}


def fake_record_id(i: int) -> str:
    """Harness-only record IDs (never in the committed ref/exemplar_test_seeds.json): recX32ZZTEST + 5 digits."""
    return f"recX32ZZTEST{i:05d}"


def overlay(seeds: list[dict], vocab: list[dict]) -> dict:
    """golden case -> the seed the reference ranker picks from the case's expected support labels, or null where nothing
    is selected (no letter, no grounding, an excluded cell or no seed in the cell)."""
    ids = {s["code"]: fake_record_id(i) for i, s in enumerate(sorted(seeds, key=lambda s: s["code"]), 1)}
    lines = "\n".join(rank_key(ids[s["code"]], s) for s in seeds)
    out = {}
    for name in sorted(os.listdir(GOLDEN)):
        if not name.endswith(".json"):
            continue
        c = _read(os.path.join(GOLDEN, name))
        e = c.get("expected") or {}
        g = e.get("grounding") or {}
        visa = c["inputs"].get("visa_code")
        if g.get("allowed") != "true" or e.get("outcome") != "letter" or c.get("kind") == "control":
            out[c["id"]] = {"pick": None, "why": "no letter expected (refused grounding, NO DRAFT or a control)"}
            continue
        weak = sorted(k for k, v in (e.get("support") or {}).items() if v in ("not_supported", "partly_supported"))
        strong = sorted(k for k, v in (e.get("support") or {}).items() if v == "supported")
        r = rank(lines, weak, visa, c["inputs"].get("document_code"), vocab, set(ids.values()), strong_keys=strong)
        out[c["id"]] = {"pick": r["exemplar_code"] or None, "score": r["score"], "conflicts": r["conflicts"],
                        "weak_keys": weak, "supported_keys": strong,
                        "why": "excluded cell" if "excluded_cell" in r["flags"] else
                               ("no seed in the cell" if not r["exemplar_code"] else "reference ranker")}
    return {"source": "X-32 overlay v1: the seed scripts/x32_seeds.py rank picks for each golden v1 case from its expected "
                      "support labels, test mode, every vocabulary row counted. Generated, never hand edited. The golden set is "
                      "not edited, so its digest pin holds.",
            "seed_record_ids": ids, "cases": out}


def airtable_rows(seeds: list[dict], firm: str) -> list[dict]:
    """The Exemplars rows of the TEST seeds, by field name, for the Airtable MCP create (go-ahead 7). Claude never fills
    RCIC Reviewer, RCIC Reviewed At, Review Attestation, Consent Recorded or Consent Reference."""
    return [{"fields": {"Exemplar Code": s["code"], "Document Code": s["document_code"], "Visa Code": s["visa_code"],
                        "Firm": firm, "Fact Pattern Tags": list(s["tags"]), "Skeleton": skeleton(s),
                        "Residual Quasi-Identifiers": "\n".join(s["terms"]), "Source Type": "Synthetic TEST",
                        "Source Note": "Synthetic X-32 TEST seed written by Claude, no client behind it."}}
            for s in sorted(seeds, key=lambda s: s["code"])]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=("lint", "check", "manifest", "overlay", "rows"))
    args = ap.parse_args(argv)
    try:
        problems = lint()
        if args.cmd in ("lint", "check"):
            if args.cmd == "check" and not problems:
                want = _read(SEED_MANIFEST).get("seeds")
                if want != manifest_rows():
                    problems.append("eval/x32/seeds/manifest.json does not match the seed files (rewrite it in a reviewed commit)")
                if _read(OVERLAY) != overlay(load_seeds(), load_vocab()):
                    problems.append("eval/x32/overlay/v1.json does not match the reference ranker (run overlay)")
            for p in problems:
                print(f"x32_seeds: {p}", file=sys.stderr)
            if problems:
                return 1
            print(f"x32 seeds: {len(load_seeds())} seed(s) clean" + (", digests and overlay match" if args.cmd == "check" else ""))
            return 0
        if problems:
            for p in problems:
                print(f"x32_seeds: {p}", file=sys.stderr)
            return 1
        if args.cmd == "manifest":
            with open(SEED_MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
                json.dump({"source": "X-32 seed set v1 digests (SHA-256 of each file with LF line ends). A seed changes only "
                                     "in a reviewed commit that rewrites this file.", "seeds": manifest_rows()}, fh, indent=2)
                fh.write("\n")
        elif args.cmd == "overlay":
            data = overlay(load_seeds(), load_vocab())   # computed first, so a failure leaves the file as it was
            with open(OVERLAY, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        else:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import audit_blueprints as ab  # noqa: E402
            print(json.dumps(airtable_rows(load_seeds(), ab.load_x32(ab.DEFAULT_X32).firm_code), indent=2, ensure_ascii=False))
    except (OSError, ValueError, KeyError, SeedError) as exc:
        print(f"x32_seeds: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
