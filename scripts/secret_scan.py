#!/usr/bin/env python3
"""Shared secret scanner for Immi-OS (audit check D and the pre-commit hook).

Findings are dicts {"pattern_type": str, "location": str}. A finding never
carries the matched value or any part of it. Locations are JSON paths
("$.flow[0].mapper.headers[0].value") for parsed objects and "source:line"
for text. JSON keys that look secret-shaped are redacted in paths.

Library use:
    from secret_scan import scan_obj, scan_text
    findings = scan_obj(blueprint)          # in-memory, before writing to disk

CLI:
    python scripts/secret_scan.py --staged  # scan staged blobs (git show :path)
    python scripts/secret_scan.py PATH...   # scan files or directories

Pinned allowlist (audit/secret_allowlist.json): a Make webhook URL written as a
literal in a Bland call module (Send a Call or Create a Call) is an address, not a credential, once the hook
it points at passes fetch-back (CLAUDE.md check D). Only pattern_type
make_webhook_url, only in mapper.webhook of a bland:sendACall or bland:createACall module
(X-46 moves the calls to Create a Call) that sits on the flow itself (flow, routes, error routes, never nested inside another module's mapper),
only when that field holds exactly one hook token and its SHA-256 equals the entry's
token_sha256, one finding per entry. The URL is pinned by value, so a different URL, a
second URL or a URL in another module blocks.

The Logger hook (Option C, decided by Rizwan 2026-10-29): every error handler calls one shared Logger scenario
through a Make HTTP module, so the Logger hook URL sits in many modules of many scenarios. The file's logger_hook
object pins it by token_sha256 like the entries above. It is the dormant fallback for an account without team variables
(the callers read the URL from var.team.IMMIOS_LOGGER_URL), so it stays null until Rizwan says yes. A make_webhook_url
finding is allowed only at exactly <module path>.mapper.url of a module on the flow (never a module-shaped object
nested in a mapper) that is a Logger call: http:MakeRequest, method POST, an API key keychain (authenticationType
apiKeyConnection or apiKey) and no routes. The field must be the bare hook URL, https, one token that hashes to the pin,
nothing before or after it, no query string, fragment, path or mapping. Any other field, a query string of another URL
or another module blocks (R6). The allowance is active only while audit/webhooks.json registers that hook for the
Logger scenario with protection api_key (the hook needs x-make-apikey, so the URL alone cannot start it). Otherwise it
is inactive and the URL blocks like any other. scan_obj itself never consults the allowlist. Callers that handle
blueprint files (make_pull, make_push, the staged scan of blueprints/) split the
findings with split_findings. Every other file is scanned without any allowance.

Exit codes: 0 clean, 1 findings, 2 usage or git error.
Standard library only.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Literal credential patterns. Order matters: the first pattern that claims a
# span wins, so specific prefixes come before generic ones.
# ---------------------------------------------------------------------------

_TEXT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("stripe_secret_key", re.compile(r"(?<![A-Za-z0-9])sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("stripe_restricted_key", re.compile(r"(?<![A-Za-z0-9])rk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("stripe_webhook_secret", re.compile(r"(?<![A-Za-z0-9])whsec_[A-Za-z0-9+/=]{16,}")),
    ("anthropic_api_key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}")),
    (
        "openai_api_key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{20,}"),
    ),
    ("airtable_pat", re.compile(r"(?<![A-Za-z0-9])pat[A-Za-z0-9]{14}\.[a-fA-F0-9]{64}(?![a-fA-F0-9])")),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
    ("supabase_secret_key", re.compile(r"(?<![A-Za-z0-9])sb_secret_[A-Za-z0-9_-]{16,}")),
    # A Postgres connection URI with the password inline, the form the Supabase Connect dialog hands out (X-17.1).
    # The loader keeps the URL and the password apart, so a URI with user:password@ is never legitimate in a file.
    # The scheme may carry a +driver suffix and JSON-escaped slashes. The password may hold @, $, *, % and brackets
    # (the class backtracks to the last @ of the authority). Only a whole-password placeholder followed by @ is clean:
    # [YOUR-PASSWORD], [password], <anything>, $VAR or ${VAR}, {{...}}, ****, %s and a few placeholder words.
    # A real password typed inside the dialog's brackets ([pw]) is flagged (review 2026-11-02).
    (
        "db_uri_with_password",
        re.compile(
            r"(?<![A-Za-z0-9+.-])(?i:postgres(?:ql)?)(?:\+[A-Za-z0-9_]+)?:(?:\\?/){2}[^\s:/?#@'\"<>\\]*:"
            r"(?!(?:(?i:\[your-password\]|\[password\]|your-password|password|passwd|example|placeholder|redacted"
            r"|changeme)|<[^>@\s]*>|\$\{?[A-Z_][A-Z0-9_]*\}?|\{\{[^@]*\}\}|\*+|%s)@)"
            r"[^\s/?#'\"<>\\]{3,}@"
        ),
    ),
    # A Make custom webhook URL: the token after the host is a bearer secret, anyone
    # holding the URL can start the scenario. hook.make.com, hook.<zone>.make.com,
    # the make.celonis.com zones and the legacy integromat.com host.
    # The host is matched without regard to case, a slash may be JSON-escaped (\/),
    # and the token may sit inside an IML string ({{"token"}}) after the host.
    (
        "make_webhook_url",
        re.compile(
            r"(?<![A-Za-z0-9-])(?i:hook\.(?:[a-z0-9]{2,6}\.)?(?:make\.com|make\.celonis\.com|integromat\.com))"
            r"\\?/(?:\{\{\s*[\"']?)?(?P<t>[A-Za-z0-9_-]{16,})"
        ),
    ),
    (
        "slack_webhook_url",
        re.compile(r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9]{6,}/[A-Za-z0-9]{6,}/[A-Za-z0-9_-]{8,}"),
    ),
]

# Plain-text rules (scan_text only). A credential-shaped value: 8+ characters
# of token alphabet, ending at whitespace, a quote, a separator or end of line.
_CRED_VALUE = r"(?P<v>[A-Za-z0-9_\-./+=~:]{8,})(?=$|[\s'\"#;,)\]}>])"
# KEY=value or KEY: value for secret-named upper-case keys (env files, docs,
# shell snippets). MAKE_API_TOKEN, AIRTABLE_PAT, STRIPE_SECRET_KEY, DB_PASSWORD.
_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?:export\s+)?(?P<k>[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|_KEY|_PAT))"
    r"['\"]?\s*[:=]\s*['\"]?" + _CRED_VALUE
)
# Authorization header written as text: curl -H, HTTP dumps, JSON in docs.
_AUTH_TEXT = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:proxy-)?authorization['\"]?\s*[:=]\s*f?['\"]?\s*(?:(?:bearer|token|basic|digest|bot)\s+)?"
    + _CRED_VALUE
)
_BEARER_TEXT = re.compile(r"(?i)(?<![A-Za-z0-9_-])bearer\s+(?P<v>[A-Za-z0-9_\-.+/=~]{16,})(?=$|[\s'\"#;,)\]}>])")
_PLACEHOLDER_WORDS = ("your", "example", "placeholder", "changeme", "replace", "redacted", "xxxx", "dummy", "sample")

# Header names whose value is a credential. Values must be pure Make mappings.
_AUTH_HEADERS = {"authorization", "proxy-authorization"}
# x-make-apikey is the header a Make webhook API key travels in. The Logger callers authenticate through a keychain
# connection, so a literal value in that header is a key written into the blueprint.
_KEY_HEADERS = {"x-api-key", "api-key", "apikey", "x-auth-token", "x-make-apikey"}
# Query, body or form parameter names (name/value pairs) whose value is a credential.
_SECRET_PARAMS = {
    "api_key", "apikey", "api-key", "access_token", "token", "auth_token", "key", "secret",
    "client_secret", "password", "passwd", "private_key", "secret_key", "signing_secret",
}
# Plain mapper keys whose value is a credential (Make HTTP basic auth and similar).
_SECRET_FIELDS = {
    "authpass", "password", "passwd", "client_secret", "clientsecret", "api_key", "apikey",
    "access_token", "private_key", "secret_key", "signing_secret", "secret",
}
_HEADER_NAME_KEYS = ("name", "key", "header", "headerName")
_URL = re.compile(r"https?://[^\s\"'<>]+")

# Auth scheme words that may precede a mapped credential ("Bearer {{1.token}}").
_SCHEME_WORDS = {"bearer", "basic", "token", "digest", "bot", "apikey", "key"}

# Make IML hash functions: name(text; [encoding]; [key]; [key encoding]).
# A non-empty key argument turns the hash into an HMAC.
_SHA_FUNCS = {"sha1", "sha256", "sha512"}
_SHA_KEY_INDEX = 2
_ENCODING_WORDS = {"hex", "base64", "text", "binary", "latin1", "utf8", "utf-8", "ascii"}
_IML_KEYWORDS = {"true", "false", "null", "emptystring", "emptyarray", "now", "timestamp", "random", "pi", "space", "tab", "nbsp"}
# A Make IML reference starts with a module id or a system namespace, then
# dotted segments (backticks quote names with spaces) and [] or [n] indexes.
_IML_REFERENCE = re.compile(r"^(?:\d+|var|error|item)(?:\.(?:`[^`]*`|[A-Za-z0-9_$@-]+)|\[\d*\])+$", re.IGNORECASE)
_IML_TOKEN = re.compile(r"(?:`[^`]*`|[^\s+*/&|<>=!,`])+")
_FUNC_NAME = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\($")

_SAFE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOTENV_ALLOWED = {".env.example", ".env.sample", ".env.template"}
_TABULAR_EXTS = {".csv", ".tsv", ".xlsx", ".xls"}


def _finding(pattern_type: str, location: str) -> dict:
    return {"pattern_type": pattern_type, "location": location}


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out = []
    for f in findings:
        k = (f["pattern_type"], f["location"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _is_placeholder_token(ptype: str, m: re.Match[str]) -> bool:
    """A webhook token that is one repeated character (xxxxxxxx) is a placeholder."""
    if ptype != "make_webhook_url":
        return False
    return len(set(m.group("t"))) < 2


def _literal_pattern_types_raw(s: str) -> list[str]:
    claimed: list[tuple[int, int]] = []
    types: list[str] = []
    for ptype, rx in _TEXT_PATTERNS:
        for m in rx.finditer(s):
            a, b = m.span()
            if any(a < cb and ca < b for ca, cb in claimed):
                continue
            if _is_placeholder_token(ptype, m):
                continue
            claimed.append((a, b))
            types.append(ptype)
    return types


def _literal_pattern_types(s: str) -> list[str]:
    """Pattern types of literal credentials in s. Never returns spans. A
    percent-encoded copy is scanned too, so https%3A%2F%2Fhook... is found."""
    types = _literal_pattern_types_raw(s)
    if "%" in s:
        decoded = urllib.parse.unquote(s)
        if decoded != s:
            for t in _literal_pattern_types_raw(decoded):
                if t not in types:
                    types.append(t)
    return types


def _looks_secret(s: str) -> bool:
    return bool(_literal_pattern_types(s))


# ---------------------------------------------------------------------------
# Make IML parsing (just enough for mappings: {{...}}, strings, calls, args).
# ---------------------------------------------------------------------------


def _iml_segments(s: str) -> tuple[list[str], str]:
    """Split s into ({{...}} expression bodies, text outside them)."""
    exprs: list[str] = []
    outside: list[str] = []
    i, n = 0, len(s)
    while i < n:
        start = s.find("{{", i)
        if start < 0:
            outside.append(s[i:])
            break
        outside.append(s[i:start])
        j = start + 2
        in_str = False
        while j < n:
            c = s[j]
            if in_str:
                if c == '"':
                    if j + 1 < n and s[j + 1] == '"':
                        j += 2
                        continue
                    in_str = False
            elif c == '"':
                in_str = True
            elif s.startswith("}}", j):
                break
            j += 1
        if j >= n:  # unterminated: treat the rest as plain text
            outside.append(s[start:])
            break
        exprs.append(s[start + 2 : j])
        i = j + 2
    return exprs, "".join(outside)


def _quoted_literals(expr: str) -> list[str]:
    """Contents of double-quoted string literals in an IML expression."""
    out: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        if expr[i] == '"':
            j = i + 1
            buf = []
            while j < n:
                if expr[j] == '"':
                    if j + 1 < n and expr[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    break
                buf.append(expr[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return out


def _split_args(expr: str, open_idx: int) -> list[str] | None:
    """Split the arguments of the call whose '(' is at open_idx."""
    args: list[str] = []
    depth = 0
    in_str = False
    cur: list[str] = []
    i, n = open_idx + 1, len(expr)
    while i < n:
        c = expr[i]
        if in_str:
            cur.append(c)
            if c == '"':
                if i + 1 < n and expr[i + 1] == '"':
                    cur.append('"')
                    i += 2
                    continue
                in_str = False
        elif c == '"':
            in_str = True
            cur.append(c)
        elif c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            if depth == 0:
                args.append("".join(cur))
                return args
            depth -= 1
            cur.append(c)
        elif c == ";" and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return None  # unbalanced


def _function_calls(expr: str) -> list[tuple[str, list[str]]]:
    """(lowercased name, args) for every call in expr, outside strings."""
    calls = []
    in_str = False
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if in_str:
            if c == '"':
                if i + 1 < n and expr[i + 1] == '"':
                    i += 2
                    continue
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "(":
            m = _FUNC_NAME.search(expr[: i + 1])
            if m:
                args = _split_args(expr, i)
                if args is not None:
                    calls.append((m.group(1).lower(), args))
        i += 1
    return calls


def _bare_is_literal(text: str, allow: set[str] = frozenset(), allow_numbers: bool = False) -> bool:
    """True if unquoted IML text holds a hardcoded value.

    The text is split into operands on whitespace and operators. Every
    operand must be a reference (1.key, var.input.x, error.message,
    5.`Signing Key`), a keyword, or an allowed word. "Sup3r.S3cret" and
    "my secret.key" are literals because their first segment is not a
    module id or namespace.
    """
    for tok in _IML_TOKEN.findall(text):
        if re.fullmatch(r"[-%^]+", tok):
            continue
        low = tok.lower()
        if low in _IML_KEYWORDS or low in allow or _IML_REFERENCE.match(tok):
            continue
        if allow_numbers and re.fullmatch(r"-?\d+(?:\.\d+)?", tok):
            continue
        return True
    return False


def _arg_is_literal(arg: str, allow: set[str] = frozenset(), allow_numbers: bool = False) -> bool:
    """True if an IML function argument carries a hardcoded value.

    Quoted text counts if it has any letter or digit. A nested call is
    literal if any of its own arguments is (recursively), so trim(secret)
    and ifempty(2.key; "fallback") are caught. Encoding words and small
    numbers are allowed inside nested calls (toBinary(2.key; base64)).
    """
    a = arg.strip()
    if not a:
        return False
    if any(re.search(r"[A-Za-z0-9]", q) for q in _quoted_literals(a)):
        return True
    calls = _function_calls(a)
    if calls:
        for _name, args in calls:
            for sub in args:
                if "(" in sub:
                    continue  # its own call is in calls too
                if _arg_is_literal(sub, allow | _ENCODING_WORDS, True):
                    return True
        # Operands outside the calls (for example 1.a + trim(2.b)).
        outside = re.sub(r'"(?:[^"]|"")*"', " ", a)
        outside = re.sub(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", "(", outside)
        depth, buf = 0, []
        for c in outside:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0:
                buf.append(c)
        return _bare_is_literal("".join(buf), allow, allow_numbers)
    if '"' in a:
        return False  # only empty or punctuation-only quoted text
    return _bare_is_literal(a, allow, allow_numbers)


def _hash_key_literal(s: str) -> bool:
    """True if any {{...}} in s calls a hash/HMAC function with a literal key."""
    exprs, _ = _iml_segments(s)
    for expr in exprs:
        for name, args in _function_calls(expr):
            if name in _SHA_FUNCS:
                if len(args) > _SHA_KEY_INDEX and _arg_is_literal(args[_SHA_KEY_INDEX]):
                    return True
            elif "hmac" in name:
                for arg in args[1:]:
                    if arg.strip().strip('"').lower() in _ENCODING_WORDS:
                        continue
                    if _arg_is_literal(arg):
                        return True
    return False


def _strip_schemes(text: str) -> str:
    return " ".join(w for w in text.split() if w.lower() not in _SCHEME_WORDS)


def _header_value_is_literal(value: str) -> bool:
    """True if a credential value is anything but a pure mapping.

    "{{1.token}}", "Bearer {{1.token}}" and "{{ifempty(1.a; 2.b)}}" are
    mappings. "Bearer abc", "{{ifempty(1.token; \"abc\")}}",
    "{{ifempty(1.token; abc)}}", "{{abc}}" and "abc" carry a literal.
    """
    exprs, outside = _iml_segments(value)
    if _strip_schemes(outside).strip():
        return True
    for expr in exprs:
        for q in _quoted_literals(expr):
            if re.search(r"[A-Za-z0-9]", _strip_schemes(q)):
                return True
        calls = _function_calls(expr)
        if not calls:
            if _bare_is_literal(expr):
                return True  # {{abc}}: raw text inside braces
            continue
        for _name, args in calls:
            for arg in args:
                if "(" not in arg and '"' not in arg and _bare_is_literal(arg, _ENCODING_WORDS, True):
                    return True
    return False


def _url_credential(url: str) -> bool:
    """True if a URL carries a literal password in its userinfo or a literal
    value in a secret-named query parameter. Mapped values are fine."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    netloc = parts.netloc
    if "@" in netloc:
        userinfo = netloc.rsplit("@", 1)[0]
        if ":" in userinfo:
            password = userinfo.split(":", 1)[1]
            if password and _header_value_is_literal(urllib.parse.unquote(password)):
                return True
    for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if name.strip().lower() in _SECRET_PARAMS and value and _header_value_is_literal(value):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _path_key(path: str, key: object) -> str:
    k = str(key)
    if _looks_secret(k) or len(k) > 128:
        return f'{path}["<redacted>"]'
    if _SAFE_KEY.match(k):
        return f"{path}.{k}"
    return f"{path}[{json.dumps(k)}]"


def _header_kind(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    n = name.strip().lower()
    if n in _AUTH_HEADERS:
        return "authorization_header_literal"
    if n in _KEY_HEADERS:
        return "api_key_header_literal"
    return None


def _pair_kind(name: object) -> str | None:
    """Kind for a {name, value} pair: credential header or secret-named parameter."""
    kind = _header_kind(name)
    if kind:
        return kind
    if isinstance(name, str) and name.strip().lower() in _SECRET_PARAMS:
        return "credential_param_literal"
    return None


def _scan_string(s: str, location: str) -> list[dict]:
    out = [_finding(t, location) for t in _literal_pattern_types(s)]
    if "{{" in s and _hash_key_literal(s):
        out.append(_finding("hash_key_literal", location))
    return out


def _is_placeholder(v: str) -> bool:
    """Text-mode values that are not credentials: no digit, no letter, or a
    placeholder word (your-token-here, example, changeme)."""
    low = v.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    return not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def _scan_text_line(line: str, location: str) -> list[dict]:
    out = _scan_string(line, location)
    for ptype, rx in (("secret_assignment_literal", _ASSIGNMENT),
                      ("authorization_header_literal", _AUTH_TEXT),
                      ("authorization_header_literal", _BEARER_TEXT)):
        if any(not _is_placeholder(m.group("v")) for m in rx.finditer(line)):
            out.append(_finding(ptype, location))
    return out


def scan_obj(obj: object, path: str = "$") -> list[dict]:
    """Walk parsed JSON and return findings with JSON-path locations."""
    findings: list[dict] = []
    stack: list[tuple[object, str]] = [(obj, path)]
    while stack:
        node, p = stack.pop()
        if isinstance(node, dict):
            # Header or parameter as {name: "Authorization", value: "..."}
            # (Make HTTP headers, query string, form fields).
            for nk in _HEADER_NAME_KEYS:
                kind = _pair_kind(node.get(nk))
                if kind and isinstance(node.get("value"), str):
                    if _header_value_is_literal(node["value"]):
                        findings.append(_finding(kind, _path_key(p, "value")))
                    break
            for k, v in node.items():
                kp = _path_key(p, k)
                if isinstance(k, str):
                    for t in _literal_pattern_types(k):
                        findings.append(_finding(t, kp))
                # Header as a plain object key: {"Authorization": "..."}.
                kind = _header_kind(k)
                if kind and isinstance(v, str) and _header_value_is_literal(v):
                    findings.append(_finding(kind, kp))
                # Credential field as a plain key: {"authPass": "..."}.
                elif isinstance(k, str) and k.strip().lower() in _SECRET_FIELDS \
                        and isinstance(v, str) and _header_value_is_literal(v):
                    findings.append(_finding("credential_field_literal", kp))
                stack.append((v, kp))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((v, f"{p}[{i}]"))
        elif isinstance(node, str):
            findings.extend(_scan_string(node, p))
            if any(_url_credential(u) for u in _URL.findall(node)):
                findings.append(_finding("url_credential_literal", p))
    findings.sort(key=lambda f: (f["location"], f["pattern_type"]))
    return _dedupe(findings)


def scan_text(text: str, source: str = "<text>") -> list[dict]:
    """Scan plain text line by line. Locations are "source:line"."""
    findings: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(_scan_text_line(line, f"{source}:{lineno}"))
    return _dedupe(findings)


_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".zip", ".docx", ".xlsx",
    ".pptx", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mov", ".mp3", ".wav",
}


def _decode_text(data: bytes) -> str | None:
    """Decode UTF-8, or UTF-16/32 by BOM or NUL pattern. None if binary."""
    for bom, enc in ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
                     (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):
            return data[len(bom):].decode(enc, errors="replace")
    head = data[:8192]
    if b"\x00" not in head:
        return data.decode("utf-8", errors="replace")
    # BOM-less UTF-16 (PowerShell and some editors): NULs in one byte lane only.
    even, odd = head[0::2], head[1::2]
    if len(head) >= 4:
        if odd.count(0) >= 0.6 * len(odd) and even.count(0) == 0:
            return data.decode("utf-16-le", errors="replace")
        if even.count(0) >= 0.6 * len(even) and odd.count(0) == 0:
            return data.decode("utf-16-be", errors="replace")
    return None


def scan_bytes(data: bytes, name: str) -> list[dict]:
    """Scan file content. JSON files get structural checks, others text checks.

    UTF-16 and UTF-32 text is decoded before scanning. Known binary types
    (images, PDF, Office, fonts, media) are skipped. Any other file that
    cannot be decoded is reported as unscannable_binary, so the hook fails
    closed on it.
    """
    text = _decode_text(data)
    if text is None:
        if os.path.splitext(name.lower())[1] in _BINARY_EXTS:
            return []
        return [_finding("unscannable_binary", name)]
    if text.startswith("﻿"):
        text = text[1:]
    if name.lower().endswith(".json"):
        try:
            obj = json.loads(text)
        except ValueError:
            pass
        else:
            return [
                _finding(f["pattern_type"], f"{name}:{f['location']}") for f in scan_obj(obj)
            ]
    return scan_text(text, name)


def scan_paths(paths: list[str]) -> list[dict]:
    """Scan files, walking directories (skipping .git, __pycache__ and node_modules, which is gitignored
    third-party code: pg's README holds example connection URIs with passwords)."""
    findings: list[dict] = []
    for root in paths:
        if os.path.isdir(root):
            for d, dirs, files in os.walk(root):
                dirs[:] = sorted(x for x in dirs if x not in (".git", "__pycache__", "node_modules"))
                for f in sorted(files):
                    findings.extend(_scan_file(os.path.join(d, f)))
        else:
            findings.extend(_scan_file(root))
    return findings


def _scan_file(path: str) -> list[dict]:
    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, path.replace(os.sep, "/"))


# ---------------------------------------------------------------------------
# Pinned secret allowlist (audit/secret_allowlist.json)
# ---------------------------------------------------------------------------

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SECRET_ALLOWLIST = os.path.join(ROOT, "audit", "secret_allowlist.json")
SECRET_ALLOWLIST_REPO_PATH = "audit/secret_allowlist.json"
# The only pattern type an entry may excuse, and where it may sit.
ALLOWLISTABLE_PATTERN_TYPES = ("make_webhook_url",)
# The Bland call modules whose mapper.webhook may hold a pinned URL. Send a Call is deprecated in Make and cannot
# dial an agent, so X-46 moves the calls to Create a Call. A tuple, so callers test membership.
ALLOWLISTABLE_MODULE_TYPE = ("bland:sendACall", "bland:createACall")
ALLOWLISTABLE_FIELD_SUFFIX = ".mapper.webhook"
_BLUEPRINT_REPO_PATH = re.compile(r"blueprints/[^/]+__(\d+)\.json")
# A Bland call webhook field exactly where a module sits: flow[i], routes[j].flow[k] and onerror[k] steps
# only. A module-shaped dict nested in another module's mapper (mapper.body.mapper.webhook) does not match.
_MODULE_WEBHOOK_PATH = re.compile(r"\$\.flow\[\d+\](?:\.(?:routes\[\d+\]\.flow|onerror)\[\d+\])*\.mapper\.webhook")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
MANIFEST_REPO_PATH = "blueprints/manifest.json"


def token_digest(token: str) -> str:
    """SHA-256 of a hook token. The token has about 190 random bits, so the digest reveals nothing
    and can sit in the repo, where the token itself must not."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
_PATH_TOKEN = re.compile(r'\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]|\[("(?:[^"\\]|\\.)*")\]')


class SecretAllowlistError(ValueError):
    """The allowlist file is unreadable or breaks its own rules. Never carries a value."""


WEBHOOKS_REPO_PATH = "audit/webhooks.json"
DEFAULT_WEBHOOKS = os.path.join(ROOT, "audit", "webhooks.json")
LOGGER_PROTECTION = "api_key"
LOGGER_KIND = "logger_hook"
PINNED_KIND = "pinned"


@dataclass(frozen=True)
class LoggerAllowance:
    """The Logger hook pinned in audit/secret_allowlist.json (logger_hook). active is True only while audit/webhooks.json
    registers hook_id for scenario_id with protection api_key. inactive_reason says why not, never a value."""
    scenario_id: str
    hook_id: int
    token_sha256: str
    reason: str
    active: bool = False
    inactive_reason: str | None = None


class SecretAllowlist(list):
    """The pinned entries (a plain list of dicts, as before) plus the Logger hook allowance in .logger. Iterating it yields
    the pinned entries only, so code that reads entries keeps working. It is truthy when it holds entries or a Logger,
    so `allowlist or []` keeps the Logger."""

    def __init__(self, entries=(), logger: LoggerAllowance | None = None):
        super().__init__(entries)
        self.logger = logger

    def __bool__(self) -> bool:
        return len(self) > 0 or self.logger is not None


def logger_registration(logger: LoggerAllowance, webhooks_data: object) -> LoggerAllowance:
    """The allowance with active set from the webhook registry data (the parsed audit/webhooks.json). Active only when the
    registry lists the Logger scenario with the same hook_id and protection api_key. A missing or unreadable registry leaves
    it inactive, so the URL blocks."""
    def off(why: str) -> LoggerAllowance:
        return dataclasses.replace(logger, active=False, inactive_reason=why)
    rows = webhooks_data.get("scenarios") if isinstance(webhooks_data, dict) else None
    if not isinstance(rows, list):
        return off("the webhook registry (audit/webhooks.json) is missing or has no scenarios list")
    top = webhooks_data.get("logger")
    rows = rows + ([top] if isinstance(top, dict) else [])
    entry = next((r for r in rows if isinstance(r, dict) and not isinstance(r.get("scenario_id"), bool)
                  and r.get("scenario_id") is not None and str(r.get("scenario_id")).strip() == logger.scenario_id), None)
    if entry is None:
        return off(f"audit/webhooks.json does not list the Logger scenario {logger.scenario_id}")
    hid = entry.get("hook_id")
    if isinstance(hid, bool) or hid != logger.hook_id:
        return off(f"audit/webhooks.json lists hook {hid} for the Logger scenario {logger.scenario_id}, the pin names hook {logger.hook_id}")
    if entry.get("protection") != LOGGER_PROTECTION:
        return off(f"audit/webhooks.json does not protect the Logger hook {logger.hook_id} with {LOGGER_PROTECTION} "
                   f"(an x-make-apikey key), so its URL is a credential")
    return dataclasses.replace(logger, active=True, inactive_reason=None)


LOGGER_CALLER = "make_http"


def registered_loggers(webhooks_data: object) -> list[dict]:
    """Every Logger registration in the parsed audit/webhooks.json, as {scenario_id, hook_id, protection, url_variable,
    connection_id}: a scenarios entry with caller make_http, and the top-level logger object once its scenario_id and hook_id
    are set (it sits there while they are null and moves into scenarios afterwards). Distinct by (scenario_id, hook_id), in
    file order. url_variable is the custom variable the callers read the hook URL from (var.team.X, no braces), connection_id
    the HTTP API key connection that sends the key. Either may be None."""
    if not isinstance(webhooks_data, dict):
        return []
    rows = webhooks_data.get("scenarios") if isinstance(webhooks_data.get("scenarios"), list) else []
    cands = [r for r in rows if isinstance(r, dict) and r.get("caller") == LOGGER_CALLER]
    top = webhooks_data.get("logger")
    if isinstance(top, dict) and top.get("scenario_id") is not None:
        cands.append(top)
    out: list[dict] = []
    for r in cands:
        sid, hid = r.get("scenario_id"), r.get("hook_id")
        if isinstance(sid, bool) or not isinstance(sid, (int, str)) or not str(sid).strip().isdigit():
            continue
        if isinstance(hid, bool) or not isinstance(hid, int):
            continue
        if any(o["scenario_id"] == str(sid).strip() and o["hook_id"] == hid for o in out):
            continue
        var, conn = r.get("url_variable"), r.get("connection_id")
        out.append({"scenario_id": str(sid).strip(), "hook_id": hid, "protection": r.get("protection"),
                    "url_variable": var.strip() if isinstance(var, str) and var.strip() else None,
                    "connection_id": conn if isinstance(conn, int) and not isinstance(conn, bool) and conn > 0 else None})
    return out


def _parse_logger_hook(raw: object, name: str) -> LoggerAllowance | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SecretAllowlistError(f"{name}: logger_hook must be null or an object")
    sid, hid = raw.get("scenario_id"), raw.get("hook_id")
    if isinstance(sid, bool) or not isinstance(sid, (int, str)) or not str(sid).strip().isdigit():
        raise SecretAllowlistError(f"{name}: logger_hook.scenario_id must be the Logger scenario ID (digits)")
    if isinstance(hid, bool) or not isinstance(hid, int) or hid <= 0:
        raise SecretAllowlistError(f"{name}: logger_hook.hook_id must be the Logger hook ID (a positive integer)")
    digest = raw.get("token_sha256")
    if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
        raise SecretAllowlistError(f"{name}: logger_hook.token_sha256 must be the 64 hex characters (lower case) of the SHA-256 "
                                   f"of the Logger hook token")
    reason = raw.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
        raise SecretAllowlistError(f"{name}: logger_hook needs a real reason (a sentence)")
    extra = sorted(set(raw) - {"scenario_id", "hook_id", "token_sha256", "reason"})
    if extra:
        raise SecretAllowlistError(f"{name}: logger_hook has unknown keys {extra}")
    return LoggerAllowance(str(sid).strip(), hid, digest, reason.strip(), False, "the webhook registry was not read")


def parse_secret_allowlist(data: object, name: str = "secret_allowlist.json",
                           webhooks_data: object = None) -> SecretAllowlist:
    """Validated pinned entries, plus the Logger hook (logger_hook, null until the Logger is deployed). webhooks_data is the
    parsed audit/webhooks.json, which decides whether the Logger allowance is active. See parse_pinned_entries."""
    entries = parse_pinned_entries(data, name)
    logger = _parse_logger_hook(data.get("logger_hook") if isinstance(data, dict) else None, name)
    if logger is not None:
        logger = logger_registration(logger, webhooks_data)
        if any(e["requires_fetch_back_hook"] == logger.scenario_id for e in entries):
            raise SecretAllowlistError(f"{name}: the Logger scenario {logger.scenario_id} is also a fetch-back target of a pinned entry")
    return SecretAllowlist(entries, logger)


def parse_pinned_entries(data: object, name: str = "secret_allowlist.json") -> list[dict]:
    """Validated entries {scenario_id, module_id, pattern_type, reason, requires_fetch_back_hook}.

    scenario_id and requires_fetch_back_hook are scenario IDs (digits), module_id is an int.
    pattern_type must be one of ALLOWLISTABLE_PATTERN_TYPES, so a Stripe or OpenAI key can never
    be excused by this file. Every entry needs a real reason, the scenario it depends on (the
    one whose hook the URL targets, which must pass fetch-back) and token_sha256, the SHA-256 of
    the one hook token the field may hold."""
    raw = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise SecretAllowlistError(f"{name} has no entries list")
    out: list[dict] = []
    seen: set[tuple] = set()
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise SecretAllowlistError(f"{name} entry {i} is not an object")
        ptype = e.get("pattern_type")
        if ptype not in ALLOWLISTABLE_PATTERN_TYPES:
            raise SecretAllowlistError(f"{name} entry {i}: pattern_type must be one of "
                                       f"{', '.join(ALLOWLISTABLE_PATTERN_TYPES)}. No other pattern can be allowlisted")
        reason = e.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 8 or not re.search(r"[A-Za-z]{3}", reason):
            raise SecretAllowlistError(f"{name} entry {i} needs a real reason (a sentence)")
        ids = {}
        for key in ("scenario_id", "requires_fetch_back_hook"):
            v = e.get(key)
            if isinstance(v, bool) or not isinstance(v, (int, str)) or not str(v).strip().isdigit():
                raise SecretAllowlistError(f"{name} entry {i}: {key} must be a scenario ID (digits)")
            ids[key] = str(v).strip()
        mid = e.get("module_id")
        if isinstance(mid, bool) or not (isinstance(mid, int) or (isinstance(mid, str) and mid.strip().isdigit())):
            raise SecretAllowlistError(f"{name} entry {i}: module_id must be an integer module ID")
        digest = e.get("token_sha256")
        if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
            raise SecretAllowlistError(f"{name} entry {i}: token_sha256 must be the 64 hex characters (lower case) of the SHA-256 "
                                       f"of the hook token. Without it an entry would excuse any URL in that module")
        key = (ids["scenario_id"], int(mid), ptype)
        if key in seen:
            raise SecretAllowlistError(f"{name} entry {i} repeats scenario {key[0]} module {key[1]}")
        seen.add(key)
        out.append({"scenario_id": ids["scenario_id"], "module_id": int(mid), "pattern_type": ptype,
                    "reason": reason.strip(), "requires_fetch_back_hook": ids["requires_fetch_back_hook"],
                    "token_sha256": digest})
    return out


def _read_webhooks(path: str | None) -> object:
    """Parsed webhook registry, or None when it is missing or unreadable (the Logger allowance then stays inactive)."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def load_secret_allowlist(path: str = DEFAULT_SECRET_ALLOWLIST, webhooks_path: str | None = None) -> SecretAllowlist:
    """Entries from the file. A missing file is the strictest allowlist (no entries, no Logger). webhooks_path is the webhook
    registry that activates the Logger allowance. It defaults to webhooks.json next to the allowlist file, so the repo's
    audit/secret_allowlist.json reads audit/webhooks.json."""
    if not os.path.exists(path):
        return SecretAllowlist()
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SecretAllowlistError(f"cannot read {os.path.basename(path)}: {exc.__class__.__name__}") from None
    if webhooks_path is None:
        webhooks_path = os.path.join(os.path.dirname(os.path.abspath(path)), "webhooks.json")
    return parse_secret_allowlist(data, os.path.basename(path), _read_webhooks(webhooks_path))


def _walk_path(obj: object, location: str):
    """(node at the path or None, deepest module dict seen on the way) for a secret_scan JSON path."""
    node: object = obj
    found = None
    rest = location[1:] if location.startswith("$") else location
    for m in _PATH_TOKEN.finditer(rest):
        if isinstance(node, dict) and "module" in node and "id" in node:
            found = node
        name, idx, quoted = m.groups()
        try:
            if name is not None:
                node = node[name]  # type: ignore[index]
            elif idx is not None:
                node = node[int(idx)]  # type: ignore[index]
            else:
                key = json.loads(quoted)
                if key == "<redacted>":
                    return None, found
                node = node[key]  # type: ignore[index]
        except (KeyError, IndexError, TypeError):
            return None, found
    if isinstance(node, dict) and "module" in node and "id" in node:
        found = node
    return node, found


def module_at(bp: dict, location: str) -> dict | None:
    """Deepest module on a JSON path such as $.flow[0].mapper.x, or None."""
    return _walk_path(bp, location)[1]


def value_at(obj: object, location: str) -> object:
    """The value a secret_scan location points at, or None. In-memory use only."""
    return _walk_path(obj, location)[0]


# The Logger URL fallback (R6) is accepted only as the whole url field of a Logger call module on the flow itself: flow[i], then
# routes[j].flow[k] and onerror[k] steps only, then .mapper.url. A module-shaped dict nested in a mapper never counts.
_MODULE_URL_PATH = re.compile(r"\$\.flow\[\d+\](?:\.(?:routes\[\d+\]\.flow|onerror)\[\d+\])*\.mapper\.url")
LOGGER_CALL_MODULE_TYPE = "http:MakeRequest"
# The API key keychain authentication types of http:MakeRequest v4 (audit_blueprints.LOGGER_AUTH). The keychain sends
# x-make-apikey, so the hook URL alone cannot start the Logger.
LOGGER_CALL_AUTH_TYPES = ("apiKeyConnection", "apiKey")
# The bare Make hook URL: https, a make.com or make.celonis.com hook host, one token, nothing else. No userinfo, port, path,
# query string, fragment, whitespace, encoding or mapping, so the URL is the request target and never a value sent somewhere.
_BARE_HOOK_URL = re.compile(r"https://(?i:hook\.(?:[a-z0-9]{2,6}\.)?(?:make\.com|make\.celonis\.com))/(?P<t>[A-Za-z0-9_-]{16,})")


def is_logger_call_module(mod: object) -> bool:
    """True when mod is shaped like a Logger call at the transport level: http:MakeRequest, method POST, an API key keychain
    authentication type and no routes. Check B and make_push hold the rest of the call (connection, body, stopOnHttpError)."""
    if not isinstance(mod, dict) or mod.get("module") != LOGGER_CALL_MODULE_TYPE or mod.get("routes"):
        return False
    params = mod.get("parameters") if isinstance(mod.get("parameters"), dict) else {}
    mapper = mod.get("mapper") if isinstance(mod.get("mapper"), dict) else {}
    method = mapper.get("method")
    return (params.get("authenticationType") in LOGGER_CALL_AUTH_TYPES
            and isinstance(method, str) and method.strip().lower() == "post")


def _logger_call_at(bp: dict, location: str) -> dict | None:
    """The Logger call module whose own mapper.url the finding is, else None (another field, another module, a module nested
    in a mapper)."""
    if not _MODULE_URL_PATH.fullmatch(location):
        return None
    own = value_at(bp, location[: -len(".mapper.url")])
    if not (isinstance(own, dict) and "module" in own and "id" in own) or module_at(bp, location) is not own:
        return None
    return own if is_logger_call_module(own) else None


def logger_url_matches(value: object, logger: LoggerAllowance | None) -> bool:
    """True when value is exactly the bare Logger hook URL (https, one token, nothing before or after it, no query string,
    fragment or mapping) and the token hashes to the active Logger pin. make_push.logger_url_ok reads it for the literal
    fallback. In-memory only, the token is never returned."""
    if logger is None or not logger.active or not isinstance(value, str):
        return False
    m = _BARE_HOOK_URL.fullmatch(value)
    return m is not None and token_digest(m.group("t")) == logger.token_sha256


def match_allowlist(findings: list[dict], bp: dict, scenario_id: object, entries: list[dict],
                    logger: LoggerAllowance | None = None) -> tuple[list[dict], list[dict]]:
    """Split findings into (blocking, allowed).

    A pinned entry allows a make_webhook_url in the mapper.webhook of a Bland call module (ALLOWLISTABLE_MODULE_TYPE) named by an entry for this
    scenario, at exactly <module path>.mapper.webhook, where the field holds exactly one distinct hook token and its SHA-256
    equals the entry's token_sha256. Each entry excuses one finding, so a second URL on the same module still blocks.

    The Logger allowance (logger, or entries.logger when entries is a SecretAllowlist) is the dormant literal-URL fallback. It
    allows a make_webhook_url only at exactly <module path>.mapper.url of a Logger call module on the flow (is_logger_call_module)
    when that field is the bare Logger hook URL (logger_url_matches), and only while it is active (the Logger hook is registered
    in audit/webhooks.json with protection api_key). Any other field, a query string of another URL or another module blocks
    (R6). It excuses one finding per Logger call, since every error handler calls the Logger.

    Allowed findings are {pattern_type, location, module_id, module_type, requires_fetch_back_hook, reason, kind}. kind is "pinned" or
    "logger_hook". A Logger finding has requires_fetch_back_hook None and requires_api_key_hook (the Logger scenario ID)."""
    if logger is None:
        logger = getattr(entries, "logger", None)
    sid = None if scenario_id is None else str(scenario_id)
    blocking: list[dict] = []
    allowed: list[dict] = []
    used: set[int] = set()
    for f in findings:
        hit = None
        if (f["pattern_type"] in ALLOWLISTABLE_PATTERN_TYPES and f["location"].endswith(ALLOWLISTABLE_FIELD_SUFFIX) and sid
                and _MODULE_WEBHOOK_PATH.fullmatch(f["location"])):
            mod = module_at(bp, f["location"])
            value = value_at(bp, f["location"])
            tokens = set(all_webhook_tokens(value)) if isinstance(value, str) else set()
            digest = token_digest(next(iter(tokens))) if len(tokens) == 1 else None
            if mod is not None and mod.get("module") in ALLOWLISTABLE_MODULE_TYPE and digest is not None:
                for i, e in enumerate(entries):
                    if (i not in used and e["pattern_type"] == f["pattern_type"] and e["scenario_id"] == sid
                            and e["module_id"] == mod.get("id") and e["token_sha256"] == digest):
                        hit = i
                        break
        if hit is not None:
            used.add(hit)
            e = entries[hit]
            allowed.append({"pattern_type": f["pattern_type"], "location": f["location"], "module_id": e["module_id"],
                            "module_type": mod.get("module"),
                            "requires_fetch_back_hook": e["requires_fetch_back_hook"], "reason": e["reason"], "kind": PINNED_KIND})
            continue
        if f["pattern_type"] == "make_webhook_url" and logger is not None and logger.active:
            mod = _logger_call_at(bp, f["location"])
            if mod is not None and logger_url_matches(value_at(bp, f["location"]), logger):
                allowed.append({"pattern_type": f["pattern_type"], "location": f["location"], "module_id": mod.get("id"),
                                "requires_fetch_back_hook": None, "requires_api_key_hook": logger.scenario_id,
                                "hook_id": logger.hook_id, "reason": logger.reason, "kind": LOGGER_KIND})
                continue
        blocking.append(f)
    return blocking, allowed


def split_findings(bp: dict, scenario_id: object, entries: list[dict],
                   logger: LoggerAllowance | None = None) -> tuple[list[dict], list[dict]]:
    """scan_obj(bp) split by the pinned allowlist and the Logger allowance into (blocking, allowed)."""
    return match_allowlist(scan_obj(bp), bp, scenario_id, entries, logger)


def make_webhook_tokens(value: str) -> list[str]:
    """Hook tokens in the Make webhook URLs inside value. Compared in memory by make_pull against
    the hook list, never written or printed."""
    rx = dict(_TEXT_PATTERNS)["make_webhook_url"]
    return [m.group("t") for m in rx.finditer(value) if not _is_placeholder_token("make_webhook_url", m)]


def all_webhook_tokens(value: str) -> list[str]:
    """Hook tokens in value as written and in its percent-decoded copy (the scanner reads both, so a second, encoded URL in
    the same field is a token too). Distinct, in order of appearance. In-memory only."""
    out: list[str] = []
    for text in (value, urllib.parse.unquote(value) if "%" in value else value):
        for t in make_webhook_tokens(text):
            if t not in out:
                out.append(t)
    return out


def _git(args: list[str], cwd: str | None = None) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def staged_paths(cwd: str | None = None) -> list[str]:
    """Paths staged for commit (added, copied, modified, renamed, type changed)."""
    out = _git(["diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z"], cwd=cwd)
    return [p for p in out.decode("utf-8", errors="replace").split("\x00") if p]


def scan_staged(cwd: str | None = None) -> list[dict]:
    """Scan the staged blob of every staged file (git show :path)."""
    root = _git(["rev-parse", "--show-toplevel"], cwd=cwd).decode().strip()
    findings: list[dict] = []
    allow_cache: dict = {}
    for p in staged_paths(root):
        low = p.rsplit("/", 1)[-1].lower()
        if (low == ".env" or low.startswith(".env.") or low.endswith(".env")) and low not in _DOTENV_ALLOWED:
            findings.append(_finding("dotenv_file_staged", p))
            continue
        # Lead and applicant exports are PII (hard rule 5). Synthetic tabular
        # fixtures may live under tests/fixtures/ only.
        if os.path.splitext(low)[1] in _TABULAR_EXTS and not p.startswith("tests/fixtures/"):
            findings.append(_finding("tabular_data_file_staged", p))
            continue
        # bland/ holds sanitized pathway exports only. A call recording or
        # transcript placed there is client data (hard rule 5) that no scanner sees.
        if p.startswith("bland/") and not re.fullmatch(r"bland/[^/]+-pathway\.json", p):
            findings.append(_finding("bland_non_pathway_file_staged", p))
            continue
        data = _git(["show", f":{p}"], cwd=root)
        m = _BLUEPRINT_REPO_PATH.fullmatch(p)
        if m:
            findings.extend(_scan_staged_blueprint(data, p, m.group(1), root, allow_cache))
            continue
        findings.extend(scan_bytes(data, p))
    return findings


def _staged_secret_allowlist(root: str) -> SecretAllowlist:
    """Entries of audit/secret_allowlist.json as staged (the index copy, which is HEAD's when
    the file is not staged), with the Logger allowance decided by audit/webhooks.json as staged.
    Raises SecretAllowlistError when the allowlist file is invalid."""
    try:
        data = _git(["show", f":{SECRET_ALLOWLIST_REPO_PATH}"], cwd=root)
    except subprocess.CalledProcessError:
        return SecretAllowlist()
    try:
        obj = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise SecretAllowlistError("staged secret_allowlist.json is not valid JSON") from None
    try:
        hooks = json.loads(_git(["show", f":{WEBHOOKS_REPO_PATH}"], cwd=root).decode("utf-8-sig"))
    except (subprocess.CalledProcessError, UnicodeDecodeError, ValueError):
        hooks = None
    return parse_secret_allowlist(obj, webhooks_data=hooks)


def _staged_manifest(root: str) -> dict[str, dict]:
    """Scenario ID -> manifest entry from blueprints/manifest.json as staged (the index copy, which
    is HEAD's when the file is not staged). Empty when it is missing or unreadable."""
    try:
        obj = json.loads(_git(["show", f":{MANIFEST_REPO_PATH}"], cwd=root).decode("utf-8-sig"))
    except (subprocess.CalledProcessError, UnicodeDecodeError, ValueError):
        return {}
    rows = obj.get("scenarios") if isinstance(obj, dict) else None
    return {str(r["id"]): r for r in rows if isinstance(r, dict) and "id" in r} if isinstance(rows, list) else {}


def _manifest_vouches(entry: dict | None, path: str, allowed: dict) -> bool:
    """make_pull wrote this file: the manifest names exactly this file for the scenario and lists
    the allowlisted finding. A hand-made blueprints/anything__<id>.json has neither."""
    if not isinstance(entry, dict) or entry.get("file") != path.rsplit("/", 1)[-1]:
        return False
    listed = entry.get("allowlisted_findings")
    kind = allowed.get("kind", PINNED_KIND)
    return isinstance(listed, list) and any(
        isinstance(x, dict) and x.get("module_id") == allowed["module_id"] and x.get("pattern_type") == allowed["pattern_type"]
        and x.get("kind", PINNED_KIND) == kind
        for x in listed)


def _scan_staged_blueprint(data: bytes, path: str, scenario_id: str, root: str, cache: dict) -> list[dict]:
    """A staged blueprint file is scanned with the same rule as make_pull: findings that match a
    pinned allowlist entry are accepted when the staged manifest vouches for the file (it names this
    exact file for the scenario and lists the finding under allowlisted_findings). Everything else blocks.

    Not checked here: whether the scenario the URL targets passes F2. That is audit check D, which turns the
    allowance into a FAIL while the target fails. The pull and the commit must still record live state, and
    withholding a snapshot until a target passes would hide the very blueprint the audit has to read. The
    token pin means a changed URL cannot be committed without an edit to audit/secret_allowlist.json, which
    is reviewed in git."""
    text = _decode_text(data)
    obj = None
    if text is not None:
        try:
            obj = json.loads(text[1:] if text.startswith("\ufeff") else text)
        except ValueError:
            obj = None
    if not isinstance(obj, dict):
        return scan_bytes(data, path)  # not parseable JSON: the ordinary text scan, no allowance
    if "entries" not in cache:
        try:
            cache["entries"] = _staged_secret_allowlist(root)
        except SecretAllowlistError:
            cache["entries"] = None
    entries = cache["entries"]
    if entries is None:
        return [_finding("secret_allowlist_invalid", SECRET_ALLOWLIST_REPO_PATH)] + scan_bytes(data, path)
    blocking, allowed = split_findings(obj, scenario_id, entries)
    if allowed:
        if "manifest" not in cache:
            cache["manifest"] = _staged_manifest(root)
        entry = cache["manifest"].get(str(scenario_id))
        blocking = blocking + [a for a in allowed if not _manifest_vouches(entry, path, a)]
    return [_finding(f["pattern_type"], f"{path}:{f['location']}") for f in blocking]


def format_findings(findings: list[dict]) -> str:
    """One line per finding: pattern type and location only."""
    return "\n".join(f"{f['pattern_type']}\t{f['location']}" for f in findings)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv in (["-h"], ["--help"]):
        print("usage: secret_scan.py --staged | PATH...", file=sys.stderr)
        return 2
    try:
        if argv == ["--staged"]:
            findings = scan_staged()
        elif "--staged" in argv:
            print("--staged takes no paths", file=sys.stderr)
            return 2
        else:
            findings = scan_paths(argv)
    except subprocess.CalledProcessError as e:
        print(f"secret_scan: git {' '.join(e.cmd[1:2])} failed (exit {e.returncode})", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"secret_scan: cannot read {e.filename}: {e.strerror}", file=sys.stderr)
        return 2
    if findings:
        print(f"secret_scan: {len(findings)} finding(s). Values are not shown.")
        print(format_findings(findings))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
