"""Checks catalog/countries.json (PROTOCOL.md 4d.2). Run with: python -m pytest catalog

What is checked:
- the file follows catalog/schema.json
- every method name comes from PROTOCOL.md 4d
- every country in the 4d.2 coverage list is present
- platforms, privacy and needs match 4d.3 / 4d.2
- every non-passport entry has a source in docs/catalog/SOURCES.md
- nothing listed as "Not included" or "Unconfirmed" in SOURCES.md is in the file
"""
import datetime
import json
import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CATALOG = HERE / "countries.json"
SCHEMA = HERE / "schema.json"
SOURCES = ROOT / "docs" / "catalog" / "SOURCES.md"

# PROTOCOL.md 4d.2 coverage: every EU/EEA country plus the UK and Switzerland, and these Asian countries.
EU = ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
      "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"]
EEA_NON_EU = ["IS", "LI", "NO"]
UK_CH = ["GB", "CH"]
ASIA = ["IN", "PH", "JP", "SG", "KR", "VN", "ID", "MY", "TH", "PK", "BD", "LK", "NP", "AE", "SA", "QA",
        "KW", "CN", "HK", "TW", "IL", "TR"]
REQUIRED_COUNTRIES = EU + EEA_NON_EU + UK_CH + ASIA

# PROTOCOL.md 4d.4: the connector ids (the 12 that connectors/ builds).
CONNECTOR_IDS = {"singpass", "digilocker", "uaepass", "bankid_se", "bankid_no", "mitid", "itsme",
                 "franceconnect", "spid", "cie", "digid", "freja"}

# Methods that must NOT be in the file (PROTOCOL.md 4d.4b): the server adds face_estimate itself if
# it ever ships, and mynumber_attested is not in v1.
NOT_IN_FILE = {"face_estimate": "the server adds it, and it is not in v1 (4d.4b)",
               "mynumber_attested": "it is not in v1 (4d.4b)"}

# PROTOCOL.md 4c / 4d.3: method -> (privacy, platforms, needs that are allowed)
RULES = {
    "anon_aadhaar": ("zero_knowledge", {"android", "windows"}, {"camera"}),
    "emrtd_attested": ("on_device", {"android"}, {"nfc", "camera"}),
    "philsys_qr_attested": ("on_device", {"android"}, {"camera"}),
    "mynumber_attested": ("on_device", {"android"}, {"nfc", "password"}),
    "mdoc_app": ("wallet", {"android"}, {"wallet"}),
    "mdoc_wallet": ("wallet", {"web"}, {"wallet"}),
    "face_estimate": ("estimate", {"android"}, {"camera"}),
    "connector": ("login", {"android", "windows"}, {"password"}),
}


def base(method):
    return "connector" if method.startswith("connector:") else method


def is_passport(m):
    return m["method"] == "emrtd_attested" and m.get("docTypes") == ["P"]


def source_key(m):
    """The key SOURCES.md uses for an entry, e.g. 'connector:itsme' or 'emrtd_attested[A,C,I]'."""
    if m["method"] == "emrtd_attested":
        return "emrtd_attested[" + ",".join(m["docTypes"]) + "]"
    return m["method"]


@pytest.fixture(scope="module")
def catalog():
    with open(CATALOG, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sources():
    return parse_sources(SOURCES.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- SOURCES.md parsing

def parse_sources(text):
    """Returns {"shared": {tag: line}, "countries": {code: {key: line}}, "excluded": [(code, key, line)]}."""
    shared, countries, excluded = {}, {}, []
    part, code = None, None
    for line in text.splitlines():
        if line.startswith("## "):
            title = line[3:].strip().lower()
            part = ("shared" if title.startswith("shared") else
                    "countries" if title.startswith("countries") else
                    "excluded" if title.startswith(("not included", "unconfirmed")) else None)
            code = None
            continue
        if part == "countries" and line.startswith("### "):
            m = re.match(r"### ([A-Z]{2}) ", line)
            assert m, f"country heading must start with a 2-letter code: {line!r}"
            code = m.group(1)
            assert code not in countries, f"SOURCES.md has two sections for {code}"
            countries[code] = {}
            continue
        if part == "shared":
            m = re.match(r"- \[S:([A-Z0-9-]+)\] ", line)
            if m:
                shared[m.group(1)] = line
        elif part == "countries" and code:
            m = re.match(r"- `([^`]+)`", line)
            if m:
                assert m.group(1) not in countries[code], f"{code} lists `{m.group(1)}` twice in SOURCES.md"
                countries[code][m.group(1)] = line
        elif part == "excluded":
            m = re.match(r"- \*\*([A-Z]{2})\*\* `([^`]+)`", line)
            if m:
                excluded.append((m.group(1), m.group(2), line))
    return {"shared": shared, "countries": countries, "excluded": excluded}


def has_citation(line, shared):
    if re.search(r"https?://\S+", line):
        return True
    tags = re.findall(r"\[S:([A-Z0-9-]+)\]", line)
    return any(t in shared and re.search(r"https?://\S+", shared[t]) for t in tags)


# ---------------------------------------------------------------- small JSON Schema checker

def schema_errors(instance, schema):
    """Uses the jsonschema package if it is installed, otherwise a small checker for the
    keywords schema.json uses. Returns a list of error strings."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return _check(instance, schema, schema, "$")
    v = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(instance)]


_TYPES = {"object": dict, "array": list, "string": str, "integer": int}


def _check(x, s, root, at):
    errs = []
    if "$ref" in s:
        node = root
        for part in s["$ref"].lstrip("#/").split("/"):
            node = node[part]
        errs += _check(x, node, root, at)
    if "type" in s:
        t = _TYPES[s["type"]]
        if not isinstance(x, t) or (s["type"] == "integer" and isinstance(x, bool)):
            return errs + [f"{at}: should be {s['type']}"]
    if "const" in s and x != s["const"]:
        errs.append(f"{at}: should be {s['const']!r}")
    if "enum" in s and x not in s["enum"]:
        errs.append(f"{at}: {x!r} is not one of {s['enum']}")
    if isinstance(x, str):
        if "pattern" in s and not re.search(s["pattern"], x):
            errs.append(f"{at}: {x!r} does not match {s['pattern']}")
        if len(x) < s.get("minLength", 0):
            errs.append(f"{at}: too short")
    if isinstance(x, int) and not isinstance(x, bool):
        if "minimum" in s and x < s["minimum"]:
            errs.append(f"{at}: below {s['minimum']}")
        if "maximum" in s and x > s["maximum"]:
            errs.append(f"{at}: above {s['maximum']}")
    if isinstance(x, list):
        if len(x) < s.get("minItems", 0):
            errs.append(f"{at}: needs at least {s['minItems']} items")
        if "maxItems" in s and len(x) > s["maxItems"]:
            errs.append(f"{at}: at most {s['maxItems']} items")
        if s.get("uniqueItems") and len({json.dumps(i, sort_keys=True) for i in x}) != len(x):
            errs.append(f"{at}: items must be unique")
        if "items" in s:
            for i, item in enumerate(x):
                errs += _check(item, s["items"], root, f"{at}[{i}]")
    if isinstance(x, dict):
        for k in s.get("required", []):
            if k not in x:
                errs.append(f"{at}: missing '{k}'")
        props = s.get("properties", {})
        for k, v in x.items():
            if k in props:
                errs += _check(v, props[k], root, f"{at}.{k}")
            elif s.get("additionalProperties") is False:
                errs.append(f"{at}: unknown field '{k}'")
    for sub in s.get("allOf", []):
        errs += _check(x, sub, root, at)
    if "not" in s and not _check(x, s["not"], root, at):
        errs.append(f"{at}: matches a 'not' rule")
    if "if" in s:
        branch = s.get("then") if not _check(x, s["if"], root, at) else s.get("else")
        if branch:
            errs += _check(x, branch, root, at)
    return errs


# ---------------------------------------------------------------- tests

def test_schema_itself_rejects_bad_input(schema):
    bad = {"version": 1, "countries": [{"code": "xx", "name": "", "region": "mars", "methods": [
        {"method": "passport_zk", "label": "x", "documents": [], "needs": ["eyes"], "privacy": "secret",
         "platforms": ["ios"]},
        {"method": "emrtd_attested", "label": "x", "documents": ["d"], "needs": ["nfc"],
         "privacy": "on_device", "platforms": ["android"]}]}]}
    errs = schema_errors(bad, schema)
    assert len(errs) >= 8, errs


def test_follows_schema(catalog, schema):
    errs = schema_errors(catalog, schema)
    assert errs == [], "\n".join(errs[:20])


def test_method_names_come_from_4d(catalog):
    allowed = set(RULES) - {"connector"}
    for c in catalog["countries"]:
        for m in c["methods"]:
            name = m["method"]
            if name.startswith("connector:"):
                assert name.split(":", 1)[1] in CONNECTOR_IDS, f"{c['code']}: unknown connector {name}"
            else:
                assert name in allowed, f"{c['code']}: {name} is not a 4d method"
            assert name not in NOT_IN_FILE, f"{c['code']}: {name} must not be in the file: {NOT_IN_FILE.get(name)}"


def test_every_coverage_country_is_present(catalog):
    codes = [c["code"] for c in catalog["countries"]]
    assert len(codes) == len(set(codes)), "a country appears twice"
    missing = [c for c in REQUIRED_COUNTRIES if c not in codes]
    assert missing == [], f"missing countries: {missing}"


def test_regions(catalog):
    for c in catalog["countries"]:
        want = "asia" if c["code"] in ASIA else "europe"
        assert c["region"] == want, f"{c['code']} should be region {want}"


def test_platforms_privacy_and_needs_match_4d3(catalog):
    for c in catalog["countries"]:
        for m in c["methods"]:
            privacy, platforms, needs = RULES[base(m["method"])]
            where = f"{c['code']} {m['method']}"
            assert set(m["platforms"]) == platforms, f"{where}: platforms should be {sorted(platforms)}"
            assert m["privacy"] == privacy, f"{where}: privacy should be {privacy}"
            assert set(m["needs"]) <= needs and m["needs"], f"{where}: needs should come from {sorted(needs)}"


def test_doc_types(catalog):
    for c in catalog["countries"]:
        keys = []
        for m in c["methods"]:
            if m["method"] == "emrtd_attested":
                assert m["docTypes"], f"{c['code']}: emrtd_attested needs docTypes"
                if "P" in m["docTypes"]:
                    assert m["docTypes"] == ["P"], f"{c['code']}: passports get their own entry"
            else:
                assert "docTypes" not in m, f"{c['code']} {m['method']}: docTypes is only for emrtd_attested"
            keys.append(source_key(m))
        assert len(keys) == len(set(keys)), f"{c['code']} lists the same method twice: {keys}"


def test_since_is_not_in_the_future(catalog):
    year = datetime.date.today().year
    for c in catalog["countries"]:
        for m in c["methods"]:
            if "since" in m:
                assert m["since"] <= year, f"{c['code']} {m['method']}: since {m['since']} is in the future"


def test_every_non_passport_entry_has_a_source(catalog, sources):
    missing = []
    for c in catalog["countries"]:
        section = sources["countries"].get(c["code"])
        for m in c["methods"]:
            if is_passport(m):
                continue
            key = source_key(m)
            line = (section or {}).get(key)
            if line is None or not has_citation(line, sources["shared"]):
                missing.append(f"{c['code']} `{key}`")
    assert missing == [], "no source in SOURCES.md for: " + ", ".join(missing)


def test_sources_list_only_entries_that_exist(catalog, sources):
    by_code = {c["code"]: {source_key(m) for m in c["methods"]} for c in catalog["countries"]}
    for code, entries in sources["countries"].items():
        assert code in by_code, f"SOURCES.md has a section for {code}, which is not in the catalog"
        stale = [k for k in entries if k not in by_code[code]]
        assert stale == [], f"SOURCES.md {code} lists entries not in countries.json: {stale}"


def test_excluded_entries_are_not_in_the_catalog(catalog, sources):
    by_code = {c["code"]: {source_key(m) for m in c["methods"]} for c in catalog["countries"]}
    assert sources["excluded"], "SOURCES.md should have 'Not included' and 'Unconfirmed' lists"
    for code, key, _ in sources["excluded"]:
        assert key not in by_code.get(code, set()), f"{code} `{key}` is listed as excluded but is in countries.json"


def test_shared_sources_have_links(sources):
    for tag, line in sources["shared"].items():
        assert re.search(r"https?://\S+", line), f"shared source {tag} has no link"
