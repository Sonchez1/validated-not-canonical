#!/usr/bin/env python3
"""Compute the results matrix, disagreement pairs and finding list.

Reads corpus/corpus.json and results/raw/*.jsonl, writes

  results/matrix-<class>.md   acceptance matrix per input class
  results/disagreements.md    per ecosystem, cases where components disagree
  results/findings.json       machine-readable finding list
  results/findings.md         human-readable finding list
  results/summary.json        counts used by the paper

Definitions (see README):

  canonical          the corpus case's UTS 46 ToASCII (strict, non-transitional)
                     or null when the input has no valid canonical form.
  effective host     for an accepted row: strict ToASCII of the row's output,
                     or "INVALID" when the output has no canonical form.
                     Two accepting components agree iff their effective hosts
                     are equal.
  outcome of a row   reject            the component rejected the input
                     accept-canonical  output == canonical byte for byte
                     accept-equivalent output != canonical but ToASCII(output)
                                       == canonical (U-label, upper case, ...)
                     accept-noncanon   output != canonical and ToASCII(output)
                                       != canonical: the blessed string is a
                                       different host or an invalid one
                     accept-invalid    the case has no canonical form and the
                                       component accepted it anyway
  finding            a validator row with outcome accept-noncanon or
                     accept-invalid (or accept-equivalent on a case whose
                     canonical collapse removes characters: invisible or
                     mapped-to-ASCII classes), on a case not marked
                     benign_difference, where at least one downstream
                     component (parser or encoder) in the same ecosystem
                     rejects the same input or yields a different effective
                     host. A validator that normalises to the canonical host
                     is correct and is never a finding.
"""
from __future__ import annotations

import collections
import glob
import json
import os
import sys
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "corpus", "corpus.json")

# ---------------------------------------------------------------------------
# Reference canonicaliser (same engine as corpus/generate.py)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(ROOT, "corpus"))
import generate as gen  # noqa: E402

ENGINE = gen.canonical_engine()
_cache: dict[str, Optional[str]] = {}


def to_ascii(host: str) -> Optional[str]:
    if host not in _cache:
        _cache[host] = gen.ref_canonical(host)
    return _cache[host]


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------
with open(CORPUS, encoding="utf-8") as fh:
    CORP = json.load(fh)
CASES = {c["id"]: c for c in CORP["cases"]}
CLASS_ORDER = ["invisible", "confusable", "idna", "control"]

ROWS = []
for path in sorted(glob.glob(os.path.join(HERE, "raw", "*.jsonl"))):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                ROWS.append(json.loads(line))

# Component kind is not in the row schema; infer it from the function name the
# harnesses use, with an explicit override table.
PARSER_HINTS = ("parse", "URL(", "Url(", "url.Parse", "URI(", "URL::", "Uri::", "uri_reference", "from_text",
                ".host", "hostname", "Request", "prepare", "fetch", "domainToASCII", "ToASCII", "encode(",
                "idn_to_ascii", "IDN.", "idna::", "to_ascii", "Punycode", "punycode", "tr46", "Name", "dns.",
                "resolver", "getaddrinfo", "Addr(", "mail.Parse", "Mail::", "Address(", "parseaddr",
                "tldextract", "tldts", "psl.", "PublicSuffix", "InternetDomainName", "publicsuffix", "extract(")


def component_kind(row: dict) -> str:
    """validator | downstream. Validators are what an application calls to
    decide whether to accept user input; downstream components are what then
    consumes the accepted string (URL parsers, HTTP clients, IDNA encoders,
    resolvers, public-suffix splitters, address parsers)."""
    k = row.get("kind")
    if k:
        return k
    fn = row["function"]
    lib = row["library"]
    if lib in ("stdlib", "idna", "requests", "urllib3", "hyperlink", "yarl", "rfc3986", "furl", "tldextract",
               "dnspython", "whatwg-url", "tr46", "punycode", "psl", "tldts", "golang.org/x/net/idna",
               "url", "idna-rs", "publicsuffix", "addressable", "public_suffix", "simpleidn", "league/uri",
               "guava", "java.net", "commons-validator:DomainValidator"):
        # stdlib validators (Go net/mail, Ruby URI) are parsers too
        return "downstream"
    if any(h in fn for h in ("validate", "Valid", "valid", "is", "Email", "URL()", "Url()", "schema", "Schema", "constraint", "Constraint", "filter_var", "z.", "yup", "Joi", "ajv")):
        return "validator"
    return "downstream"


def outcome(row: dict, case: dict) -> tuple[str, Optional[str]]:
    """Return (outcome, effective_host)."""
    if not row["accepted"]:
        return "reject", None
    out = row["output"] if row["output"] is not None else ""
    canon = case["canonical"]
    eff = to_ascii(out)
    eff_key = eff if eff is not None else "INVALID"
    if canon is None:
        if case["whatwg"] is not None and out == case["whatwg"]:
            return "accept-whatwg", eff_key
        return "accept-invalid", eff_key
    if out == canon:
        return "accept-canonical", eff_key
    if eff == canon:
        return "accept-equivalent", eff_key
    if case["whatwg"] is not None and out == case["whatwg"]:
        return "accept-whatwg", eff_key
    return "accept-noncanon", eff_key


# Cases where "equivalent" still means the blessed string carries characters
# the canonical form drops: an invisible character or a mapped confusable.
COLLAPSE_SUBCLASSES = {"ignored", "deviation", "disallowed", "mapped-to-ascii", "mapped-to-nonascii", "fullwidth-dot",
                       "whitespace-control", "percent-encoded"}


def is_collapse_case(case: dict) -> bool:
    return case["class"] in ("invisible",) or case["subclass"] in COLLAPSE_SUBCLASSES


# ---------------------------------------------------------------------------
# Annotate rows
# ---------------------------------------------------------------------------
for r in ROWS:
    c = CASES[r["case_id"]]
    r["_kind"] = component_kind(r)
    r["_outcome"], r["_eff"] = outcome(r, c)
    r["_class"], r["_sub"] = c["class"], c["subclass"]

by_eco_case = collections.defaultdict(list)
for r in ROWS:
    by_eco_case[(r["ecosystem"], r["case_id"])].append(r)


def comp_name(r: dict) -> str:
    return f"{r['library']} {r['version']} :: {r['function']}"


# ---------------------------------------------------------------------------
# Matrix per class
# ---------------------------------------------------------------------------
SYMBOL = {"reject": "R", "accept-canonical": "C", "accept-equivalent": "E", "accept-noncanon": "N", "accept-invalid": "X", "accept-whatwg": "W"}
LEGEND = ("Cell = outcome counts over the subclass's cases: **R** rejected, **C** accepted and output is the canonical "
          "A-label byte for byte, **E** accepted and output is equivalent (same host after UTS 46 ToASCII, e.g. a U-label "
          "or upper case), **N** accepted and output canonicalises to a *different* host, **X** accepted although the input "
          "has no valid canonical form, **W** accepted with exactly the host the WHATWG URL parser produces (browser-conformant, "
          "not counted as a finding even where strict UTS 46 rejects). For the invisible and mapped-confusable classes an **E** means the validator passed "
          "the invisible/mapped character through: the string is equivalent only to a UTS 46-aware consumer.")


def write_matrices() -> None:
    for cls in CLASS_ORDER:
        subs = []
        for c in CORP["cases"]:
            if c["class"] == cls and c["subclass"] not in subs:
                subs.append(c["subclass"])
        comps = []
        seen = set()
        for r in ROWS:
            if r["_class"] == cls:
                k = (r["ecosystem"], r["library"], r["version"], r["function"], r["surface"])
                if k not in seen:
                    seen.add(k)
                    comps.append(k)
        comps.sort()
        lines = [f"# Results matrix: class `{cls}`", "", LEGEND, "",
                 "Subclass case counts: " + ", ".join(f"`{s}` {sum(1 for c in CORP['cases'] if c['class']==cls and c['subclass']==s)}" for s in subs), "",
                 "| ecosystem | library | version | function | surface | " + " | ".join(subs) + " |",
                 "|" + "---|" * (5 + len(subs))]
        for k in comps:
            cells = []
            for s in subs:
                counts = collections.Counter()
                for r in ROWS:
                    if (r["ecosystem"], r["library"], r["version"], r["function"], r["surface"]) == k and r["_class"] == cls and r["_sub"] == s:
                        counts[SYMBOL[r["_outcome"]]] += 1
                cells.append(" ".join(f"{sym}{n}" for sym, n in sorted(counts.items())) or "-")
            fn = k[3].replace("|", "\\|")
            lines.append(f"| {k[0]} | {k[1]} | {k[2]} | `{fn}` | {k[4]} | " + " | ".join(cells) + " |")
        with open(os.path.join(HERE, f"matrix-{cls}.md"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Disagreements and findings
# ---------------------------------------------------------------------------
def disagreements():
    """For each (ecosystem, case) with >= 2 components: the set of distinct
    verdicts. A disagreement exists when the set has more than one member."""
    out = {}
    for key, rows in by_eco_case.items():
        verdicts = collections.defaultdict(list)
        for r in rows:
            v = "reject" if r["_outcome"] == "reject" else f"accept:{r['_eff']}"
            verdicts[v].append(comp_name(r))
        if len(verdicts) > 1:
            out[key] = verdicts
    return out


# Finding buckets. Only these subclasses can produce a finding against a
# validator; the others are policy differences where the reference engines
# themselves disagree (hyphens, symbols), or valid input that a validator is
# entitled to pass through (deviation characters, valid confusable letters).
BUCKETS = {
    "invisible": ("invisible", "low-moderate"),
    "mapped-to-ascii": ("mapped-confusable", "low-moderate"),
    "fullwidth-dot": ("mapped-confusable", "low-moderate"),
    "whitespace-control": ("whitespace-control", "low-moderate"),
    "punycode-decodes-invalid": ("undecodable-punycode", "low"),
    "punycode-ascii-only": ("undecodable-punycode", "low"),
    "punycode-invalid": ("undecodable-punycode", "low"),
    "label-length": ("length", "low"),
    "name-length": ("length", "low"),
    "dots": ("empty-label", "low"),
    "bidi": ("bidi", "informational"),
    "mapped-to-nonascii": ("mapped-confusable", "informational"),
    "percent-encoded": ("percent-encoded", "informational"),
}


# Libraries whose "valid" predicate is documented as a public-suffix rule
# match rather than hostname syntax validation. Applications do use them as
# validators, so they stay in the list, but at informational severity.
SEVERITY_OVERRIDE = {
    ("node", "psl"): ("informational", "psl.isValid checks that the trailing labels match a Public Suffix List rule; it is not a syntax validator"),
    ("ruby", "public_suffix"): ("informational", "PublicSuffix.valid? checks that the trailing labels match a Public Suffix List rule; it is not a syntax validator"),
}


def bucket_for(case: dict):
    if case["class"] == "invisible":
        return BUCKETS["invisible"]
    return BUCKETS.get(case["subclass"])


def handles_idn(eco: str, name: str) -> bool:
    """A downstream component counts as disagreeing only if it can handle a
    valid IDN at all (accepts ctl-good-idn or ctl-good-alabel on its surface);
    otherwise its rejection of every non-ASCII string says nothing about the
    specific case."""
    for cid in ("ctl-good-idn", "ctl-good-alabel"):
        for d in by_eco_case.get((eco, cid), []):
            if comp_name(d) == name and d["accepted"]:
                return True
    return False


def compute_findings():
    """Group by (ecosystem, library, version, function, surface, bucket)."""
    groups = collections.OrderedDict()
    for r in ROWS:
        if r["_kind"] != "validator":
            continue
        c = CASES[r["case_id"]]
        if c["benign_difference"] or c["class"] == "control":
            continue
        b = bucket_for(c)
        if b is None:
            continue
        bucket, severity = b
        o = r["_outcome"]
        if o in ("reject", "accept-canonical", "accept-whatwg"):
            continue
        if o == "accept-equivalent" and (not is_collapse_case(c) or r["output"] != c["host"]):
            continue  # a valid IDN passed through, or the validator normalised it: not a finding
        # downstream disagreement in the same ecosystem
        downstream = [d for d in by_eco_case[(r["ecosystem"], r["case_id"])] if d["_kind"] == "downstream"]
        disagree = []
        for d in downstream:
            name = comp_name(d)
            if d["_outcome"] == "reject":
                if handles_idn(r["ecosystem"], name):
                    disagree.append((name, "rejects"))
            elif d["_eff"] != r["_eff"]:
                disagree.append((name, f"yields {d['_eff']}"))
            elif r["output_kind"] == "passthrough" and d["output_kind"] in ("normalized", "parsed") and d["output"] != r["output"]:
                disagree.append((name, f"normalises to {d['output']!r}"))
        if not disagree:
            continue
        key = (r["ecosystem"], r["library"], r["version"], r["function"], r["surface"], bucket)
        override = SEVERITY_OVERRIDE.get((r["ecosystem"], r["library"]))
        g = groups.setdefault(key, {
            "ecosystem": r["ecosystem"], "library": r["library"], "version": r["version"],
            "function": r["function"], "surface": r["surface"], "bucket": bucket,
            "severity": override[0] if override else severity, "severity_note": override[1] if override else None,
            "cases": [], "downstream_disagreements": collections.Counter(),
        })
        g["cases"].append({"case_id": c["id"], "input": r["input"], "output": r["output"], "outcome": o,
                           "canonical": c["canonical"], "note": c["note"]})
        for name, what in disagree:
            g["downstream_disagreements"][f"{name} -> {what}"] += 1
    findings = []
    for g in groups.values():
        g["downstream_disagreements"] = [f"{k} ({v} cases)" for k, v in g["downstream_disagreements"].most_common()]
        g["n_cases"] = len(g["cases"])
        findings.append(g)
    sev_rank = {"low-moderate": 0, "low": 1, "informational": 2}
    findings.sort(key=lambda g: (sev_rank[g["severity"]], g["ecosystem"], g["library"], g["bucket"], g["function"]))
    return findings


def write_disagreements(dis):
    lines = ["# Disagreement pairs", "",
             "For each ecosystem and corpus case where at least two components reached different verdicts. "
             "`accept:<host>` is the effective host (strict UTS 46 ToASCII of the component's output); `accept:INVALID` means the "
             "component accepted a string that has no valid canonical form.", ""]
    by_eco = collections.defaultdict(list)
    for (eco, cid), v in dis.items():
        by_eco[eco].append((cid, v))
    for eco in sorted(by_eco):
        lines.append(f"## {eco}")
        lines.append("")
        items = sorted(by_eco[eco], key=lambda t: (CLASS_ORDER.index(CASES[t[0]]["class"]), t[0]))
        for cid, v in items:
            c = CASES[cid]
            lines.append(f"### `{cid}` ({c['class']}/{c['subclass']}): `{json.dumps(c['host'], ensure_ascii=True)}` -> canonical `{c['canonical']}`")
            lines.append("")
            for verdict in sorted(v):
                lines.append(f"- **{verdict}**: " + "; ".join(sorted(v[verdict])))
            lines.append("")
    with open(os.path.join(HERE, "disagreements.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_findings(findings):
    with open(os.path.join(HERE, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump({"canonical_engine": ENGINE, "count": len(findings), "findings": findings}, fh, ensure_ascii=True, indent=1)
    lines = ["# Finding list", "",
             f"{len(findings)} findings. Canonical engine: `{ENGINE}`. A finding is one validator function that accepted a case "
             "whose blessed output is not the canonical host, where a downstream component in the same ecosystem rejects the same "
             "input or treats it as a different host. Validators that normalise to the canonical host are not listed.", "",
             "| # | severity | ecosystem | library | version | function | surface | class bucket | cases | downstream components that disagree |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for i, g in enumerate(findings, 1):
        ids = ", ".join(sorted(c["case_id"] for c in g["cases"]))
        if len(ids) > 120:
            ids = ids[:117] + "..."
        ds = "<br>".join(g["downstream_disagreements"][:4]).replace("|", "\\|")
        fn = g["function"].replace("|", "\\|")
        lines.append(f"| {i} | {g['severity']} | {g['ecosystem']} | {g['library']} | {g['version']} | `{fn}` | {g['surface']} | {g['bucket']} | {g['n_cases']} ({ids}) | {ds} |")
    with open(os.path.join(HERE, "findings.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_summary(findings, dis):
    ecos = sorted({r["ecosystem"] for r in ROWS})
    libs = sorted({(r["ecosystem"], r["library"], r["version"]) for r in ROWS})
    funcs = sorted({(r["ecosystem"], r["library"], r["function"], r["surface"]) for r in ROWS})
    sev = collections.Counter(g["severity"] for g in findings)
    bucket = collections.Counter(g["bucket"] for g in findings)
    per_eco = collections.Counter(g["ecosystem"] for g in findings)
    outcome_counts = collections.Counter((r["_class"], r["_outcome"]) for r in ROWS)
    summary = {
        "canonical_engine": ENGINE,
        "cases": CORP["counts"],
        "rows": len(ROWS),
        "ecosystems": ecos,
        "libraries": len(libs),
        "functions": len(funcs),
        "findings": len(findings),
        "findings_by_severity": dict(sev),
        "findings_by_bucket": dict(bucket),
        "findings_by_ecosystem": dict(per_eco),
        "disagreement_cases_by_ecosystem": dict(collections.Counter(e for e, _ in dis)),
        "outcomes_by_class": {f"{c}/{o}": n for (c, o), n in sorted(outcome_counts.items())},
    }
    with open(os.path.join(HERE, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    return summary


if __name__ == "__main__":
    write_matrices()
    dis = disagreements()
    write_disagreements(dis)
    findings = compute_findings()
    write_findings(findings)
    s = write_summary(findings, dis)
    print(json.dumps({k: s[k] for k in ("rows", "ecosystems", "libraries", "functions", "findings", "findings_by_severity", "findings_by_bucket", "findings_by_ecosystem")}, indent=1))
