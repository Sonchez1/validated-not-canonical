#!/usr/bin/env python3
"""Generate paper/generated.tex from the study's results so that every number
in the paper is derived from corpus/corpus.json and results/*.json.

Run inside harness/python/.venv after results/analyze.py."""
from __future__ import annotations

import collections
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "generated.tex")

corpus = json.load(open(os.path.join(ROOT, "corpus", "corpus.json"), encoding="utf-8"))
summary = json.load(open(os.path.join(ROOT, "results", "summary.json"), encoding="utf-8"))
findings = json.load(open(os.path.join(ROOT, "results", "findings.json"), encoding="utf-8"))["findings"]
rows = []
for p in sorted(glob.glob(os.path.join(ROOT, "results", "raw", "*.jsonl"))):
    with open(p, encoding="utf-8") as fh:
        rows += [json.loads(l) for l in fh if l.strip()]
cases = {c["id"]: c for c in corpus["cases"]}

ECO_NAME = {"python": "Python", "node": "Node.js", "go": "Go", "java": "Java", "rust": "Rust", "ruby": "Ruby", "php": "PHP"}
ECO_ORDER = ["python", "node", "go", "java", "rust", "ruby", "php"]


def tex(s: str) -> str:
    return (s.replace("\\", "\\textbackslash{}").replace("&", "\\&").replace("%", "\\%").replace("_", "\\_")
            .replace("#", "\\#").replace("{", "\\{").replace("}", "\\}").replace("$", "\\$"))


def num(name: str, value) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}\n"


out = []
# ---------------------------------------------------------------- macros
out.append(num("nCases", corpus["counts"]["cases"]))
for cls, n in corpus["counts"]["by_class"].items():
    out.append(num("nCases" + cls.capitalize(), n))
out.append(num("nRows", f"{summary['rows']:,}"))
out.append(num("nLibraries", summary["libraries"]))
out.append(num("nFunctions", summary["functions"]))
out.append(num("nEcosystems", len(summary["ecosystems"])))
out.append(num("nFindings", summary["findings"]))
sev = summary["findings_by_severity"]
out.append(num("nFindingsLowMod", sev.get("low-moderate", 0)))
out.append(num("nFindingsLow", sev.get("low", 0)))
out.append(num("nFindingsInfo", sev.get("informational", 0)))
libs_lm = {(g["ecosystem"], g["library"]) for g in findings if g["severity"] == "low-moderate"}
libs_any = {(g["ecosystem"], g["library"]) for g in findings}
out.append(num("nFindingLibsLowMod", len(libs_lm)))
out.append(num("nFindingLibs", len(libs_any)))
validators = {(r["ecosystem"], r["library"], r["function"], r["surface"]) for r in rows if r["kind"] == "validator"}
downstream = {(r["ecosystem"], r["library"], r["function"], r["surface"]) for r in rows if r["kind"] == "downstream"}
out.append(num("nValidatorFunctions", len(validators)))
out.append(num("nDownstreamFunctions", len(downstream)))
out.append(num("canonicalEngine", tex(summary["canonical_engine"])))
out.append(num("unicodeVersion", corpus["unicode_data"]["IdnaMappingTable.txt"]))

# per-ecosystem validator acceptance of the headline cases
HEAD = ["inv-200B-mid", "inv-00AD-mid", "inv-E0041-mid", "cfs-mapped-ff45-e", "idn-ws-tab-mid"]
by = collections.defaultdict(lambda: collections.defaultdict(set))
for r in rows:
    if r["kind"] == "validator":
        by[r["ecosystem"]]["all"].add((r["library"], r["function"], r["surface"]))
        if r["accepted"] and r["case_id"] in HEAD:
            by[r["ecosystem"]][r["case_id"]].add((r["library"], r["function"], r["surface"]))
    # validators accepting at least one collapsing invisible case with passthrough
inv_pass = collections.defaultdict(set)
map_pass = collections.defaultdict(set)
for r in rows:
    if r["kind"] != "validator" or not r["accepted"]:
        continue
    c = cases[r["case_id"]]
    if c["class"] == "invisible" and c["canonical"] is not None and r["output"] == c["host"] and c["subclass"] in ("ignored", "disallowed"):
        inv_pass[r["ecosystem"]].add((r["library"], r["function"], r["surface"]))
    if c["subclass"] == "mapped-to-ascii" and r["output"] == c["host"]:
        map_pass[r["ecosystem"]].add((r["library"], r["function"], r["surface"]))
    if c["class"] == "invisible" and c["canonical"] is None and r["output"] == c["host"]:
        inv_pass[r["ecosystem"]].add((r["library"], r["function"], r["surface"]))

# ---------------------------------------------------------------- table: ecosystems
out.append("\\newcommand{\\tableEcosystems}{%\n\\begin{tabular}{@{}lrrrrrr@{}}\n\\toprule\n"
           "Ecosystem & Libraries & Validator fns & Downstream fns & Pass invisible & Pass mapped & Findings (libs) \\\\\n\\midrule\n")
for eco in ECO_ORDER:
    libs = {r["library"] for r in rows if r["ecosystem"] == eco}
    v = {k for k in validators if k[0] == eco}
    dn = {k for k in downstream if k[0] == eco}
    f_libs = {g["library"] for g in findings if g["ecosystem"] == eco and g["severity"] == "low-moderate"}
    out.append(f"{ECO_NAME[eco]} & {len(libs)} & {len(v)} & {len(dn)} & {len(inv_pass[eco])} & {len(map_pass[eco])} & {len(f_libs)} \\\\\n")
out.append("\\midrule\n")
f_libs_all = len(libs_lm)
out.append(f"Total & {summary['libraries']} & {len(validators)} & {len(downstream)} & {sum(len(s) for s in inv_pass.values())} & {sum(len(s) for s in map_pass.values())} & {f_libs_all} \\\\\n")
out.append("\\bottomrule\n\\end{tabular}}\n")

# ---------------------------------------------------------------- table: corpus
out.append("\\newcommand{\\tableCorpus}{%\n\\begin{tabular}{@{}llr@{}}\n\\toprule\nClass & Subclass & Cases \\\\\n\\midrule\n")
sub = collections.OrderedDict()
for c in corpus["cases"]:
    sub[(c["class"], c["subclass"])] = sub.get((c["class"], c["subclass"]), 0) + 1
last = None
for (cls, s), n in sub.items():
    out.append(f"{cls if cls != last else ''} & {tex(s)} & {n} \\\\\n")
    last = cls
out.append("\\bottomrule\n\\end{tabular}}\n")

# ---------------------------------------------------------------- table: what one input becomes
ZW = "inv-200B-mid"
out.append("\\newcommand{\\tableZwsp}{%\n\\begin{tabular}{@{}lp{0.78\\linewidth}@{}}\n\\toprule\nOutput handed downstream & Components (ecosystem: library) \\\\\n\\midrule\n")
groups = collections.defaultdict(list)
for r in rows:
    if r["case_id"] != ZW:
        continue
    key = "rejected" if not r["accepted"] else r["output"]
    groups[key].append(f"{ECO_NAME[r['ecosystem']]}: {r['library']}")
order = sorted(groups, key=lambda k: (-len(groups[k]), k))
for k in order:
    comps = sorted(set(groups[k]))
    label = "rejected" if k == "rejected" else "\\texttt{" + tex(k.replace("\u200b", "<U+200B>").replace("\ufffd", "<FFFD>")) + "}"
    out.append(f"{label} ({len(groups[k])}) & {tex('; '.join(comps))} \\\\\n")
out.append("\\bottomrule\n\\end{tabular}}\n")

# ---------------------------------------------------------------- table: reference engines
out.append("\\newcommand{\\tableReferences}{%\n\\begin{tabular}{@{}lrrrr@{}}\n\\toprule\nClass & ICU strict & IDNA 2008 & IDNA 2003 & WHATWG \\\\\n\\midrule\n")
for cls in ["invisible", "confusable", "idna", "control"]:
    cs = [c for c in corpus["cases"] if c["class"] == cls]
    out.append(f"{cls} ({len(cs)}) & {sum(c['canonical'] is not None for c in cs)} & {sum(c['idna2008'] is not None for c in cs)} & {sum(c['idna2003'] is not None for c in cs)} & {sum(c['whatwg'] is not None for c in cs)} \\\\\n")
out.append("\\bottomrule\n\\end{tabular}}\n")
n_ref_dis = sum(1 for c in corpus["cases"] if len({c["canonical"], c["idna2008"], c["idna2003"], c["whatwg"]}) > 1)
out.append(num("nRefDisagree", n_ref_dis))
out.append(num("nRefAgree", corpus["counts"]["cases"] - n_ref_dis))

# ---------------------------------------------------------------- table: findings (library level)
ABBR = {"invisible": "I", "mapped-confusable": "M", "whitespace-control": "W", "undecodable-punycode": "P", "length": "L", "bidi": "B", "percent-encoded": "E"}
out.append("\\newcommand{\\tableFindings}{%\n\\begin{tabular}{@{}llllp{0.56\\linewidth}@{}}\n\\toprule\nEcosystem & Library & Version & Severity & Functions (buckets: I invisible, M mapped confusable, W whitespace/control, P undecodable punycode, L length, B bidi, E percent-encoded) \\\\\n\\midrule\n")
lib = collections.OrderedDict()
rank = {"low-moderate": 0, "low": 1, "informational": 2}
for g in findings:
    k = (g["ecosystem"], g["library"], g["version"])
    e = lib.setdefault(k, {"sev": set(), "funcs": collections.OrderedDict()})
    e["sev"].add(g["severity"])
    e["funcs"].setdefault(g["function"].split("(")[0].split("  [")[0].strip(), set()).add(g["bucket"])
for k, e in sorted(lib.items(), key=lambda kv: (min(rank[s] for s in kv[1]["sev"]), ECO_ORDER.index(kv[0][0]), kv[0][1])):
    top = min(e["sev"], key=lambda s: rank[s])
    fns = "; ".join(f"{tex(fn)} ({''.join(sorted(ABBR[x] for x in b))})" for fn, b in e["funcs"].items())
    out.append(f"{ECO_NAME[k[0]]} & {tex(k[1].replace('github.com/', ''))} & {tex(k[2][:14])} & {top} & {fns} \\\\\n")
out.append("\\bottomrule\n\\end{tabular}}\n")

# ---------------------------------------------------------------- acceptance matrix for validators on key subclasses (appendix)
SUBS = [("invisible", "ignored"), ("invisible", "disallowed"), ("invisible", "deviation"), ("confusable", "mapped-to-ascii"),
        ("confusable", "cyrillic"), ("idna", "fullwidth-dot"), ("idna", "whitespace-control"), ("idna", "punycode-decodes-invalid"), ("idna", "label-length")]
out.append("\\newcommand{\\tableMatrix}{%\n\\begin{tabular}{@{}lll" + "r" * len(SUBS) + "@{}}\n\\toprule\n"
           "Ecosystem & Library & Function & " + " & ".join("\\rotatebox{90}{" + tex(s) + "}" for _, s in SUBS) + " \\\\\n\\midrule\n")
tot = {s: sum(1 for c in corpus["cases"] if c["class"] == cl and c["subclass"] == s) for cl, s in SUBS}
seen = []
for r in rows:
    if r["kind"] == "validator":
        k = (r["ecosystem"], r["library"], r["function"], r["surface"])
        if k not in seen:
            seen.append(k)
seen.sort(key=lambda k: (ECO_ORDER.index(k[0]), k[1], k[2]))
acc = collections.Counter()
for r in rows:
    if r["kind"] == "validator" and r["accepted"]:
        c = cases[r["case_id"]]
        acc[(r["ecosystem"], r["library"], r["function"], r["surface"], c["subclass"])] += 1
for k in seen:
    cells = [f"{acc[(k[0], k[1], k[2], k[3], s)]}/{tot[s]}" for _, s in SUBS]
    fn = k[2].split("  [")[0]
    if len(fn) > 44:
        fn = fn[:41] + "..."
    out.append(f"{ECO_NAME[k[0]]} & {tex(k[1].replace('github.com/', '')[:26])} & \\texttt{{{tex(fn)}}} & " + " & ".join(cells) + " \\\\\n")
out.append("\\bottomrule\n\\end{tabular}}\n")

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write("% Generated by paper/make_tables.py. Do not edit.\n" + "".join(out))
print(f"wrote {OUT}")
