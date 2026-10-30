#!/usr/bin/env python3
"""Deterministic corpus generator for "Validated but not canonical".

Writes corpus/corpus.json: one record per case with the host string, the URL
and e-mail surfaces built from it, the class/subclass, and several reference
encodings of the host:

  canonical      UTS #46 ToASCII, Transitional_Processing=false, CheckHyphens,
                 CheckBidi, CheckJoiners, UseSTD3ASCIIRules, VerifyDnsLength
                 (ICU when PyICU is importable, else the `idna` package which
                 implements UTS 46 mapping followed by IDNA 2008 validation).
                 null means "no canonical form: a correct component rejects".
  canonical_engine  which implementation produced `canonical`.
  idna2008       the `idna` package (uts46=True, transitional=False), or null.
  idna2003       Python's legacy `encodings.idna` codec (RFC 3490 nameprep,
                 which is transitional and maps most format characters to
                 nothing), or null.
  whatwg         Node's url.domainToASCII (WHATWG URL host parser: UTS 46 with
                 CheckHyphens=false, VerifyDnsLength=false, UseSTD3=false), or
                 null when node is unavailable or the parse failed.
  uts46_status   UTS 46 status of every non-ASCII or control code point in the
                 host, from corpus/data/IdnaMappingTable.txt.
  skeleton       UTS #39 skeleton of the host from corpus/data/confusables.txt.

Everything is deterministic: no randomness, fixed ordering. Re-running must
produce a byte-identical file given the same reference libraries.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unicodedata
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "corpus.json")

# ----------------------------------------------------------------------------
# Unicode reference data
# ----------------------------------------------------------------------------

def load_idna_table() -> list[tuple[int, int, str, str]]:
    rows = []
    with open(os.path.join(DATA, "IdnaMappingTable.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            f = [x.strip() for x in line.split(";")]
            r = f[0].split("..")
            lo, hi = int(r[0], 16), int(r[-1], 16)
            status = f[1]
            mapping = f[2] if len(f) > 2 else ""
            rows.append((lo, hi, status, mapping))
    return rows


def load_confusables() -> dict[str, str]:
    table = {}
    with open(os.path.join(DATA, "confusables.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            f = [x.strip() for x in line.split(";")]
            if len(f) < 3 or f[2] != "MA":
                continue
            src = "".join(chr(int(c, 16)) for c in f[0].split())
            dst = "".join(chr(int(c, 16)) for c in f[1].split())
            table[src] = dst
    return table


def data_version(name: str) -> str:
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("# Version:"):
                return line.split(":", 1)[1].strip()
    return "unknown"


IDNA_TABLE = load_idna_table()
CONFUSABLES = load_confusables()


def uts46_status(cp: int) -> tuple[str, str]:
    for lo, hi, status, mapping in IDNA_TABLE:
        if lo <= cp <= hi:
            return status, mapping
    return "unassigned", ""


def skeleton(s: str) -> str:
    """UTS #39 section 4 skeleton: NFD, map each char by confusables.txt, NFD."""
    s = unicodedata.normalize("NFD", s)
    s = "".join(CONFUSABLES.get(ch, ch) for ch in s)
    return unicodedata.normalize("NFD", s)


# ----------------------------------------------------------------------------
# Reference encoders
# ----------------------------------------------------------------------------

def ref_idna2008(host: str) -> Optional[str]:
    try:
        import idna
    except ImportError:
        return None
    try:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except Exception:
        return None


def ref_idna2003(host: str) -> Optional[str]:
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return None


_ICU = None


def icu_instance():
    global _ICU
    if _ICU is not None:
        return _ICU
    try:
        import icu  # PyICU
    except ImportError:
        _ICU = False
        return False
    opts = (icu.IDNA.CHECK_NONTRANSITIONAL_TO_ASCII
            | icu.IDNA.CHECK_NONTRANSITIONAL_TO_UNICODE
            | icu.IDNA.CHECK_BIDI
            | icu.IDNA.CHECK_CONTEXTJ
            | icu.IDNA.USE_STD3_RULES)
    _ICU = (icu.IDNA(opts), icu)
    return _ICU


def ref_icu(host: str) -> Optional[str]:
    inst = icu_instance()
    if not inst:
        return None
    uts46, icu = inst
    info = icu.IDNAInfo()
    try:
        out = uts46.nameToASCII(host, info)
    except Exception:
        return None
    if info.errors():
        return None
    return str(out)


def canonical_engine() -> str:
    inst = icu_instance()
    if inst:
        return f"icu-{inst[1].ICU_VERSION}-unicode-{inst[1].UNICODE_VERSION}"
    import idna
    return f"idna-{idna.__version__}-unicode-{idna.idnadata.__version__}"


def ref_canonical(host: str) -> Optional[str]:
    if icu_instance():
        return ref_icu(host)
    return ref_idna2008(host)


def ref_whatwg_batch(hosts: list[str]) -> list[Optional[str]]:
    node = shutil.which("node")
    if not node:
        return [None] * len(hosts)
    script = (
        "const {domainToASCII}=require('node:url');"
        "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{"
        "const out=JSON.parse(d).map(h=>{const r=domainToASCII(h);return r===''?null:r;});"
        "process.stdout.write(JSON.stringify(out));});"
    )
    p = subprocess.run([node, "-e", script], input=json.dumps(hosts).encode("utf-8"),
                       capture_output=True, check=True)
    return json.loads(p.stdout.decode("utf-8"))


def node_version() -> Optional[str]:
    node = shutil.which("node")
    if not node:
        return None
    return subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()


# ----------------------------------------------------------------------------
# Case construction
# ----------------------------------------------------------------------------

CASES: list[dict] = []
SEEN: set[str] = set()


def add(cid: str, cls: str, sub: str, host: str, note: str, *,
        looks_like: Optional[str] = None, surfaces: tuple[str, ...] = ("host", "url", "email"),
        benign_difference: bool = False) -> None:
    assert cid not in SEEN, cid
    SEEN.add(cid)
    CASES.append({
        "id": cid,
        "class": cls,
        "subclass": sub,
        "host": host,
        "note": note,
        "looks_like": looks_like,
        "surfaces": list(surfaces),
        "benign_difference": benign_difference,
    })


def cps(s: str) -> list[str]:
    return [f"U+{ord(c):04X}" for c in s if ord(c) > 0x7E or ord(c) < 0x21]


BASE = "example.com"

# --- controls ---------------------------------------------------------------
add("ctl-good", "control", "known-good", "example.com", "known-good host; every harness must accept")
add("ctl-good-sub", "control", "known-good", "www.example.com", "known-good host with subdomain")
add("ctl-good-idn", "control", "known-good", "bücher.example", "valid IDN label (u-umlaut); canonical is the A-label", looks_like="bucher.example")
add("ctl-good-alabel", "control", "known-good", "xn--bcher-kva.example", "valid A-label for the previous case")
add("ctl-bad-space", "control", "known-bad", "exa mple.com", "known-bad host (interior space); every harness must reject")
add("ctl-bad-at", "control", "known-bad", "exa@mple.com", "known-bad host (interior @); e-mail surface becomes user@exa@mple.com")
add("ctl-single-label", "control", "single-label", "localhost", "single label: valid DNS name, but most validators require a dot", benign_difference=True)
add("ctl-upper", "control", "case", "EXAMPLE.COM", "upper-case ASCII; canonical is lower-case; DNS is case-insensitive", benign_difference=True)
add("ctl-mixed-case", "control", "case", "Example.Com", "mixed-case ASCII", benign_difference=True)
add("ctl-digit-1", "control", "ascii-confusable", "examp1e.com", "ASCII digit 1 for l; valid and canonical; acceptance is correct", looks_like="example.com")
add("ctl-digit-0", "control", "ascii-confusable", "examp1e.c0m", "ASCII digit 0 for o; valid and canonical", looks_like="example.com")
add("ctl-rn", "control", "ascii-confusable", "exarnple.com", "rn for m; valid and canonical", looks_like="example.com")

# --- class 1: invisible format characters -----------------------------------
INVISIBLE = [
    (0x00AD, "SOFT HYPHEN"), (0x200B, "ZERO WIDTH SPACE"), (0x200C, "ZERO WIDTH NON-JOINER"),
    (0x200D, "ZERO WIDTH JOINER"), (0x2060, "WORD JOINER"), (0xFEFF, "ZERO WIDTH NO-BREAK SPACE"),
    (0x034F, "COMBINING GRAPHEME JOINER"), (0x061C, "ARABIC LETTER MARK"), (0x180E, "MONGOLIAN VOWEL SEPARATOR"),
    (0x2061, "FUNCTION APPLICATION"), (0x2062, "INVISIBLE TIMES"), (0x2063, "INVISIBLE SEPARATOR"),
    (0x2064, "INVISIBLE PLUS"), (0x206A, "INHIBIT SYMMETRIC SWAPPING"), (0x206B, "ACTIVATE SYMMETRIC SWAPPING"),
    (0x206C, "INHIBIT ARABIC FORM SHAPING"), (0x206D, "ACTIVATE ARABIC FORM SHAPING"),
    (0x206E, "NATIONAL DIGIT SHAPES"), (0x206F, "NOMINAL DIGIT SHAPES"),
    (0xE0001, "LANGUAGE TAG"), (0xE0020, "TAG SPACE"), (0xE0041, "TAG LATIN CAPITAL LETTER A"),
    (0xE007F, "CANCEL TAG"),
]
HEADLINE = {0x00AD, 0x200B, 0x200D, 0x2060, 0xFEFF, 0xE0041}
POSITIONS = {
    "mid": lambda c: f"exam{c}ple.com",
    "start": lambda c: f"{c}example.com",
    "end": lambda c: f"example{c}.com",
    "tld": lambda c: f"example.c{c}om",
}
for cp, name in INVISIBLE:
    c = chr(cp)
    status, _ = uts46_status(cp)
    positions = ["mid", "start"] + (["end", "tld"] if cp in HEADLINE else [])
    for pos in positions:
        add(f"inv-{cp:04X}-{pos}", "invisible", status, POSITIONS[pos](c),
            f"U+{cp:04X} {name} ({status} in UTS 46) at label {pos}", looks_like=BASE)
add("inv-double", "invisible", "ignored", "ex­am​ple.com",
    "two different ignored characters in one label", looks_like=BASE)
add("inv-200B-x3", "invisible", "ignored", "e​x​a​mple.com",
    "three zero-width spaces in one label", looks_like=BASE)
add("inv-200C-valid-ctx", "invisible", "deviation",
    "نامه‌ای.example.com",
    "ZWNJ in a valid CONTEXTJ position (Persian); canonical keeps it (non-transitional)")
add("inv-200D-valid-ctx", "invisible", "deviation",
    "क्‍ष.example.com",
    "ZWJ after virama (Devanagari): valid CONTEXTJ; canonical keeps it")

# --- class 2: confusables ---------------------------------------------------
# 2a: code points UTS 46 *maps* to ASCII. Canonical is the ASCII host, so a
# validator that accepts without normalising returns a non-canonical string
# that a UTS 46 component collapses to the ASCII domain.
MAPPED = [
    ("ff45-e", "ｅxample.com", "FULLWIDTH LATIN SMALL LETTER E for e"),
    ("ff-whole", "ｅｘａｍｐｌｅ.com", "whole label in fullwidth Latin"),
    ("1d41e-e", "\U0001d41example.com", "MATHEMATICAL BOLD SMALL E for e"),
    ("1d5be-e", "\U0001d5bexample.com", "MATHEMATICAL SANS-SERIF SMALL E for e"),
    ("212a-k", "Keep.example.com", "KELVIN SIGN for k"),
    ("017f-s", "ſample.example.com", "LATIN SMALL LETTER LONG S for s"),
    ("2102-c", "ℂode.example.com", "DOUBLE-STRUCK CAPITAL C maps to c"),
    ("2460-1", "examp①e.com", "CIRCLED DIGIT ONE maps to 1 (so looks like examp1e)"),
    ("ff10-0", "examp1e.c０m", "FULLWIDTH DIGIT ZERO maps to 0"),
    ("00aa-a", "exªmple.com", "FEMININE ORDINAL INDICATOR maps to a"),
    ("2113-l", "exampℓe.com", "SCRIPT SMALL L maps to l"),
    ("ff0d-hyphen", "exam－ple.com", "FULLWIDTH HYPHEN-MINUS maps to -"),
]
for key, host, note in MAPPED:
    add(f"cfs-mapped-{key}", "confusable", "mapped-to-ascii", host, note, looks_like=skeleton(host))

# 2b: mapped to non-ASCII (still an IDN after mapping)
add("cfs-mapped-212b", "confusable", "mapped-to-nonascii", "Ångstrom.example.com", "ANGSTROM SIGN maps to a-ring (U+00E5)")
add("cfs-mapped-0130", "confusable", "mapped-to-nonascii", "İnfo.example.com", "CAPITAL I WITH DOT ABOVE maps to i + U+0307")

# 2c: valid confusable letters from Cyrillic, Greek, Armenian (single and whole-label)
CYR = [("0430", "exаmple.com", "CYRILLIC SMALL A for a"), ("0435", "еxample.com", "CYRILLIC SMALL IE for e"),
       ("043e", "example.cоm", "CYRILLIC SMALL O for o (in TLD label)"), ("0440", "examрle.com", "CYRILLIC SMALL ER for p"),
       ("0441", "example.сom", "CYRILLIC SMALL ES for c (in TLD label)"), ("0445", "eхample.com", "CYRILLIC SMALL HA for x"),
       ("whole", "соре.example.com", "whole-Cyrillic label that reads cope")]
for key, host, note in CYR:
    add(f"cfs-cyr-{key}", "confusable", "cyrillic", host, note, looks_like=skeleton(host))
GRK = [("03bf", "example.cοm", "GREEK SMALL OMICRON for o"), ("03b1", "exαmple.com", "GREEK SMALL ALPHA for a"),
       ("03c1", "examρle.com", "GREEK SMALL RHO for p")]
for key, host, note in GRK:
    add(f"cfs-grk-{key}", "confusable", "greek", host, note, looks_like=skeleton(host))
ARM = [("0585", "example.cօm", "ARMENIAN SMALL OH for o"), ("0578", "ոote.example.com", "ARMENIAN SMALL VO for n"),
       ("0570", "հome.example.com", "ARMENIAN SMALL HO for h"), ("057d", "սser.example.com", "ARMENIAN SMALL SEH for u")]
for key, host, note in ARM:
    add(f"cfs-arm-{key}", "confusable", "armenian", host, note, looks_like=skeleton(host))

# 2d: confusables whose UTS #39 prototype is itself non-ASCII
add("cfs-proto-0442", "confusable", "nonascii-prototype", "тest.example.com", "CYRILLIC SMALL TE; prototype is U+1D1B, not t", looks_like=skeleton("тest.example.com"))
add("cfs-proto-1d1b", "confusable", "nonascii-prototype", "ᴛest.example.com", "LATIN LETTER SMALL CAPITAL T (the prototype itself)", looks_like=skeleton("ᴛest.example.com"))
add("cfs-proto-03ba", "confusable", "nonascii-prototype", "κeep.example.com", "GREEK SMALL KAPPA; prototype is U+0138 kra, not k", looks_like=skeleton("κeep.example.com"))
add("cfs-proto-0138", "confusable", "nonascii-prototype", "ĸeep.example.com", "LATIN SMALL LETTER KRA (the prototype itself)", looks_like=skeleton("ĸeep.example.com"))
add("cfs-0131-l", "confusable", "latin-valid", "exampıe.com", "DOTLESS I for l; valid, not mapped", looks_like=skeleton("exampıe.com"))

# --- class 3: IDNA edge cases -----------------------------------------------
def puny(label: str) -> str:
    return "xn--" + label.encode("punycode").decode("ascii")

add("idn-pny-mixed-cyr", "idna", "punycode-mixed-script", puny("exаmple") + ".com", "valid A-label that decodes to Latin + Cyrillic a")
add("idn-pny-invisible", "idna", "punycode-decodes-invalid", puny("exam​ple") + ".com", "A-label whose decoded form contains U+200B (ignored): invalid")
add("idn-pny-tag", "idna", "punycode-decodes-invalid", puny("exam\U000e0041ple") + ".com", "A-label whose decoded form contains a tag character (disallowed)")
add("idn-pny-upper-inside", "idna", "punycode-decodes-invalid", puny("Exаmple") + ".com", "A-label whose decoded form has an upper-case letter: not in canonical form")
add("idn-pny-dot-inside", "idna", "punycode-decodes-invalid", puny("example。com") + ".test", "A-label whose decoded form contains an ideographic full stop")
add("idn-pny-ascii-only", "idna", "punycode-ascii-only", "xn--example-.com", "A-label that decodes to pure ASCII: not permitted")
add("idn-pny-empty", "idna", "punycode-invalid", "xn--.com", "xn-- with nothing after it")
add("idn-pny-garbage", "idna", "punycode-invalid", "xn--zzzzzzzzzzzzzzzzzzzzzzzz.com", "xn-- with input that is not valid Punycode output")
add("idn-pny-upper-prefix", "idna", "punycode-case", "XN--BCHER-KVA.example", "upper-case XN-- prefix; canonical is lower-case", benign_difference=True)
add("idn-pny-mixed-prefix", "idna", "punycode-case", "Xn--bcher-kva.example", "mixed-case Xn-- prefix", benign_difference=True)

# length
add("idn-len-63", "idna", "label-length", "a" * 63 + ".example.com", "63-octet label: valid")
add("idn-len-64", "idna", "label-length", "a" * 64 + ".example.com", "64-octet label: invalid")


def search_puny_len(target: int) -> str:
    # label of repeated u-umlaut plus trailing ASCII so punycode grows slowly
    for n in range(1, 60):
        for tail in range(0, 40):
            lab = "ü" * n + "a" * tail
            if len(puny(lab)) == target:
                return lab
    raise RuntimeError("no label found")


lab63 = search_puny_len(63)
lab64 = search_puny_len(64)
add("idn-len-u63", "idna", "label-length", lab63 + ".example.com", f"U-label whose A-label is exactly 63 octets ({len(lab63)} code points): valid")
add("idn-len-u64", "idna", "label-length", lab64 + ".example.com", f"U-label of {len(lab64)} code points whose A-label is 64 octets: invalid under VerifyDnsLength; WHATWG does not check length")
add("idn-len-253", "idna", "name-length", ".".join(["a" * 63] * 3 + ["b" * 61]), "253-octet name: valid")
add("idn-len-254", "idna", "name-length", ".".join(["a" * 63] * 3 + ["b" * 62]), "254-octet name: invalid")

# separators
add("idn-sep-3002", "idna", "fullwidth-dot", "example。com", "IDEOGRAPHIC FULL STOP as label separator (mapped to .)", looks_like=BASE)
add("idn-sep-ff0e", "idna", "fullwidth-dot", "example．com", "FULLWIDTH FULL STOP as separator", looks_like=BASE)
add("idn-sep-ff61", "idna", "fullwidth-dot", "example｡com", "HALFWIDTH IDEOGRAPHIC FULL STOP as separator", looks_like=BASE)
add("idn-sep-3002-sub", "idna", "fullwidth-dot", "www。example.com", "IDEOGRAPHIC FULL STOP between subdomain and domain", looks_like="www.example.com")
add("idn-dot-trailing", "idna", "dots", "example.com.", "trailing dot (root label); canonical keeps it", benign_difference=True)
add("idn-dot-trailing2", "idna", "dots", "example.com..", "two trailing dots: empty label, invalid")
add("idn-dot-leading", "idna", "dots", ".example.com", "leading dot: empty label, invalid")
add("idn-dot-double", "idna", "dots", "example..com", "empty interior label, invalid")

# whitespace and controls
WS = [("sp-lead", " example.com", "leading space"), ("sp-trail", "example.com ", "trailing space"),
      ("tab-lead", "\texample.com", "leading tab"), ("nl-trail", "example.com\n", "trailing newline"),
      ("cr-trail", "example.com\r", "trailing carriage return"), ("tab-mid", "exam\tple.com", "interior tab (WHATWG strips tabs and newlines anywhere)"),
      ("nl-mid", "exam\nple.com", "interior newline"), ("cr-mid", "exam\rple.com", "interior carriage return"),
      ("c0-01-mid", "exam\x01ple.com", "interior U+0001"), ("del-mid", "exam\x7fple.com", "interior DELETE"),
      ("nul-trail", "example.com\x00", "trailing NUL"), ("nbsp-lead", " example.com", "leading NO-BREAK SPACE (mapped to space, disallowed under STD3)"),
      ("vt-lead", "\x0bexample.com", "leading vertical tab"), ("ff-lead", "\x0cexample.com", "leading form feed")]
for key, host, note in WS:
    add(f"idn-ws-{key}", "idna", "whitespace-control", host, note, looks_like=BASE)

# hyphens
add("idn-hy-lead", "idna", "hyphen", "-example.com", "leading hyphen: CheckHyphens fails; WHATWG allows")
add("idn-hy-trail", "idna", "hyphen", "example-.com", "trailing hyphen: CheckHyphens fails; WHATWG allows")
add("idn-hy-34", "idna", "hyphen", "ex--ample.com", "hyphens in positions 3-4 without xn: CheckHyphens fails; WHATWG allows")

# deviation / transitional
add("idn-dev-sharp-s", "idna", "deviation", "faß.example.com", "LATIN SMALL SHARP S: non-transitional keeps it (xn--fa-hia); transitional maps to fass")
add("idn-dev-final-sigma", "idna", "deviation", "βόλος.example.com", "GREEK SMALL FINAL SIGMA: non-transitional keeps it; transitional maps to sigma")

# IDNA 2003 vs 2008 symbols
add("idn-sym-snowman", "idna", "symbol", "☃.example.com", "SNOWMAN: valid in UTS 46 (NV8), disallowed by IDNA 2008")
add("idn-sym-emoji", "idna", "symbol", "\U0001f600.example.com", "GRINNING FACE emoji")
add("idn-sym-heart", "idna", "symbol", "❤.example.com", "HEAVY BLACK HEART")

# bidi
add("idn-bidi-rtl", "idna", "bidi", "אב.example.com", "Hebrew label: valid RTL label")
add("idn-bidi-rtl-digit-end", "idna", "bidi", "אב1.example.com", "Hebrew label ending in a European digit: valid")
add("idn-bidi-digit-first", "idna", "bidi", "1א.example.com", "digit before Hebrew: Bidi rule 1 fails")

# URL-only edge cases (host surface is still recorded; email surface omitted)
add("idn-url-pct-host", "idna", "percent-encoded", "exa%6dple.com", "percent-encoded letter in host; WHATWG decodes to example.com", looks_like=BASE, surfaces=("host", "url"))
add("idn-url-pct-zwsp", "idna", "percent-encoded", "exam%E2%80%8Bple.com", "percent-encoded U+200B in host; WHATWG decodes then applies UTS 46", looks_like=BASE, surfaces=("host", "url"))

# ----------------------------------------------------------------------------
# Surfaces and references
# ----------------------------------------------------------------------------

def build() -> dict:
    hosts = [c["host"] for c in CASES]
    whatwg = ref_whatwg_batch(hosts)
    for c, w in zip(CASES, whatwg):
        h = c["host"]
        c["url"] = f"https://{h}/path?q=1"
        c["email"] = f"user@{h}"
        c["codepoints"] = cps(h)
        c["uts46_status"] = sorted({f"U+{ord(ch):04X}:{uts46_status(ord(ch))[0]}" for ch in h if ord(ch) > 0x7E or ord(ch) < 0x21})
        c["skeleton"] = skeleton(h)
        c["canonical"] = ref_canonical(h)
        c["idna2008"] = ref_idna2008(h)
        c["idna2003"] = ref_idna2003(h)
        c["whatwg"] = w
        c["expected"] = "reject" if c["canonical"] is None else "accept"
    classes = {}
    for c in CASES:
        classes[c["class"]] = classes.get(c["class"], 0) + 1
    return {
        "name": "validated-not-canonical corpus",
        "version": "1.0.0",
        "canonical_definition": "UTS #46 ToASCII, Transitional_Processing=false, CheckHyphens=true, CheckBidi=true, CheckJoiners=true, UseSTD3ASCIIRules=true, VerifyDnsLength=true",
        "canonical_engine": canonical_engine(),
        "whatwg_engine": f"node {node_version()} url.domainToASCII" if node_version() else None,
        "unicode_data": {
            "IdnaMappingTable.txt": data_version("IdnaMappingTable.txt"),
            "confusables.txt": data_version("confusables.txt"),
        },
        "python": sys.version.split()[0],
        "counts": {"cases": len(CASES), "by_class": classes},
        "cases": CASES,
    }


if __name__ == "__main__":
    doc = build()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=True, indent=1, sort_keys=False)
        fh.write("\n")
    print(f"wrote {OUT}: {doc['counts']}  engine={doc['canonical_engine']}")
