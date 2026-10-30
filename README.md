# Validated but not canonical

A cross-ecosystem measurement study of how URL, e-mail-address and hostname
parsers and validators handle three classes of adversarial input:

1. **invisible Unicode format characters** inside a label (U+00AD, U+200B,
   U+200C, U+200D, U+2060, U+FEFF, U+034F, U+061C, U+180E, U+2061–2064,
   U+206A–206F, tag characters U+E0000–E007F);
2. **confusable substitutions** (Cyrillic, Greek and Armenian letters for
   Latin, code points that UTS #46 maps to ASCII such as fullwidth letters,
   the Kelvin sign and long s, and the two confusables whose UTS #39
   prototype is itself non-ASCII, U+0442 and U+03BA);
3. **IDNA edge cases** (Punycode labels that decode to invalid or mixed-script
   strings, labels at the 63-octet limit after encoding, trailing dots,
   upper-case `xn--`, fullwidth dots as label separators, leading and trailing
   whitespace and C0 controls, deviation characters, Bidi rule violations).

The question is not "does the validator accept it?" but **"when a library
reports a hostname valid, is the string it blessed the canonical host, and do
two components in the same ecosystem agree about it?"** A validator that
normalises its input to the canonical form (UTS #46 ToASCII, non-transitional)
is correct and is recorded as safe. A *finding* is a validator that accepts a
string whose output is not canonical while a downstream component in the same
ecosystem, one that handles internationalised names at all, rejects the same
string or resolves it to a different host.

Seven ecosystems: Python, Node.js, Go, Java, Rust, Ruby, PHP.

## Layout

| path | contents |
|---|---|
| `corpus/generate.py` | deterministic generator; writes `corpus/corpus.json` |
| `corpus/corpus.json` | 158 cases with class, subclass, host/URL/e-mail surfaces, canonical form (ICU UTS #46 strict), IDNA 2008, IDNA 2003 and WHATWG reference encodings, UTS #46 status of every non-ASCII code point, UTS #39 skeleton |
| `corpus/data/` | Unicode 18.0 `IdnaMappingTable.txt` and `confusables.txt` used by the generator |
| `harness/SCHEMA.md` | the JSONL row every harness emits |
| `harness/<ecosystem>/run.sh` | one-command reproduction per ecosystem |
| `results/analyze.py` | computes the matrices, disagreement pairs and finding list from `results/raw/*.jsonl` |
| `results/` | generated outputs (see "Publication schedule") |
| `fixes/` | hardening patches per library (held until disclosure completes) |
| `paper/` | bibliography and the script that derives the paper's tables from the results; the paper source itself is withheld until disclosure completes (see below) |

## Reproduce

Each harness performs no network I/O. Resolver-side rows exercise only the
IDNA encoding step a resolver applies before sending a query.

```bash
python3 corpus/generate.py          # needs: pip install idna PyICU (PyICU optional; falls back to idna)
harness/python/run.sh               # Python 3.13, creates harness/python/.venv
harness/node/run.sh                 # Node 22, npm
harness/go/run.sh                   # Go (the module's go.mod selects the toolchain)
harness/java/run.sh                 # Temurin 21 + Maven
harness/rust/run.sh                 # cargo
harness/ruby/run.sh                 # Ruby 3.2 + bundler
harness/php/run.sh                  # PHP 8.5 with intl + Composer
python3 results/analyze.py          # run inside harness/python/.venv so ICU is available
```

Every harness first runs a self-check on the control cases (`example.com`,
`https://example.com/path?q=1`, `user@example.com` must be accepted by every
function; `exa mple.com` must be rejected by every validator) and aborts if a
library fails it. Libraries whose published behaviour legitimately fails a
control (for example a public-suffix matcher that does no syntax checking)
are exempted explicitly and the exemption is printed.

Behind a TLS-inspecting corporate proxy, Maven needs the proxy's CA in a
truststore once (`MAVEN_OPTS=-Djavax.net.ssl.trustStore=...`); the Java
`run.sh` explains the step. Nothing else needs special treatment.

## Definitions used by `results/analyze.py`

* **canonical**: UTS #46 ToASCII with Transitional_Processing=false,
  CheckHyphens, CheckBidi, CheckJoiners, UseSTD3ASCIIRules and VerifyDnsLength
  all on, as implemented by ICU (`corpus.json` records the ICU and Unicode
  versions). `null` means the input has no valid canonical form.
* **outcome** of one (function, case) row: `reject`; `accept-canonical`
  (output equals the canonical A-label byte for byte); `accept-equivalent`
  (output differs but canonicalises to the same host, e.g. a U-label or upper
  case); `accept-noncanon` (output canonicalises to a different host);
  `accept-invalid` (input has no canonical form); `accept-whatwg` (output is
  exactly what the WHATWG URL host parser produces: browser-conformant, never
  a finding).
* **disagreement**: two components in one ecosystem hand different byte
  strings downstream for the same input, or one accepts and one rejects.
* **finding**: a validator row with outcome `accept-noncanon`,
  `accept-invalid`, or `accept-equivalent` on a case whose canonicalisation
  drops or rewrites characters, where the validator passed the raw string
  through and at least one downstream component in the same ecosystem that
  accepts valid IDNs rejects the input or yields a different host. Policy
  differences where the reference implementations themselves disagree
  (hyphen placement, symbols valid under UTS #46 but not IDNA 2008) are
  reported in the matrices but never counted as findings.

## Publication schedule

The corpus, harnesses and analysis code are public now. The generated
results (`results/raw/`, the matrices, the disagreement list and the finding
list), the hardening patches and the paper name the affected libraries, so
they are withheld until each maintainer has responded to the private report
or 90 days have passed, whichever comes first. Everything regenerates from
the commands above in the meantime.

## Disclosure

Findings are reported privately to each project's security contact before
anything is published. Reports describe a parsing inconsistency with a
minimal reproducer showing that two functions disagree; they contain no
exploit chain against any deployment. Weakness classes: CWE-176 (Improper
Handling of Unicode Encoding) and CWE-20 (Improper Input Validation).

## Licence

MIT. Unicode data files in `corpus/data/` are © Unicode, Inc. and distributed
under the Unicode licence (https://www.unicode.org/license.txt).
