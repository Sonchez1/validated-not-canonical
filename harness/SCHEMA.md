# Harness output schema

Every harness (`harness/<ecosystem>/run.*`) reads `corpus/corpus.json` and
writes `results/raw/<ecosystem>.jsonl`: one JSON object per line, one line per
(library, function, case, surface). Field order does not matter. Strings are
JSON strings with non-ASCII escaped (`\uXXXX`) so the files are safe to diff.

| field | type | meaning |
|---|---|---|
| `ecosystem` | string | `python`, `node`, `go`, `java`, `rust`, `ruby`, `php` |
| `runtime` | string | runtime version, e.g. `3.13.1`, `v22.12.0`, `go1.23.6` |
| `library` | string | package name as published (`validators`, `zod`, `golang.org/x/net/idna`, `stdlib`) |
| `version` | string | installed version of that package (`stdlib` uses the runtime version) |
| `function` | string | the API called, e.g. `validators.domain`, `URL(...).hostname`, `idn_to_ascii` |
| `surface` | string | `host`, `url` or `email`: which corpus surface was passed in |
| `case_id` | string | corpus case id |
| `input` | string | the exact string passed to the function |
| `accepted` | bool | `true` if the function reported the input valid / parsed without error |
| `output` | string or null | the host the function hands downstream, byte-for-byte. For a parser: the parsed host. For a boolean validator: the input host (it blesses the string as-is). For a normalising validator: the normalised host. For an e-mail function: the domain part of the accepted address. `null` when rejected. |
| `output_kind` | string | `parsed`, `passthrough`, `normalized`, or `rejected` |
| `error` | string or null | exception class and message (first 200 chars) when rejected |
| `kind` | string | `validator` (an API an application calls to decide whether to accept input) or `downstream` (a parser, encoder, HTTP client, resolver step or public-suffix splitter that consumes the accepted string) |

## Self-check

Before writing results each harness runs the controls and aborts if any fails:

* `ctl-good` (`example.com`, `https://example.com/path?q=1`, `user@example.com`) must be accepted by every function on its surface.
* `ctl-bad-space` (`exa mple.com`) must be rejected by every *validator* on the host and email surfaces. URL parsers are exempt from the self-check on this case (several accept and percent-encode) but their result is still recorded.

A harness that cannot load a library writes no lines for it and prints a
`SKIP <library>: <reason>` line to stderr so the omission is visible.

## Downstream components

Each ecosystem also records at least one *downstream* component that consumes
a host after validation: the URL parser the HTTP client uses, the IDNA encoder
the resolver uses, or the HTTP client's request preparation. These rows use
the same schema and let `results/analyze.py` compute disagreement pairs. No
harness performs network I/O: resolver rows exercise the encoding step only.
