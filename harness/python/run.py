#!/usr/bin/env python3
"""Python harness: runs every corpus case through each library and writes
results/raw/python.jsonl following harness/SCHEMA.md.

Usage:  harness/python/run.sh        (creates the venv, installs, runs)
        python harness/python/run.py [--out PATH]

No network I/O is performed. Resolver-side rows exercise only the IDNA
encoding step that CPython's socket module and dnspython apply to a hostname
before any query is sent; see check_socket_uses_idna_codec().
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import platform
import sys
import traceback
from typing import Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "corpus", "corpus.json")
DEFAULT_OUT = os.path.join(ROOT, "results", "raw", "python.jsonl")

Result = tuple[bool, Optional[str], str, Optional[str]]  # accepted, output, kind, error


def ok(output: str, kind: str) -> Result:
    return True, output, kind, None


def rejected(exc: BaseException) -> Result:
    msg = f"{type(exc).__name__}: {exc}"
    return False, None, "rejected", msg[:200]


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1] if "@" in addr else addr


def raw_host(u: str) -> str:
    """Host of a URL string without parsing or normalising it: the authority
    up to the first / ? #, minus userinfo and port."""
    import re
    a = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", u).split("/")[0].split("?")[0].split("#")[0]
    a = a.rsplit("@", 1)[-1]
    return re.sub(r":\d*$", "", a)


def version_of(dist: str) -> str:
    try:
        return md.version(dist)
    except md.PackageNotFoundError:
        return "unknown"


class Adapter:
    def __init__(self, library: str, version: str, function: str, surface: str,
                 kind: str, fn: Callable[[str, dict], Result]):
        self.library, self.version, self.function, self.surface, self.kind, self.fn = (
            library, version, function, surface, kind, fn)


ADAPTERS: list[Adapter] = []
SKIPPED: list[str] = []


def adapter(library, version, function, surface, kind):
    def deco(fn):
        ADAPTERS.append(Adapter(library, version, function, surface, kind, fn))
        return fn
    return deco


def guarded(fn):
    """Turn any exception into a rejection record."""
    def wrapper(value: str, case: dict) -> Result:
        try:
            return fn(value, case)
        except Exception as exc:  # noqa: BLE001 - we record every failure mode
            return rejected(exc)
    return wrapper


PYVER = platform.python_version()

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
from urllib.parse import urlsplit  # noqa: E402


@adapter("stdlib", PYVER, "urllib.parse.urlsplit(url).hostname", "url", "parser")
@guarded
def py_urlsplit(value, case):
    h = urlsplit(value).hostname
    if h is None:
        return rejected(ValueError("no hostname"))
    return ok(h, "parsed")


@adapter("stdlib", PYVER, "str.encode('idna')  [encodings.idna, RFC 3490; used by socket.getaddrinfo]", "host", "encoder")
@guarded
def py_idna_codec(value, case):
    return ok(value.encode("idna").decode("ascii"), "normalized")


import email.utils  # noqa: E402
import email.headerregistry  # noqa: E402


@adapter("stdlib", PYVER, "email.utils.parseaddr(addr)[1]", "email", "parser")
@guarded
def py_parseaddr(value, case):
    name, addr = email.utils.parseaddr(value, strict=True)
    if not addr or "@" not in addr:
        return rejected(ValueError(f"parseaddr returned {addr!r}"))
    return ok(domain_of(addr), "parsed")


@adapter("stdlib", PYVER, "email.headerregistry.Address(addr_spec=addr).domain", "email", "parser")
@guarded
def py_headerregistry(value, case):
    a = email.headerregistry.Address(addr_spec=value)
    if not a.domain:
        return rejected(ValueError("empty domain"))
    return ok(a.domain, "parsed")


# ---------------------------------------------------------------------------
# idna
# ---------------------------------------------------------------------------
try:
    import idna

    @adapter("idna", idna.__version__, "idna.encode(host)  [IDNA 2008, no UTS 46 mapping]", "host", "encoder")
    @guarded
    def idna_strict(value, case):
        return ok(idna.encode(value).decode("ascii"), "normalized")

    @adapter("idna", idna.__version__, "idna.encode(host, uts46=True)", "host", "encoder")
    @guarded
    def idna_uts46(value, case):
        return ok(idna.encode(value, uts46=True).decode("ascii"), "normalized")
except ImportError as e:
    SKIPPED.append(f"idna: {e}")

# ---------------------------------------------------------------------------
# validators (python-validators)
# ---------------------------------------------------------------------------
try:
    import validators

    _vv = version_of("validators")

    def _bool_validator(fn):
        def inner(value, case):
            r = fn(value)
            if r is True:
                return ok(case["host"], "passthrough")
            return False, None, "rejected", f"{type(r).__name__}: {r}"[:200]
        return inner

    adapter("validators", _vv, "validators.domain(host)", "host", "validator")(guarded(_bool_validator(validators.domain)))
    adapter("validators", _vv, "validators.hostname(host)", "host", "validator")(guarded(_bool_validator(validators.hostname)))
    adapter("validators", _vv, "validators.url(url)", "url", "validator")(guarded(_bool_validator(validators.url)))
    adapter("validators", _vv, "validators.email(addr)", "email", "validator")(guarded(_bool_validator(validators.email)))
except ImportError as e:
    SKIPPED.append(f"validators: {e}")

# ---------------------------------------------------------------------------
# email-validator
# ---------------------------------------------------------------------------
try:
    import email_validator

    @adapter("email-validator", version_of("email-validator"),
             "email_validator.validate_email(addr, check_deliverability=False).normalized", "email", "validator")
    @guarded
    def ev(value, case):
        r = email_validator.validate_email(value, check_deliverability=False)
        return ok(domain_of(r.normalized), "normalized")
except ImportError as e:
    SKIPPED.append(f"email-validator: {e}")

# ---------------------------------------------------------------------------
# pydantic
# ---------------------------------------------------------------------------
try:
    import pydantic

    _pv = pydantic.__version__

    class _HttpModel(pydantic.BaseModel):
        u: pydantic.HttpUrl

    class _AnyModel(pydantic.BaseModel):
        u: pydantic.AnyUrl

    class _EmailModel(pydantic.BaseModel):
        e: pydantic.EmailStr

    @adapter("pydantic", _pv, "HttpUrl(url).host", "url", "validator")
    @guarded
    def pyd_http(value, case):
        return ok(_HttpModel(u=value).u.host, "normalized")

    @adapter("pydantic", _pv, "AnyUrl(url).host", "url", "validator")
    @guarded
    def pyd_any(value, case):
        return ok(_AnyModel(u=value).u.host, "normalized")

    @adapter("pydantic", _pv, "EmailStr(addr)", "email", "validator")
    @guarded
    def pyd_email(value, case):
        return ok(domain_of(_EmailModel(e=value).e), "normalized")
except ImportError as e:
    SKIPPED.append(f"pydantic: {e}")

# ---------------------------------------------------------------------------
# marshmallow
# ---------------------------------------------------------------------------
try:
    import marshmallow
    from marshmallow import validate as mm_validate

    _mv = version_of("marshmallow")

    @adapter("marshmallow", _mv, "marshmallow.validate.Email()(addr)", "email", "validator")
    @guarded
    def mm_email(value, case):
        return ok(domain_of(mm_validate.Email()(value)), "passthrough")

    @adapter("marshmallow", _mv, "marshmallow.validate.URL()(url)", "url", "validator")
    @guarded
    def mm_url(value, case):
        return ok(raw_host(mm_validate.URL()(value)), "passthrough")
except ImportError as e:
    SKIPPED.append(f"marshmallow: {e}")

# ---------------------------------------------------------------------------
# WTForms
# ---------------------------------------------------------------------------
try:
    import wtforms
    from wtforms import validators as wtv

    _wv = wtforms.__version__

    class _Field:
        def __init__(self, data):
            self.data = data
            self.gettext = lambda s: s
            self.ngettext = lambda s, p, n: s

    @adapter("wtforms", _wv, "wtforms.validators.URL()(form, field)", "url", "validator")
    @guarded
    def wt_url(value, case):
        f = _Field(value)
        wtv.URL()(None, f)
        return ok(raw_host(f.data), "passthrough")

    @adapter("wtforms", _wv, "wtforms.validators.Email()(form, field)", "email", "validator")
    @guarded
    def wt_email(value, case):
        f = _Field(value)
        wtv.Email()(None, f)
        return ok(domain_of(f.data), "passthrough")

    @adapter("wtforms", _wv, "wtforms.validators.HostnameValidation(require_tld=True)(host)", "host", "validator")
    @guarded
    def wt_host(value, case):
        if wtv.HostnameValidation(require_tld=True)(value):
            return ok(case["host"], "passthrough")
        return rejected(ValueError("HostnameValidation returned False"))
except ImportError as e:
    SKIPPED.append(f"wtforms: {e}")

# ---------------------------------------------------------------------------
# voluptuous
# ---------------------------------------------------------------------------
try:
    import voluptuous

    _vov = version_of("voluptuous")

    @adapter("voluptuous", _vov, "voluptuous.Url()(url)", "url", "validator")
    @guarded
    def vo_url(value, case):
        return ok(raw_host(voluptuous.Url()(value)), "passthrough")

    @adapter("voluptuous", _vov, "voluptuous.FqdnUrl()(url)", "url", "validator")
    @guarded
    def vo_fqdn(value, case):
        return ok(raw_host(voluptuous.FqdnUrl()(value)), "passthrough")

    @adapter("voluptuous", _vov, "voluptuous.Email()(addr)", "email", "validator")
    @guarded
    def vo_email(value, case):
        return ok(domain_of(voluptuous.Email()(value)), "passthrough")
except ImportError as e:
    SKIPPED.append(f"voluptuous: {e}")

# ---------------------------------------------------------------------------
# FormEncode
# ---------------------------------------------------------------------------
try:
    import formencode.validators as fv

    _fv = version_of("FormEncode")

    @adapter("formencode", _fv, "formencode.validators.Email().to_python(addr)", "email", "validator")
    @guarded
    def fe_email(value, case):
        return ok(domain_of(fv.Email().to_python(value)), "passthrough")

    @adapter("formencode", _fv, "formencode.validators.URL().to_python(url)", "url", "validator")
    @guarded
    def fe_url(value, case):
        out = fv.URL().to_python(value)
        return ok(raw_host(out), "normalized" if out != value else "passthrough")
except ImportError as e:
    SKIPPED.append(f"formencode: {e}")

# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------
try:
    import django
    from django.conf import settings as dj_settings

    if not dj_settings.configured:
        dj_settings.configure(USE_I18N=False)
    django.setup()
    from django.core import validators as djv

    _dv = django.get_version()

    @adapter("django", _dv, "django.core.validators.URLValidator()(url)", "url", "validator")
    @guarded
    def dj_url(value, case):
        djv.URLValidator()(value)
        return ok(case["host"], "passthrough")

    @adapter("django", _dv, "django.core.validators.EmailValidator()(addr)", "email", "validator")
    @guarded
    def dj_email(value, case):
        djv.EmailValidator()(value)
        return ok(domain_of(value), "passthrough")

    if hasattr(djv, "DomainNameValidator"):
        @adapter("django", _dv, "django.core.validators.DomainNameValidator()(host)", "host", "validator")
        @guarded
        def dj_domain(value, case):
            djv.DomainNameValidator()(value)
            return ok(case["host"], "passthrough")
except Exception as e:  # noqa: BLE001
    SKIPPED.append(f"django: {e}")

# ---------------------------------------------------------------------------
# HTTP clients and URL libraries (downstream components)
# ---------------------------------------------------------------------------
try:
    import requests

    @adapter("requests", requests.__version__, "requests.Request('GET', url).prepare().url  [host of prepared URL]", "url", "parser")
    @guarded
    def rq_prepare(value, case):
        p = requests.Request("GET", value).prepare()
        h = urlsplit(p.url).hostname
        return ok(h, "normalized")
except ImportError as e:
    SKIPPED.append(f"requests: {e}")

try:
    import urllib3
    from urllib3.util import parse_url

    @adapter("urllib3", urllib3.__version__, "urllib3.util.parse_url(url).host", "url", "parser")
    @guarded
    def u3_parse(value, case):
        h = parse_url(value).host
        if h is None:
            return rejected(ValueError("no host"))
        return ok(h, "normalized")
except ImportError as e:
    SKIPPED.append(f"urllib3: {e}")

try:
    import hyperlink

    @adapter("hyperlink", version_of("hyperlink"), "hyperlink.URL.from_text(url).host", "url", "parser")
    @guarded
    def hl_parse(value, case):
        return ok(hyperlink.URL.from_text(value).host, "parsed")
except ImportError as e:
    SKIPPED.append(f"hyperlink: {e}")

try:
    import yarl

    @adapter("yarl", yarl.__version__, "yarl.URL(url).host", "url", "parser")
    @guarded
    def yarl_parse(value, case):
        h = yarl.URL(value).host
        if h is None:
            return rejected(ValueError("no host"))
        return ok(h, "normalized")
except ImportError as e:
    SKIPPED.append(f"yarl: {e}")

try:
    import rfc3986

    @adapter("rfc3986", rfc3986.__version__, "rfc3986.uri_reference(url).host  [+ validator requires host]", "url", "parser")
    @guarded
    def rfc_parse(value, case):
        ref = rfc3986.uri_reference(value)
        rfc3986.validators.Validator().require_presence_of("scheme", "host").check_validity_of("host").validate(ref)
        return ok(ref.host, "parsed")
except ImportError as e:
    SKIPPED.append(f"rfc3986: {e}")

try:
    import furl

    @adapter("furl", version_of("furl"), "furl.furl(url).host", "url", "parser")
    @guarded
    def furl_parse(value, case):
        h = furl.furl(value).host
        if not h:
            return rejected(ValueError("no host"))
        return ok(h, "parsed")
except ImportError as e:
    SKIPPED.append(f"furl: {e}")

try:
    import tldextract

    _tx = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

    @adapter("tldextract", version_of("tldextract"), "tldextract.extract(host).fqdn  [offline snapshot]", "host", "parser")
    @guarded
    def tld_parse(value, case):
        r = _tx(value)
        if not r.fqdn:
            return rejected(ValueError(f"no fqdn (suffix={r.suffix!r}, domain={r.domain!r})"))
        return ok(r.fqdn, "parsed")
except ImportError as e:
    SKIPPED.append(f"tldextract: {e}")

try:
    import dns.name
    import dns.version

    @adapter("dnspython", dns.version.version, "dns.name.from_text(host).to_text()  [name the resolver would query]", "host", "encoder")
    @guarded
    def dns_name(value, case):
        return ok(dns.name.from_text(value).to_text(omit_final_dot=True), "normalized")

    @adapter("dnspython", dns.version.version, "dns.name.from_text(host, idna_codec=dns.name.IDNA_2008_UTS_46).to_text()", "host", "encoder")
    @guarded
    def dns_name_2008(value, case):
        return ok(dns.name.from_text(value, idna_codec=dns.name.IDNA_2008_UTS_46).to_text(omit_final_dot=True), "normalized")
except ImportError as e:
    SKIPPED.append(f"dnspython: {e}")


# ---------------------------------------------------------------------------
# Offline check that socket.getaddrinfo applies the 'idna' codec first
# ---------------------------------------------------------------------------
def check_socket_uses_idna_codec() -> str:
    """A 64-octet label fails inside the idna codec before any network I/O.
    If getaddrinfo raises UnicodeError (not gaierror) for it, the codec runs
    first, so the resolver sees the codec's output for every other case too."""
    import socket
    try:
        socket.getaddrinfo("a" * 64 + ".invalid", 80)
    except UnicodeError as exc:
        return f"confirmed: socket.getaddrinfo raised {type(exc).__name__}: {exc}"
    except socket.gaierror as exc:
        return f"NOT confirmed: gaierror reached the resolver: {exc}"
    return "NOT confirmed: no error"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(out_path: str) -> None:
    with open(CORPUS, encoding="utf-8") as fh:
        corpus = json.load(fh)
    cases = corpus["cases"]
    by_id = {c["id"]: c for c in cases}

    # self-check
    good, bad = by_id["ctl-good"], by_id["ctl-bad-space"]
    failures = []
    for a in ADAPTERS:
        acc, out, kind, err = a.fn(good[a.surface], good)
        if not acc:
            failures.append(f"{a.library} {a.function}: rejected known-good {good[a.surface]!r}: {err}")
        if a.kind == "validator" and a.surface in ("host", "email"):
            acc, out, kind, err = a.fn(bad[a.surface], bad)
            if acc:
                failures.append(f"{a.library} {a.function}: accepted known-bad {bad[a.surface]!r}")
    if failures:
        print("SELF-CHECK FAILED:", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        sys.exit(2)

    print(check_socket_uses_idna_codec(), file=sys.stderr)
    for s in SKIPPED:
        print("SKIP " + s, file=sys.stderr)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    n = 0
    with open(out_path, "w", encoding="utf-8") as fh:
        for a in ADAPTERS:
            for c in cases:
                if a.surface not in c["surfaces"]:
                    continue
                value = c[a.surface]
                acc, out, kind, err = a.fn(value, c)
                rec = {
                    "ecosystem": "python", "runtime": PYVER,
                    "library": a.library, "version": a.version, "function": a.function,
                    "surface": a.surface, "case_id": c["id"], "input": value,
                    "accepted": acc, "output": out, "output_kind": kind, "error": err,
                    "kind": "validator" if a.kind == "validator" else "downstream",
                }
                fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
                n += 1
    print(f"wrote {n} rows from {len(ADAPTERS)} adapters to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()
    run(args.out)
