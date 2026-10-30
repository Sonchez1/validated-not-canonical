//! Rust harness: runs every corpus case through each library and writes
//! results/raw/rust.jsonl following harness/SCHEMA.md.
//!
//! Usage:  harness/rust/run.sh
//!         cargo run --release -- [--out PATH]
//!
//! No network I/O is performed. The `runtime` field comes from the
//! RUSTC_VERSION environment variable (set by run.sh); library versions are
//! read from Cargo.lock at runtime.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use email_address::EmailAddress;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use serde::{Deserialize, Serialize};
use url::Url;
use validator::{ValidateEmail, ValidateUrl};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

// ---------------------------------------------------------------------------
// Corpus and output types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    id: String,
    host: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    email: Option<String>,
    surfaces: Vec<String>,
}

impl Case {
    fn surface(&self, s: &str) -> Option<&str> {
        match s {
            "host" => Some(self.host.as_str()),
            "url" => self.url.as_deref(),
            "email" => self.email.as_deref(),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct Row<'a> {
    ecosystem: &'a str,
    runtime: &'a str,
    library: &'a str,
    version: &'a str,
    function: &'a str,
    surface: &'a str,
    case_id: &'a str,
    input: &'a str,
    accepted: bool,
    output: Option<&'a str>,
    output_kind: &'a str,
    error: Option<&'a str>,
    kind: &'a str,
}

/// accepted, output, output_kind, error
struct Res {
    accepted: bool,
    output: Option<String>,
    output_kind: &'static str,
    error: Option<String>,
}

fn ok(output: String, kind: &'static str) -> Res {
    Res { accepted: true, output: Some(output), output_kind: kind, error: None }
}

fn rejected(type_name: &str, msg: impl std::fmt::Display) -> Res {
    let full = format!("{}: {}", type_name, msg);
    let truncated: String = full.chars().take(200).collect();
    Res { accepted: false, output: None, output_kind: "rejected", error: Some(truncated) }
}

fn domain_of(addr: &str) -> &str {
    match addr.rfind('@') {
        Some(i) => &addr[i + 1..],
        None => addr,
    }
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

type AdapterFn = Box<dyn Fn(&str, &Case) -> Res>;

struct Adapter {
    library: &'static str,
    version: String,
    function: &'static str,
    surface: &'static str,
    /// "validator" or "downstream"
    kind: &'static str,
    /// Some(reason) when the function legitimately fails the self-check and
    /// is excluded from it (its rows are still recorded).
    selfcheck_exempt: Option<&'static str>,
    fn_: AdapterFn,
}

fn build_adapters(versions: &HashMap<String, String>) -> Vec<Adapter> {
    let v = |name: &str| versions.get(name).cloned().unwrap_or_else(|| "unknown".to_string());
    let mut a: Vec<Adapter> = Vec::new();

    // ---- url crate (downstream: the URL parser HTTP clients such as reqwest/hyper use)
    a.push(Adapter {
        library: "url",
        version: v("url"),
        function: "url::Url::parse(url)?.host_str()",
        surface: "url",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match Url::parse(value) {
            Err(e) => rejected("url::ParseError", e),
            Ok(u) => match u.host_str() {
                Some(h) => ok(h.to_string(), "parsed"),
                None => rejected("NoHost", "host_str() returned None"),
            },
        }),
    });
    a.push(Adapter {
        library: "url",
        version: v("url"),
        function: "url::Url::parse(url)?.domain()",
        surface: "url",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match Url::parse(value) {
            Err(e) => rejected("url::ParseError", e),
            Ok(u) => match u.domain() {
                Some(h) => ok(h.to_string(), "parsed"),
                None => rejected("NoDomain", "domain() returned None (no host or host is an IP address)"),
            },
        }),
    });

    // ---- idna crate (downstream: the UTS 46 encoder url/reqwest/hickory use)
    a.push(Adapter {
        library: "idna",
        version: v("idna"),
        function: "idna::domain_to_ascii(host)  [UTS 46: AsciiDenyList::EMPTY, Hyphens::Allow, DnsLength::Ignore]",
        surface: "host",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match idna::domain_to_ascii(value) {
            Ok(s) => ok(s, "normalized"),
            Err(e) => rejected("idna::Errors", e),
        }),
    });
    a.push(Adapter {
        library: "idna",
        version: v("idna"),
        function: "idna::domain_to_ascii_strict(host)  [UTS 46 beStrict: AsciiDenyList::STD3, Hyphens::Check, DnsLength::Verify]",
        surface: "host",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match idna::domain_to_ascii_strict(value) {
            Ok(s) => ok(s, "normalized"),
            Err(e) => rejected("idna::Errors", e),
        }),
    });
    a.push(Adapter {
        library: "idna",
        version: v("idna"),
        function: "idna::uts46::Uts46::new().to_ascii(host, AsciiDenyList::STD3, Hyphens::Check, DnsLength::Verify)",
        surface: "host",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| {
            match Uts46::new().to_ascii(value.as_bytes(), AsciiDenyList::STD3, Hyphens::Check, DnsLength::Verify) {
                Ok(s) => ok(s.into_owned(), "normalized"),
                Err(e) => rejected("idna::Errors", e),
            }
        }),
    });
    a.push(Adapter {
        library: "idna",
        version: v("idna"),
        function: "idna::uts46::Uts46::new().to_ascii(host, AsciiDenyList::URL, Hyphens::Allow, DnsLength::Ignore)  [WHATWG domain-to-ASCII]",
        surface: "host",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| {
            match Uts46::new().to_ascii(value.as_bytes(), AsciiDenyList::URL, Hyphens::Allow, DnsLength::Ignore) {
                Ok(s) => ok(s.into_owned(), "normalized"),
                Err(e) => rejected("idna::Errors", e),
            }
        }),
    });

    // ---- email_address crate (validator)
    a.push(Adapter {
        library: "email_address",
        version: v("email_address"),
        function: "email_address::EmailAddress::from_str(addr)?.domain()",
        surface: "email",
        kind: "validator",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match EmailAddress::from_str(value) {
            Ok(e) => {
                let d = e.domain().to_string();
                let kind = if d == domain_of(value) { "passthrough" } else { "normalized" };
                ok(d, kind)
            }
            Err(e) => rejected(&format!("email_address::Error::{:?}", e), e),
        }),
    });

    // ---- validator crate (boolean validators)
    a.push(Adapter {
        library: "validator",
        version: v("validator"),
        function: "validator::ValidateEmail::validate_email(&addr)",
        surface: "email",
        kind: "validator",
        selfcheck_exempt: None,
        fn_: Box::new(|value, case| {
            if ValidateEmail::validate_email(&value) {
                ok(case.host.clone(), "passthrough")
            } else {
                rejected("bool", "validate_email returned false")
            }
        }),
    });
    a.push(Adapter {
        library: "validator",
        version: v("validator"),
        function: "validator::ValidateUrl::validate_url(&url)",
        surface: "url",
        kind: "validator",
        selfcheck_exempt: None,
        fn_: Box::new(|value, case| {
            if ValidateUrl::validate_url(&value) {
                ok(case.host.clone(), "passthrough")
            } else {
                rejected("bool", "validate_url returned false")
            }
        }),
    });

    // ---- psl crate (downstream: public-suffix splitter, compiled-in list)
    a.push(Adapter {
        library: "psl",
        version: v("psl"),
        function: "psl::domain(host.as_bytes())  [registrable domain; compiled-in public suffix list]",
        surface: "host",
        kind: "downstream",
        selfcheck_exempt: None,
        fn_: Box::new(|value, _| match psl::domain(value.as_bytes()) {
            Some(d) => match std::str::from_utf8(d.as_bytes()) {
                Ok(s) => ok(s.to_string(), "parsed"),
                Err(e) => rejected("Utf8Error", e),
            },
            None => rejected("NoDomain", "psl::domain returned None"),
        }),
    });

    a
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal Cargo.lock reader: package name -> version (first occurrence wins).
fn lock_versions(lock_path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(text) = fs::read_to_string(lock_path) else { return out };
    let mut name: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            name = None;
        } else if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                out.entry(n).or_insert_with(|| rest.trim_matches('"').to_string());
            }
        }
    }
    out
}

/// Escape every char above 0x7E as \uXXXX (surrogate pairs above U+FFFF) so
/// the output is pure ASCII. serde_json already escapes `"`, `\` and C0
/// controls, so this is safe to apply to a serialised JSON line.
fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp <= 0x7E {
            out.push(c);
        } else if cp <= 0xFFFF {
            out.push_str(&format!("\\u{:04x}", cp));
        } else {
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root: PathBuf = Path::new(MANIFEST_DIR).join("..").join("..");
    let mut out_path = root.join("results").join("raw").join("rust.jsonl");
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            eprintln!("unknown argument: {}", args[i]);
            std::process::exit(1);
        }
    }

    let runtime = std::env::var("RUSTC_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let versions = lock_versions(&Path::new(MANIFEST_DIR).join("Cargo.lock"));
    let adapters = build_adapters(&versions);

    let corpus_path = root.join("corpus").join("corpus.json");
    let corpus_text = fs::read_to_string(&corpus_path)
        .unwrap_or_else(|e| { eprintln!("cannot read {}: {}", corpus_path.display(), e); std::process::exit(1) });
    let corpus: Corpus = serde_json::from_str(&corpus_text)
        .unwrap_or_else(|e| { eprintln!("cannot parse corpus: {}", e); std::process::exit(1) });
    let cases = corpus.cases;
    let by_id: HashMap<&str, &Case> = cases.iter().map(|c| (c.id.as_str(), c)).collect();

    // ---- self-check
    let good = by_id["ctl-good"];
    let bad = by_id["ctl-bad-space"];
    let mut failures: Vec<String> = Vec::new();
    for a in &adapters {
        if let Some(reason) = a.selfcheck_exempt {
            eprintln!("SELF-CHECK EXEMPT {} {}: {}", a.library, a.function, reason);
            continue;
        }
        let gv = good.surface(a.surface).expect("ctl-good lacks surface");
        let r = (a.fn_)(gv, good);
        if !r.accepted {
            failures.push(format!("{} {}: rejected known-good {:?}: {}", a.library, a.function, gv, r.error.unwrap_or_default()));
        }
        if a.kind == "validator" && (a.surface == "host" || a.surface == "email") {
            let bv = bad.surface(a.surface).expect("ctl-bad-space lacks surface");
            let r = (a.fn_)(bv, bad);
            if r.accepted {
                failures.push(format!("{} {}: accepted known-bad {:?}", a.library, a.function, bv));
            }
        }
    }
    if !failures.is_empty() {
        eprintln!("SELF-CHECK FAILED:");
        for f in &failures {
            eprintln!("  {}", f);
        }
        std::process::exit(2);
    }

    // ---- run
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create results dir");
    }
    let mut fh = fs::File::create(&out_path)
        .unwrap_or_else(|e| { eprintln!("cannot write {}: {}", out_path.display(), e); std::process::exit(1) });
    let mut n = 0usize;
    let mut table: Vec<(String, usize, usize)> = Vec::new();
    let mut mid_rows: Vec<String> = Vec::new();
    for a in &adapters {
        let mut accepted = 0usize;
        let mut total = 0usize;
        for c in &cases {
            if !c.surfaces.iter().any(|s| s == a.surface) {
                continue;
            }
            let Some(value) = c.surface(a.surface) else { continue };
            let r = (a.fn_)(value, c);
            let row = Row {
                ecosystem: "rust",
                runtime: &runtime,
                library: a.library,
                version: &a.version,
                function: a.function,
                surface: a.surface,
                case_id: &c.id,
                input: value,
                accepted: r.accepted,
                output: r.output.as_deref(),
                output_kind: r.output_kind,
                error: r.error.as_deref(),
                kind: a.kind,
            };
            let line = escape_non_ascii(&serde_json::to_string(&row).expect("serialise row"));
            if c.id == "inv-200B-mid" {
                mid_rows.push(line.clone());
            }
            writeln!(fh, "{}", line).expect("write row");
            n += 1;
            total += 1;
            if r.accepted {
                accepted += 1;
            }
        }
        table.push((format!("{} {}", a.library, a.function), accepted, total));
    }
    fh.flush().expect("flush");

    eprintln!("runtime: {}", runtime);
    for lib in ["url", "idna", "email_address", "validator", "psl"] {
        eprintln!("version {} = {}", lib, versions.get(lib).map(String::as_str).unwrap_or("unknown"));
    }
    eprintln!("{:<8} {:<8} function", "accepted", "total");
    for (name, acc, tot) in &table {
        eprintln!("{:<8} {:<8} {}", acc, tot, name);
    }
    eprintln!("--- rows for case_id inv-200B-mid ---");
    for l in &mid_rows {
        eprintln!("{}", l);
    }
    eprintln!("wrote {} rows from {} adapters to {}", n, adapters.len(), out_path.display());
}
