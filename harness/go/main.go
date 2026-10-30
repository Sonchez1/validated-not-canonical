// Go harness: runs every corpus case through each library and writes
// results/raw/go.jsonl following harness/SCHEMA.md.
//
// Usage:  harness/go/run.sh            (go run . with the default output path)
//
//	go run . [-out PATH]
//
// No network I/O is performed. net/http rows only build the request object
// (http.NewRequest); nothing is sent. govalidator.IsExistingEmail is skipped
// because it calls net.LookupMX / net.LookupIP.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"github.com/asaskevich/govalidator"
	"github.com/go-playground/validator/v10"
	"golang.org/x/net/idna"
)

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

type Case struct {
	ID       string   `json:"id"`
	Host     string   `json:"host"`
	URL      string   `json:"url"`
	Email    string   `json:"email"`
	Surfaces []string `json:"surfaces"`
}

type Corpus struct {
	Cases []Case `json:"cases"`
}

func (c Case) value(surface string) string {
	switch surface {
	case "host":
		return c.Host
	case "url":
		return c.URL
	case "email":
		return c.Email
	}
	panic("unknown surface " + surface)
}

func (c Case) hasSurface(surface string) bool {
	for _, s := range c.Surfaces {
		if s == surface {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

type Result struct {
	Accepted   bool
	Output     *string
	OutputKind string
	Error      *string
}

func ok(output, kind string) Result {
	return Result{Accepted: true, Output: &output, OutputKind: kind}
}

func rejected(err error) Result {
	msg := fmt.Sprintf("%T: %v", err, err)
	return rejectedMsg(msg)
}

func rejectedMsg(msg string) Result {
	if len(msg) > 200 {
		// cut on a rune boundary
		cut := 200
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut]
	}
	return Result{Accepted: false, OutputKind: "rejected", Error: &msg}
}

type AdapterFn func(value string, c Case) Result

type Adapter struct {
	Library  string
	Version  string
	Function string
	Surface  string
	Kind     string // "validator" or "downstream"
	Fn       AdapterFn
}

var adapters []Adapter
var skipped []string

func add(library, version, function, surface, kind string, fn AdapterFn) {
	adapters = append(adapters, Adapter{library, version, function, surface, kind, guarded(fn)})
}

// guarded turns a panic inside an adapter into a rejection record.
func guarded(fn AdapterFn) AdapterFn {
	return func(value string, c Case) (r Result) {
		defer func() {
			if p := recover(); p != nil {
				r = rejectedMsg(fmt.Sprintf("panic: %v", p))
			}
		}()
		return fn(value, c)
	}
}

func domainOf(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

var goVersion = runtime.Version()

func moduleVersion(path string) string {
	bi, okb := debug.ReadBuildInfo()
	if !okb {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path == path {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Adapter registration
// ---------------------------------------------------------------------------

func registerAdapters() {
	// --- stdlib ------------------------------------------------------------
	add("stdlib", goVersion, "net/url.Parse(url).Hostname()", "url", "downstream",
		func(v string, c Case) Result {
			u, err := url.Parse(v)
			if err != nil {
				return rejected(err)
			}
			h := u.Hostname()
			if h == "" {
				return rejectedMsg("error: empty host")
			}
			return ok(h, "parsed")
		})

	add("stdlib", goVersion, `net/http.NewRequest("GET", url, nil).URL.Hostname()`, "url", "downstream",
		func(v string, c Case) Result {
			req, err := http.NewRequest("GET", v, nil)
			if err != nil {
				return rejected(err)
			}
			h := req.URL.Hostname()
			if h == "" {
				return rejectedMsg("error: empty host")
			}
			return ok(h, "parsed")
		})

	add("stdlib", goVersion, "net/mail.ParseAddress(addr).Address  [domain part after last @]", "email", "downstream",
		func(v string, c Case) Result {
			a, err := mail.ParseAddress(v)
			if err != nil {
				return rejected(err)
			}
			if !strings.Contains(a.Address, "@") {
				return rejectedMsg("error: parsed address has no @: " + a.Address)
			}
			return ok(domainOf(a.Address), "parsed")
		})

	// --- golang.org/x/net/idna -------------------------------------------
	idnaLib := "golang.org/x/net/idna"
	idnaVer := moduleVersion("golang.org/x/net")
	idnaAdapter := func(function string, fn func(string) (string, error)) {
		add(idnaLib, idnaVer, function, "host", "downstream", func(v string, c Case) Result {
			out, err := fn(v)
			if err != nil {
				return rejected(err)
			}
			return ok(out, "normalized")
		})
	}
	idnaAdapter("idna.Lookup.ToASCII(host)", idna.Lookup.ToASCII)
	idnaAdapter("idna.Registration.ToASCII(host)", idna.Registration.ToASCII)
	idnaAdapter("idna.Display.ToASCII(host)", idna.Display.ToASCII)
	idnaAdapter("idna.ToASCII(host)  [Punycode profile]", idna.ToASCII)
	strict := idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.VerifyDNSLength(true),
		idna.BidiRule(), idna.ValidateForRegistration())
	idnaAdapter("idna.New(MapForLookup, StrictDomainName(true), VerifyDNSLength(true), BidiRule, ValidateForRegistration).ToASCII(host)",
		strict.ToASCII)

	// --- go-playground/validator/v10 --------------------------------------
	vLib := "github.com/go-playground/validator/v10"
	vVer := moduleVersion(vLib)
	validate := validator.New()
	vAdapter := func(tag, surface string) {
		add(vLib, vVer, fmt.Sprintf("validate.Var(%s, %q)", surface, tag), surface, "validator",
			func(v string, c Case) Result {
				if err := validate.Var(v, tag); err != nil {
					return rejected(err)
				}
				return ok(c.Host, "passthrough")
			})
	}
	vAdapter("hostname", "host")
	vAdapter("hostname_rfc1123", "host")
	vAdapter("fqdn", "host")
	vAdapter("url", "url")
	vAdapter("http_url", "url")
	vAdapter("email", "email")

	// --- asaskevich/govalidator -------------------------------------------
	gLib := "github.com/asaskevich/govalidator"
	gVer := moduleVersion(gLib)
	gAdapter := func(name, surface string, fn func(string) bool) {
		add(gLib, gVer, fmt.Sprintf("govalidator.%s(%s)", name, surface), surface, "validator",
			func(v string, c Case) Result {
				if !fn(v) {
					return rejectedMsg("ReturnedFalse: govalidator." + name + " returned false")
				}
				return ok(c.Host, "passthrough")
			})
	}
	gAdapter("IsDNSName", "host", govalidator.IsDNSName)
	gAdapter("IsURL", "url", govalidator.IsURL)
	gAdapter("IsRequestURL", "url", govalidator.IsRequestURL)
	gAdapter("IsEmail", "email", govalidator.IsEmail)
	skipped = append(skipped, gLib+" IsExistingEmail: performs DNS lookups (net.LookupMX / net.LookupIP) for any host other than localhost/example.com; no network I/O allowed")
}

// selfCheckExempt lists functions that legitimately fail the self-check.
// They are reported on stderr, excluded from the abort decision, and their
// rows are still written. Key: Library + " " + Function.
var selfCheckExempt = map[string]string{}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

type Record struct {
	Ecosystem  string  `json:"ecosystem"`
	Runtime    string  `json:"runtime"`
	Library    string  `json:"library"`
	Version    string  `json:"version"`
	Function   string  `json:"function"`
	Surface    string  `json:"surface"`
	CaseID     string  `json:"case_id"`
	Input      string  `json:"input"`
	Accepted   bool    `json:"accepted"`
	Output     *string `json:"output"`
	OutputKind string  `json:"output_kind"`
	Error      *string `json:"error"`
	Kind       string  `json:"kind"`
}

// marshalASCII marshals v with HTML escaping off and every rune above 0x7E
// written as \uXXXX (surrogate pairs above U+FFFF), so the file is pure ASCII.
func marshalASCII(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	s := strings.TrimRight(sb.String(), "\n")
	var out strings.Builder
	out.Grow(len(s))
	for _, r := range s {
		switch {
		case r <= 0x7E:
			out.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
		default:
			fmt.Fprintf(&out, "\\u%04x", r)
		}
	}
	return []byte(out.String()), nil
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

func main() {
	here, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	root := filepath.Dir(filepath.Dir(here))
	defaultOut := filepath.Join(root, "results", "raw", "go.jsonl")
	corpusPath := filepath.Join(root, "corpus", "corpus.json")

	outPath := flag.String("out", defaultOut, "output JSONL path")
	flag.Parse()

	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		fatal(err)
	}
	var corpus Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		fatal(err)
	}
	byID := map[string]Case{}
	for _, c := range corpus.Cases {
		byID[c.ID] = c
	}

	registerAdapters()

	// --- self-check ---------------------------------------------------------
	good, bad := byID["ctl-good"], byID["ctl-bad-space"]
	var failures []string
	for _, a := range adapters {
		key := a.Library + " " + a.Function
		var local []string
		r := a.Fn(good.value(a.Surface), good)
		if !r.Accepted {
			local = append(local, fmt.Sprintf("%s: rejected known-good %q: %s", key, good.value(a.Surface), deref(r.Error)))
		}
		if a.Kind == "validator" && (a.Surface == "host" || a.Surface == "email") {
			r = a.Fn(bad.value(a.Surface), bad)
			if r.Accepted {
				local = append(local, fmt.Sprintf("%s: accepted known-bad %q", key, bad.value(a.Surface)))
			}
		}
		if len(local) == 0 {
			continue
		}
		if reason, exempt := selfCheckExempt[key]; exempt {
			for _, f := range local {
				fmt.Fprintf(os.Stderr, "SELF-CHECK EXEMPT %s  (reason: %s)\n", f, reason)
			}
			continue
		}
		failures = append(failures, local...)
	}
	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "SELF-CHECK FAILED:")
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, "  "+f)
		}
		os.Exit(2)
	}
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "SKIP "+s)
	}

	// --- run ------------------------------------------------------------------
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fatal(err)
	}
	fh, err := os.Create(*outPath)
	if err != nil {
		fatal(err)
	}
	defer fh.Close()
	w := bufio.NewWriter(fh)
	defer w.Flush()

	type tally struct{ accepted, total int }
	tallies := make([]tally, len(adapters))
	n := 0
	for i, a := range adapters {
		for _, c := range corpus.Cases {
			if !c.hasSurface(a.Surface) {
				continue
			}
			v := c.value(a.Surface)
			r := a.Fn(v, c)
			rec := Record{
				Ecosystem: "go", Runtime: goVersion,
				Library: a.Library, Version: a.Version, Function: a.Function,
				Surface: a.Surface, CaseID: c.ID, Input: v,
				Accepted: r.Accepted, Output: r.Output, OutputKind: r.OutputKind, Error: r.Error,
				Kind: a.Kind,
			}
			line, err := marshalASCII(rec)
			if err != nil {
				fatal(err)
			}
			w.Write(line)
			w.WriteByte('\n')
			n++
			tallies[i].total++
			if r.Accepted {
				tallies[i].accepted++
			}
		}
	}

	// --- summary table ---------------------------------------------------------
	fmt.Fprintf(os.Stderr, "\n%-40s %-8s %-7s %-10s %s\n", "library", "version", "surface", "accepted", "function")
	for i, a := range adapters {
		fmt.Fprintf(os.Stderr, "%-40s %-8s %-7s %4d/%-5d %s\n",
			a.Library, a.Version, a.Surface, tallies[i].accepted, tallies[i].total, a.Function)
	}
	fmt.Fprintf(os.Stderr, "\nwrote %d rows from %d adapters to %s\n", n, len(adapters), *outPath)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
