#!/usr/bin/env ruby
# frozen_string_literal: true
# encoding: utf-8
#
# Ruby harness: runs every corpus case through each library and writes
# results/raw/ruby.jsonl following harness/SCHEMA.md.
#
# Usage:  harness/ruby/run.sh                (bundle install, then run)
#         bundle exec ruby run.rb [--out PATH]
#
# No network I/O is performed. Resolv rows exercise only
# Resolv::DNS::Name.create, the name-construction step that precedes any
# query; Net::HTTP is deliberately not exercised because it would connect.

Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8

require "json"
require "uri"
require "resolv"

HERE = File.expand_path(__dir__)
ROOT = File.expand_path("../..", HERE)
CORPUS = File.join(ROOT, "corpus", "corpus.json")
DEFAULT_OUT = File.join(ROOT, "results", "raw", "ruby.jsonl")

RUNTIME = RUBY_VERSION

# ---------------------------------------------------------------------------
# Result helpers: [accepted, output, output_kind, error]
# ---------------------------------------------------------------------------
def ok(output, kind)
  [true, output.to_s, kind, nil]
end

def rejected(exc_or_msg)
  msg = exc_or_msg.is_a?(Exception) ? "#{exc_or_msg.class}: #{exc_or_msg.message}" : exc_or_msg.to_s
  [false, nil, "rejected", msg[0, 200]]
end

def domain_of(addr)
  addr.include?("@") ? addr.rpartition("@").last : addr
end

def gem_version(name)
  spec = Gem.loaded_specs[name]
  spec ? spec.version.to_s : "unknown"
end

Adapter = Struct.new(:library, :version, :function, :surface, :kind, :self_check_exempt, :fn)

ADAPTERS = []
SKIPPED = []

# kind: "validator" or "downstream" (matches the schema's `kind` field).
# self_check_exempt: nil, or a reason string explaining why the function
# legitimately fails the control self-check (its rows are still written).
def adapter(library, version, function, surface, kind, self_check_exempt: nil, &blk)
  guarded = lambda do |value, kase|
    begin
      blk.call(value, kase)
    rescue StandardError => e
      rejected(e)
    end
  end
  ADAPTERS << Adapter.new(library, version, function, surface, kind, self_check_exempt, guarded)
end

# ---------------------------------------------------------------------------
# stdlib: URI
# ---------------------------------------------------------------------------
URI_VER = defined?(URI::VERSION) ? URI::VERSION : "bundled"
DEFAULT_PARSER_CLASS = URI::DEFAULT_PARSER.class.name

adapter("stdlib", RUNTIME,
        "URI.parse(u).host  [URI::DEFAULT_PARSER = #{DEFAULT_PARSER_CLASS}; uri #{URI_VER}]",
        "url", "downstream") do |u, _c|
  h = URI.parse(u).host
  h.nil? || h.empty? ? rejected("ArgumentError: no host") : ok(h, "parsed")
end

if defined?(URI::RFC2396_PARSER)
  adapter("stdlib", RUNTIME, "URI::RFC2396_PARSER.parse(u).host  [uri #{URI_VER}]",
          "url", "downstream") do |u, _c|
    h = URI::RFC2396_PARSER.parse(u).host
    h.nil? || h.empty? ? rejected("ArgumentError: no host") : ok(h, "parsed")
  end
else
  SKIPPED << "stdlib URI::RFC2396_PARSER: constant not defined in this Ruby"
end

if defined?(URI::RFC3986_PARSER)
  adapter("stdlib", RUNTIME, "URI::RFC3986_PARSER.parse(u).host  [uri #{URI_VER}]",
          "url", "downstream") do |u, _c|
    h = URI::RFC3986_PARSER.parse(u).host
    h.nil? || h.empty? ? rejected("ArgumentError: no host") : ok(h, "parsed")
  end
else
  SKIPPED << "stdlib URI::RFC3986_PARSER: constant not defined in this Ruby"
end

# URI::MailTo::EMAIL_REGEXP is what many Rails apps use in `validates format:`.
adapter("stdlib", RUNTIME, "URI::MailTo::EMAIL_REGEXP.match?(addr)  [uri #{URI_VER}]",
        "email", "validator") do |addr, c|
  if URI::MailTo::EMAIL_REGEXP.match?(addr)
    ok(c["host"], "passthrough")
  else
    rejected("EMAIL_REGEXP: no match")
  end
end

# ---------------------------------------------------------------------------
# stdlib: Resolv (name construction only; no query is sent)
# ---------------------------------------------------------------------------
adapter("stdlib", RUNTIME,
        "Resolv::DNS::Name.create(host).to_s  [name the resolver would query; no IDNA step]",
        "host", "downstream") do |h, _c|
  ok(Resolv::DNS::Name.create(h).to_s, "normalized")
end

# ---------------------------------------------------------------------------
# mail
# ---------------------------------------------------------------------------
begin
  require "mail"
  adapter("mail", gem_version("mail"), "Mail::Address.new(addr).domain", "email", "downstream") do |addr, _c|
    d = Mail::Address.new(addr).domain
    d.nil? || d.empty? ? rejected("Mail::Field::ParseError: nil domain") : ok(d, "parsed")
  end
rescue LoadError => e
  SKIPPED << "mail: #{e.message}"
end

# ---------------------------------------------------------------------------
# addressable
# ---------------------------------------------------------------------------
begin
  require "addressable/uri"
  require "addressable/idna"
  av = gem_version("addressable")
  idna_src = Addressable::IDNA.method(:to_ascii).source_location.to_a.first.to_s
  IDNA_IMPL = if idna_src.include?("pure") then "pure-Ruby IDNA"
              elsif idna_src.include?("native") then "libidn (native)"
              else "unknown backend"
              end

  adapter("addressable", av, "Addressable::URI.parse(u).host", "url", "downstream") do |u, _c|
    h = Addressable::URI.parse(u).host
    h.nil? || h.empty? ? rejected("Addressable::URI::InvalidURIError: no host") : ok(h, "parsed")
  end

  adapter("addressable", av, "Addressable::URI.parse(u).normalized_host  [#{IDNA_IMPL}]",
          "url", "downstream") do |u, _c|
    h = Addressable::URI.parse(u).normalized_host
    h.nil? || h.empty? ? rejected("Addressable::URI::InvalidURIError: no host") : ok(h, "normalized")
  end

  adapter("addressable", av, "Addressable::IDNA.to_ascii(host)  [#{IDNA_IMPL}]",
          "host", "downstream") do |h, _c|
    ok(Addressable::IDNA.to_ascii(h), "normalized")
  end
rescue LoadError => e
  SKIPPED << "addressable: #{e.message}"
end

# ---------------------------------------------------------------------------
# public_suffix (default rule list, default_rule left at its default)
# ---------------------------------------------------------------------------
begin
  require "public_suffix"
  pv = gem_version("public_suffix")

  adapter("public_suffix", pv, "PublicSuffix.valid?(host)", "host", "validator",
          self_check_exempt: "PublicSuffix.valid? only checks that the trailing labels match a " \
                             "public-suffix rule; it performs no label-syntax validation, so " \
                             "it accepts 'exa mple.com' by design") do |h, c|
    PublicSuffix.valid?(h) ? ok(c["host"], "passthrough") : rejected("PublicSuffix.valid? returned false")
  end

  adapter("public_suffix", pv, "PublicSuffix.parse(host).to_s", "host", "downstream") do |h, _c|
    ok(PublicSuffix.parse(h).to_s, "parsed")
  end
rescue LoadError => e
  SKIPPED << "public_suffix: #{e.message}"
end

# ---------------------------------------------------------------------------
# simpleidn
# ---------------------------------------------------------------------------
begin
  require "simpleidn"
  adapter("simpleidn", gem_version("simpleidn"), "SimpleIDN.to_ascii(host)", "host", "downstream") do |h, _c|
    ok(SimpleIDN.to_ascii(h), "normalized")
  end
rescue LoadError => e
  SKIPPED << "simpleidn: #{e.message}"
end

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(out_path)
  corpus = JSON.parse(File.read(CORPUS, encoding: "UTF-8"))
  cases = corpus["cases"]
  by_id = cases.to_h { |c| [c["id"], c] }

  good = by_id.fetch("ctl-good")
  bad = by_id.fetch("ctl-bad-space")
  failures = []
  ADAPTERS.each do |a|
    if a.self_check_exempt
      warn "SELF-CHECK EXEMPT #{a.library} #{a.function}: #{a.self_check_exempt}"
      next
    end
    acc, _out, _kind, err = a.fn.call(good[a.surface], good)
    failures << "#{a.library} #{a.function}: rejected known-good #{good[a.surface].inspect}: #{err}" unless acc
    if a.kind == "validator" && %w[host email].include?(a.surface)
      acc, = a.fn.call(bad[a.surface], bad)
      failures << "#{a.library} #{a.function}: accepted known-bad #{bad[a.surface].inspect}" if acc
    end
  end
  unless failures.empty?
    warn "SELF-CHECK FAILED:"
    failures.each { |f| warn "  #{f}" }
    exit 2
  end

  SKIPPED.each { |s| warn "SKIP #{s}" }

  require "fileutils"
  FileUtils.mkdir_p(File.dirname(out_path))
  n = 0
  stats = []
  File.open(out_path, "w", encoding: "UTF-8") do |fh|
    ADAPTERS.each do |a|
      total = 0
      accepted = 0
      cases.each do |c|
        next unless c["surfaces"].include?(a.surface)

        value = c[a.surface]
        acc, out, kind, err = a.fn.call(value, c)
        rec = {
          "ecosystem" => "ruby", "runtime" => RUNTIME,
          "library" => a.library, "version" => a.version, "function" => a.function,
          "surface" => a.surface, "case_id" => c["id"], "input" => value,
          "accepted" => acc, "output" => out, "output_kind" => kind, "error" => err,
          "kind" => a.kind,
        }
        fh.write(JSON.generate(rec, ascii_only: true) + "\n")
        n += 1
        total += 1
        accepted += 1 if acc
      end
      stats << [a.library, a.version, a.function, a.surface, a.kind, accepted, total]
    end
  end

  warn "wrote #{n} rows from #{ADAPTERS.size} adapters to #{out_path}"
  warn ""
  warn format("%-14s %-8s %-8s %-10s %-9s %s", "library", "version", "surface", "kind", "acc/total", "function")
  stats.each do |lib, ver, fn, surf, kind, acc, tot|
    warn format("%-14s %-8s %-8s %-10s %4d/%-4d %s", lib, ver, surf, kind, acc, tot, fn)
  end
end

if $PROGRAM_NAME == __FILE__
  out = DEFAULT_OUT
  if (i = ARGV.index("--out"))
    out = ARGV[i + 1] or abort("--out requires a path")
  end
  run(out)
end
