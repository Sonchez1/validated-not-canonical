package vnc;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Java harness: runs every corpus case through each library and writes
 * results/raw/java.jsonl following harness/SCHEMA.md.
 *
 * Usage:  harness/java/run.sh                      (mvn package, then run)
 *         java -cp "target/classes:target/lib/*" vnc.Run [--out PATH]
 *
 * No network I/O is performed: java.net.InetAddress is never touched, and
 * every "downstream" row exercises only an in-process parsing or encoding
 * step (java.net.URI / java.net.URL / HttpRequest.uri() / IDN.toASCII).
 */
public final class Run {

    // ------------------------------------------------------------------
    // Result + adapter plumbing (mirrors harness/python/run.py)
    // ------------------------------------------------------------------
    record Result(boolean accepted, String output, String outputKind, String error) {
        static Result ok(String output, String kind) { return new Result(true, output, kind, null); }
        static Result rejected(String error) { return new Result(false, null, "rejected", trunc(error)); }
        static Result rejected(Throwable t) {
            return rejected(t.getClass().getSimpleName() + ": " + (t.getMessage() == null ? "" : t.getMessage()));
        }
    }

    @FunctionalInterface
    interface Fn { Result apply(String value, JsonNode kase) throws Exception; }

    static final class Adapter {
        final String library, version, function, surface, kind;
        final Fn fn;
        /** non-null => excluded from the self-check, with the stated reason */
        String selfCheckExempt;
        Adapter(String library, String version, String function, String surface, String kind, Fn fn) {
            this.library = library; this.version = version; this.function = function;
            this.surface = surface; this.kind = kind; this.fn = fn;
        }
        Result run(String value, JsonNode kase) {
            try {
                return fn.apply(value, kase);
            } catch (Throwable t) {          // every failure mode is a rejection record
                return Result.rejected(t);
            }
        }
    }

    static final List<Adapter> ADAPTERS = new ArrayList<>();
    static final List<String> SKIPPED = new ArrayList<>();
    static final PrintStream ERR = System.err;

    static Adapter adapter(String library, String version, String function, String surface, String kind, Fn fn) {
        Adapter a = new Adapter(library, version, function, surface, kind, fn);
        ADAPTERS.add(a);
        return a;
    }

    static String trunc(String s) { return s == null ? null : (s.length() > 200 ? s.substring(0, 200) : s); }

    static String domainOf(String addr) {
        int i = addr.lastIndexOf('@');
        return i >= 0 ? addr.substring(i + 1) : addr;
    }

    static final String RUNTIME = System.getProperty("java.version");

    /** Library version: jar file name first (artifact-<version>.jar), then manifest attributes. */
    static String versionOf(Class<?> c, String artifactId) {
        try {
            File jar = new File(c.getProtectionDomain().getCodeSource().getLocation().toURI());
            String name = jar.getName();
            if (name.endsWith(".jar")) {
                String base = name.substring(0, name.length() - 4);
                if (base.startsWith(artifactId + "-")) return base.substring(artifactId.length() + 1);
            }
            try (JarFile jf = new JarFile(jar)) {
                Manifest m = jf.getManifest();
                if (m != null) {
                    Attributes a = m.getMainAttributes();
                    for (String k : new String[]{"Implementation-Version", "Bundle-Version"}) {
                        String v = a.getValue(k);
                        if (v != null && !v.isBlank()) return v;
                    }
                }
            }
        } catch (Exception ignored) { /* fall through */ }
        return "unknown";
    }

    // ------------------------------------------------------------------
    // Adapter registration
    // ------------------------------------------------------------------
    @SuppressWarnings("deprecation")
    static void registerStdlib() {
        adapter("stdlib", RUNTIME, "new java.net.URI(url).getHost()", "url", "downstream", (u, k) -> {
            try {
                String h = new URI(u).getHost();
                if (h == null) return Result.rejected("NullHost: URI parsed but getHost() returned null (registry-based authority)");
                return Result.ok(h, "parsed");
            } catch (URISyntaxException e) {
                return Result.rejected(e);
            }
        });

        adapter("stdlib", RUNTIME, "new java.net.URL(url).getHost()  [deprecated constructor]", "url", "downstream", (u, k) -> {
            String h = new URL(u).getHost();          // MalformedURLException -> rejected
            if (h == null || h.isEmpty()) return Result.rejected("EmptyHost: URL parsed but getHost() is empty");
            return Result.ok(h, "parsed");
        });

        adapter("stdlib", RUNTIME, "HttpRequest.newBuilder(URI.create(url)).build().uri().getHost()  [java.net.http]", "url", "downstream", (u, k) -> {
            String h = HttpRequest.newBuilder(URI.create(u)).build().uri().getHost();
            if (h == null) return Result.rejected("NullHost: request built but uri().getHost() is null");
            return Result.ok(h, "parsed");
        });

        adapter("stdlib", RUNTIME, "java.net.IDN.toASCII(host)  [IDNA 2003]", "host", "downstream",
                (h, k) -> Result.ok(IDN.toASCII(h), "normalized"));

        adapter("stdlib", RUNTIME, "java.net.IDN.toASCII(host, IDN.ALLOW_UNASSIGNED)  [IDNA 2003]", "host", "downstream",
                (h, k) -> Result.ok(IDN.toASCII(h, IDN.ALLOW_UNASSIGNED), "normalized"));
    }

    static void registerCommonsValidator() {
        try {
            Class.forName("org.apache.commons.validator.routines.UrlValidator");
        } catch (Throwable t) {
            SKIPPED.add("commons-validator: " + t);
            return;
        }
        final String v = versionOf(org.apache.commons.validator.routines.UrlValidator.class, "commons-validator");
        final org.apache.commons.validator.routines.UrlValidator urlDefault =
                org.apache.commons.validator.routines.UrlValidator.getInstance();
        final org.apache.commons.validator.routines.UrlValidator urlLocal =
                new org.apache.commons.validator.routines.UrlValidator(org.apache.commons.validator.routines.UrlValidator.ALLOW_LOCAL_URLS);
        final org.apache.commons.validator.routines.EmailValidator email =
                org.apache.commons.validator.routines.EmailValidator.getInstance();
        final org.apache.commons.validator.routines.DomainValidator domain =
                org.apache.commons.validator.routines.DomainValidator.getInstance();

        adapter("commons-validator", v, "UrlValidator.getInstance().isValid(url)", "url", "validator",
                (u, k) -> urlDefault.isValid(u) ? Result.ok(k.get("host").asText(), "passthrough") : Result.rejected("isValid returned false"));
        adapter("commons-validator", v, "new UrlValidator(UrlValidator.ALLOW_LOCAL_URLS).isValid(url)", "url", "validator",
                (u, k) -> urlLocal.isValid(u) ? Result.ok(k.get("host").asText(), "passthrough") : Result.rejected("isValid returned false"));
        adapter("commons-validator", v, "EmailValidator.getInstance().isValid(addr)", "email", "validator",
                (a, k) -> email.isValid(a) ? Result.ok(domainOf(a), "passthrough") : Result.rejected("isValid returned false"));
        adapter("commons-validator", v, "DomainValidator.getInstance().isValid(host)", "host", "validator",
                (h, k) -> domain.isValid(h) ? Result.ok(k.get("host").asText(), "passthrough") : Result.rejected("isValid returned false"));
    }

    /** Bean for Hibernate Validator; the field not under test stays null (null is valid for both constraints). */
    public static final class Bean {
        @jakarta.validation.constraints.Email public String email;
        @org.hibernate.validator.constraints.URL public String url;
    }

    static void registerHibernateValidator() {
        Logger.getLogger("org.hibernate.validator").setLevel(Level.WARNING);   // silence HV000001 banner (JUL backend)
        jakarta.validation.Validator validator;
        String note = "";
        try {
            validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
        } catch (Throwable t1) {
            try {
                validator = jakarta.validation.Validation.byDefaultProvider().configure()
                        .messageInterpolator(new org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator())
                        .buildValidatorFactory().getValidator();
                note = "  [ParameterMessageInterpolator; default EL bootstrap failed: " + t1 + "]";
                ERR.println("NOTE hibernate-validator: default EL bootstrap failed (" + t1 + "); using ParameterMessageInterpolator");
            } catch (Throwable t2) {
                SKIPPED.add("hibernate-validator: " + t1 + " / " + t2);
                return;
            }
        }
        final jakarta.validation.Validator val = validator;
        final String v = versionOf(org.hibernate.validator.HibernateValidator.class, "hibernate-validator");
        final String n = note;

        adapter("hibernate-validator", v, "@jakarta.validation.constraints.Email  [Validator.validate(bean)]" + n, "email", "validator", (a, k) -> {
            Bean b = new Bean(); b.email = a;
            Set<jakarta.validation.ConstraintViolation<Bean>> viol = val.validate(b);
            if (viol.isEmpty()) return Result.ok(domainOf(a), "passthrough");
            return Result.rejected("ConstraintViolation: " + viol.iterator().next().getMessage());
        });
        adapter("hibernate-validator", v, "@org.hibernate.validator.constraints.URL  [Validator.validate(bean)]" + n, "url", "validator", (u, k) -> {
            Bean b = new Bean(); b.url = u;
            Set<jakarta.validation.ConstraintViolation<Bean>> viol = val.validate(b);
            if (viol.isEmpty()) return Result.ok(k.get("host").asText(), "passthrough");
            return Result.rejected("ConstraintViolation: " + viol.iterator().next().getMessage());
        });
    }

    static void registerGuava() {
        try {
            Class.forName("com.google.common.net.InternetDomainName");
        } catch (Throwable t) {
            SKIPPED.add("guava: " + t);
            return;
        }
        final String v = versionOf(com.google.common.net.InternetDomainName.class, "guava");
        adapter("guava", v, "InternetDomainName.isValid(host)  [output = InternetDomainName.from(host).toString()]", "host", "validator", (h, k) -> {
            if (!com.google.common.net.InternetDomainName.isValid(h)) return Result.rejected("isValid returned false");
            String out = com.google.common.net.InternetDomainName.from(h).toString();
            return Result.ok(out, out.equals(h) ? "passthrough" : "normalized");
        });
    }

    static void registerJakartaMail() {
        try {
            Class.forName("jakarta.mail.internet.InternetAddress");
        } catch (Throwable t) {
            SKIPPED.add("jakarta.mail: " + t);
            return;
        }
        final String v = versionOf(jakarta.mail.internet.InternetAddress.class, "jakarta.mail");
        adapter("jakarta.mail", v, "new InternetAddress(addr, true).validate()  [strict RFC 822; output = domain of getAddress()]", "email", "validator", (a, k) -> {
            jakarta.mail.internet.InternetAddress ia = new jakarta.mail.internet.InternetAddress(a, true);  // AddressException -> rejected
            ia.validate();
            String out = domainOf(ia.getAddress());
            return Result.ok(out, out.equals(domainOf(a)) ? "passthrough" : "normalized");
        });
    }

    // ------------------------------------------------------------------
    // Runner
    // ------------------------------------------------------------------
    static Path findRoot() {
        Path p = Paths.get("").toAbsolutePath();
        for (Path q = p; q != null; q = q.getParent()) {
            if (Files.isRegularFile(q.resolve("corpus").resolve("corpus.json"))) return q;
        }
        throw new IllegalStateException("cannot locate corpus/corpus.json above " + p);
    }

    public static void main(String[] args) throws Exception {
        Path root = findRoot();
        Path corpusPath = root.resolve("corpus").resolve("corpus.json");
        Path out = root.resolve("results").resolve("raw").resolve("java.jsonl");
        for (int i = 0; i < args.length; i++) {
            if ("--out".equals(args[i]) && i + 1 < args.length) out = Paths.get(args[++i]).toAbsolutePath();
        }

        registerStdlib();
        registerCommonsValidator();
        registerHibernateValidator();
        registerGuava();
        registerJakartaMail();

        ObjectMapper mapper = new ObjectMapper(JsonFactory.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build());
        JsonNode corpus = mapper.readTree(corpusPath.toFile());
        JsonNode cases = corpus.get("cases");
        Map<String, JsonNode> byId = new LinkedHashMap<>();
        for (JsonNode c : cases) byId.put(c.get("id").asText(), c);

        // ---- self-check -------------------------------------------------
        JsonNode good = byId.get("ctl-good"), bad = byId.get("ctl-bad-space");
        List<String> failures = new ArrayList<>();
        for (Adapter a : ADAPTERS) {
            if (a.selfCheckExempt != null) {
                ERR.println("SELF-CHECK EXEMPT " + a.library + " " + a.function + ": " + a.selfCheckExempt);
                continue;
            }
            Result r = a.run(good.get(a.surface).asText(), good);
            if (!r.accepted())
                failures.add(a.library + " " + a.function + ": rejected known-good '" + good.get(a.surface).asText() + "': " + r.error());
            if ("validator".equals(a.kind) && ("host".equals(a.surface) || "email".equals(a.surface))) {
                r = a.run(bad.get(a.surface).asText(), bad);
                if (r.accepted())
                    failures.add(a.library + " " + a.function + ": accepted known-bad '" + bad.get(a.surface).asText() + "'");
            }
        }
        if (!failures.isEmpty()) {
            ERR.println("SELF-CHECK FAILED:");
            for (String f : failures) ERR.println("  " + f);
            System.exit(2);
        }
        for (String s : SKIPPED) ERR.println("SKIP " + s);

        // ---- run + write ------------------------------------------------
        Files.createDirectories(out.getParent());
        int n = 0;
        Map<Adapter, int[]> tally = new LinkedHashMap<>();
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            for (Adapter a : ADAPTERS) {
                int[] t = new int[2];
                tally.put(a, t);
                for (JsonNode c : cases) {
                    boolean has = false;
                    for (JsonNode s : c.get("surfaces")) if (a.surface.equals(s.asText())) has = true;
                    if (!has) continue;
                    String value = c.get(a.surface).asText();
                    Result r = a.run(value, c);
                    Map<String, Object> rec = new LinkedHashMap<>();
                    rec.put("ecosystem", "java");
                    rec.put("runtime", RUNTIME);
                    rec.put("library", a.library);
                    rec.put("version", a.version);
                    rec.put("function", a.function);
                    rec.put("surface", a.surface);
                    rec.put("case_id", c.get("id").asText());
                    rec.put("input", value);
                    rec.put("accepted", r.accepted());
                    rec.put("output", r.output());
                    rec.put("output_kind", r.outputKind());
                    rec.put("error", r.error());
                    rec.put("kind", a.kind);
                    w.write(mapper.writeValueAsString(rec));
                    w.write('\n');
                    n++;
                    t[1]++;
                    if (r.accepted()) t[0]++;
                }
            }
        }

        // ---- stderr table ----------------------------------------------
        int wl = 0, wf = 0;
        for (Adapter a : tally.keySet()) { wl = Math.max(wl, a.library.length()); wf = Math.max(wf, a.function.length()); }
        String fmt = "%-" + wl + "s  %-14s  %-10s  %-" + wf + "s  %s%n";
        ERR.printf(fmt, "library", "version", "kind", "function", "accepted/total");
        ERR.println("-".repeat(wl + wf + 50));
        for (Map.Entry<Adapter, int[]> e : tally.entrySet()) {
            Adapter a = e.getKey();
            ERR.printf(fmt, a.library, a.version, a.kind, a.function, e.getValue()[0] + "/" + e.getValue()[1]);
        }
        ERR.println("runtime java " + RUNTIME + " (" + System.getProperty("java.vendor") + ")");
        ERR.println("wrote " + n + " rows from " + ADAPTERS.size() + " adapters to " + out);
    }
}
