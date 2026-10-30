<?php
/**
 * PHP harness: runs every corpus case through each library/function and
 * writes results/raw/php.jsonl following harness/SCHEMA.md.
 *
 * Usage:  harness/php/run.sh            (composer install, then run)
 *         php harness/php/run.php [--out PATH]
 *
 * No network I/O is performed anywhere: no DNS checks (no checkdnsrr, no
 * DNSCheckValidation), no sockets, no curl.
 */
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\RFCValidation;
use Egulias\EmailValidator\Validation\NoRFCWarningsValidation;
use Egulias\EmailValidator\Validation\Extra\SpoofCheckValidation;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Validation;

const ROOT = __DIR__ . '/../..';
const CORPUS = ROOT . '/corpus/corpus.json';
const DEFAULT_OUT = ROOT . '/results/raw/php.jsonl';

// Warnings/notices become exceptions (recorded as rejections); deprecations are ignored.
set_error_handler(static function (int $errno, string $errstr, string $errfile = '', int $errline = 0): bool {
    if ($errno & (E_DEPRECATED | E_USER_DEPRECATED)) {
        return true;
    }
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
/** @return array{0:bool,1:?string,2:string,3:?string} accepted, output, output_kind, error */
function ok(string $output, string $kind): array
{
    return [true, $output, $kind, null];
}

function rejected(Throwable|string $e): array
{
    $msg = $e instanceof Throwable ? get_class($e) . ': ' . $e->getMessage() : $e;
    return [false, null, 'rejected', mb_strcut($msg, 0, 200, '8bit')];
}

function domain_of(string $addr): string
{
    $p = strrpos($addr, '@');
    return $p === false ? $addr : substr($addr, $p + 1);
}

function pkg_version(string $pkg): string
{
    try {
        return \Composer\InstalledVersions::getPrettyVersion($pkg) ?? 'unknown';
    } catch (Throwable) {
        return 'unknown';
    }
}

final class Adapter
{
    public function __construct(
        public string $library,
        public string $version,
        public string $function,
        public string $surface,
        public string $kind,      // 'validator' | 'downstream'
        public Closure $fn,       // fn(string $value, array $case): array
    ) {
    }

    public function run(string $value, array $case): array
    {
        try {
            return ($this->fn)($value, $case);
        } catch (Throwable $e) {
            return rejected($e);
        }
    }
}

/** @var Adapter[] $ADAPTERS */
$ADAPTERS = [];
/** @var string[] $SKIPPED */
$SKIPPED = [];
$add = static function (string $lib, string $ver, string $fn, string $surface, string $kind, Closure $f) use (&$ADAPTERS): void {
    $ADAPTERS[] = new Adapter($lib, $ver, $fn, $surface, $kind, $f);
};

$PHPVER = PHP_VERSION;

// ---------------------------------------------------------------------------
// ext/filter  (filter_var)
// ---------------------------------------------------------------------------
$add('stdlib', $PHPVER, 'filter_var(url, FILTER_VALIDATE_URL)', 'url', 'validator',
    static function (string $v, array $c): array {
        $r = filter_var($v, FILTER_VALIDATE_URL);
        return $r === false ? rejected('filter_var returned false') : ok($c['host'], 'passthrough');
    });

$add('stdlib', $PHPVER, 'filter_var(addr, FILTER_VALIDATE_EMAIL)', 'email', 'validator',
    static function (string $v, array $c): array {
        $r = filter_var($v, FILTER_VALIDATE_EMAIL);
        return $r === false ? rejected('filter_var returned false') : ok(domain_of($r), 'passthrough');
    });

$add('stdlib', $PHPVER, 'filter_var(addr, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE)', 'email', 'validator',
    static function (string $v, array $c): array {
        $r = filter_var($v, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE);
        return $r === false ? rejected('filter_var returned false') : ok(domain_of($r), 'passthrough');
    });

$add('stdlib', $PHPVER, 'filter_var(host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)', 'host', 'validator',
    static function (string $v, array $c): array {
        $r = filter_var($v, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
        return $r === false ? rejected('filter_var returned false') : ok($c['host'], 'passthrough');
    });

// ---------------------------------------------------------------------------
// ext/standard  (parse_url)
// ---------------------------------------------------------------------------
$add('stdlib', $PHPVER, 'parse_url(url, PHP_URL_HOST)', 'url', 'downstream',
    static function (string $v, array $c): array {
        $h = parse_url($v, PHP_URL_HOST);
        if ($h === false) {
            return rejected('parse_url returned false (seriously malformed URL)');
        }
        if ($h === null || $h === '') {
            return rejected('parse_url returned no host');
        }
        return ok($h, 'parsed');
    });

// ---------------------------------------------------------------------------
// ext/intl  (idn_to_ascii, UTS 46)
// ---------------------------------------------------------------------------
if (function_exists('idn_to_ascii')) {
    $ICU = defined('INTL_ICU_VERSION') ? INTL_ICU_VERSION : 'unknown';

    $idna_err = static function (array $info): string {
        $names = [];
        foreach (get_defined_constants(true)['intl'] ?? [] as $k => $val) {
            if (str_starts_with($k, 'IDNA_ERROR_') && is_int($val) && ($info['errors'] & $val)) {
                $names[] = $k;
            }
        }
        return 'idn_to_ascii returned false; errors=' . ($info['errors'] ?? '?') . ' [' . implode('|', $names) . ']';
    };

    $add('intl', $ICU, 'idn_to_ascii(host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46)', 'host', 'downstream',
        static function (string $v, array $c) use ($idna_err): array {
            $info = [];
            $r = idn_to_ascii($v, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46, $info);
            return $r === false ? rejected($idna_err($info)) : ok($r, 'normalized');
        });

    $add('intl', $ICU, 'idn_to_ascii(host, IDNA_NONTRANSITIONAL_TO_ASCII|IDNA_CHECK_BIDI|IDNA_CHECK_CONTEXTJ|IDNA_USE_STD3_RULES, INTL_IDNA_VARIANT_UTS46)', 'host', 'downstream',
        static function (string $v, array $c) use ($idna_err): array {
            $info = [];
            $flags = IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ | IDNA_USE_STD3_RULES;
            $r = idn_to_ascii($v, $flags, INTL_IDNA_VARIANT_UTS46, $info);
            return $r === false ? rejected($idna_err($info)) : ok($r, 'normalized');
        });
} else {
    $SKIPPED[] = 'intl: idn_to_ascii() not available';
}

// ---------------------------------------------------------------------------
// ext/uri  (PHP 8.5: Uri\WhatWg\Url, Uri\Rfc3986\Uri)
// ---------------------------------------------------------------------------
$URIVER = phpversion('uri') ?: $PHPVER;
if (class_exists('Uri\WhatWg\Url')) {
    $add('ext-uri', $URIVER, '(new Uri\WhatWg\Url(url))->getAsciiHost()', 'url', 'downstream',
        static function (string $v, array $c): array {
            $u = new \Uri\WhatWg\Url($v);
            $h = $u->getAsciiHost();
            return ($h === null || $h === '') ? rejected('WhatWg\Url: no host') : ok($h, 'normalized');
        });
} else {
    $SKIPPED[] = 'ext-uri: class Uri\WhatWg\Url not present';
}
if (class_exists('Uri\Rfc3986\Uri')) {
    $add('ext-uri', $URIVER, '(new Uri\Rfc3986\Uri(url))->getHost()', 'url', 'downstream',
        static function (string $v, array $c): array {
            $u = new \Uri\Rfc3986\Uri($v);
            $h = $u->getHost();
            return ($h === null || $h === '') ? rejected('Rfc3986\Uri: no host') : ok($h, 'parsed');
        });
} else {
    $SKIPPED[] = 'ext-uri: class Uri\Rfc3986\Uri not present';
}

// ---------------------------------------------------------------------------
// egulias/email-validator 4
// ---------------------------------------------------------------------------
if (class_exists(EmailValidator::class)) {
    $EGV = pkg_version('egulias/email-validator');
    $eg = static function (string $label, Closure $mk) use ($add, $EGV): void {
        $add('egulias/email-validator', $EGV, "(new EmailValidator)->isValid(addr, new $label())", 'email', 'validator',
            static function (string $v, array $c) use ($mk): array {
                $ev = new EmailValidator();
                $validation = $mk();
                if ($ev->isValid($v, $validation)) {
                    return ok(domain_of($v), 'passthrough');
                }
                $e = $ev->getError();
                return rejected($e ? get_class($e->reason()) . ': ' . $e->description() : 'isValid returned false');
            });
    };
    $eg('RFCValidation', static fn() => new RFCValidation());
    $eg('NoRFCWarningsValidation', static fn() => new NoRFCWarningsValidation());
    if (class_exists('Spoofchecker') && class_exists(SpoofCheckValidation::class)) {
        $eg('Extra\SpoofCheckValidation', static fn() => new SpoofCheckValidation());
    } else {
        $SKIPPED[] = 'egulias SpoofCheckValidation: intl Spoofchecker not available';
    }
} else {
    $SKIPPED[] = 'egulias/email-validator: class not found';
}

// ---------------------------------------------------------------------------
// symfony/validator 7
// ---------------------------------------------------------------------------
if (class_exists(Validation::class)) {
    $SFV = pkg_version('symfony/validator');
    $validator = Validation::createValidator();
    $sf = static function (string $label, string $surface, Closure $mk) use ($add, $SFV, $validator): void {
        $add('symfony/validator', $SFV, "Validation::createValidator()->validate(v, $label)", $surface, 'validator',
            static function (string $v, array $c) use ($mk, $validator, $surface): array {
                $violations = $validator->validate($v, $mk());
                if (count($violations) === 0) {
                    return ok($surface === 'email' ? domain_of($v) : $c['host'], 'passthrough');
                }
                $msgs = [];
                foreach ($violations as $viol) {
                    $msgs[] = $viol->getMessage();
                }
                return rejected('ConstraintViolation: ' . implode('; ', $msgs));
            });
    };
    // Array options are deprecated since 7.3 -> named arguments.
    $sf("new Email(mode: 'html5')", 'email', static fn() => new Assert\Email(mode: Assert\Email::VALIDATION_MODE_HTML5));
    $sf("new Email(mode: 'strict')", 'email', static fn() => new Assert\Email(mode: Assert\Email::VALIDATION_MODE_STRICT));
    // requireTld passed explicitly (its current default, false) to silence the 7.1 deprecation.
    $sf('new Url(requireTld: false)', 'url', static fn() => new Assert\Url(requireTld: false));
    $sf('new Hostname()', 'host', static fn() => new Assert\Hostname());
} else {
    $SKIPPED[] = 'symfony/validator: class not found';
}

// ---------------------------------------------------------------------------
// league/uri 7
// ---------------------------------------------------------------------------
if (class_exists(\League\Uri\Uri::class)) {
    $add('league/uri', pkg_version('league/uri'), 'League\Uri\Uri::new(url)->getHost()', 'url', 'downstream',
        static function (string $v, array $c): array {
            $h = \League\Uri\Uri::new($v)->getHost();
            return ($h === null || $h === '') ? rejected('League\Uri: no host') : ok($h, 'parsed');
        });
} else {
    $SKIPPED[] = 'league/uri: class not found';
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
function encode_row(array $rec): string
{
    $s = json_encode($rec, JSON_UNESCAPED_SLASHES);
    if ($s === false) {
        $s = json_encode($rec, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    if ($s === false) {
        throw new RuntimeException('json_encode failed: ' . json_last_error_msg());
    }
    return $s;
}

function main(array $argv, array $ADAPTERS, array $SKIPPED): void
{
    $out = DEFAULT_OUT;
    for ($i = 1; $i < count($argv); $i++) {
        if ($argv[$i] === '--out' && isset($argv[$i + 1])) {
            $out = $argv[++$i];
        }
    }

    $corpus = json_decode(file_get_contents(CORPUS), true, 512, JSON_THROW_ON_ERROR);
    $cases = $corpus['cases'];
    $byId = [];
    foreach ($cases as $c) {
        $byId[$c['id']] = $c;
    }
    $good = $byId['ctl-good'];
    $bad = $byId['ctl-bad-space'];

    // --- self-check -------------------------------------------------------
    // Functions whose design legitimately cannot pass the control are listed
    // here with the reason; they are excluded from the self-check but their
    // rows are still written.
    $exempt = [
        '(new EmailValidator)->isValid(addr, new Extra\SpoofCheckValidation())'
            => 'SpoofCheckValidation only runs ICU Spoofchecker over the address; it performs no syntax check, so it cannot reject the interior space in ctl-bad-space by design',
    ];
    $failures = [];
    foreach ($ADAPTERS as $a) {
        if (isset($exempt[$a->function])) {
            fwrite(STDERR, "SELF-CHECK EXEMPT {$a->library} {$a->function}: {$exempt[$a->function]}\n");
            continue;
        }
        [$acc, , , $err] = $a->run($good[$a->surface], $good);
        if (!$acc) {
            $failures[] = "{$a->library} {$a->function}: rejected known-good " . json_encode($good[$a->surface]) . ": $err";
        }
        if ($a->kind === 'validator' && in_array($a->surface, ['host', 'email'], true)) {
            [$acc] = $a->run($bad[$a->surface], $bad);
            if ($acc) {
                $failures[] = "{$a->library} {$a->function}: accepted known-bad " . json_encode($bad[$a->surface]);
            }
        }
    }
    if ($failures) {
        fwrite(STDERR, "SELF-CHECK FAILED:\n");
        foreach ($failures as $f) {
            fwrite(STDERR, "  $f\n");
        }
        exit(2);
    }
    foreach ($SKIPPED as $s) {
        fwrite(STDERR, "SKIP $s\n");
    }

    // --- run ----------------------------------------------------------------
    if (!is_dir(dirname($out))) {
        mkdir(dirname($out), 0777, true);
    }
    $fh = fopen($out, 'w');
    if ($fh === false) {
        throw new RuntimeException("cannot open $out");
    }
    $n = 0;
    $stats = [];
    foreach ($ADAPTERS as $a) {
        $key = "{$a->library} | {$a->function}";
        $stats[$key] = ['acc' => 0, 'tot' => 0];
        foreach ($cases as $c) {
            if (!in_array($a->surface, $c['surfaces'], true)) {
                continue;
            }
            $value = $c[$a->surface];
            [$acc, $output, $okind, $err] = $a->run($value, $c);
            // JSON cannot carry invalid UTF-8. PHP's parse_url, for example, rewrites
            // continuation bytes 0x80-0x9F to '_' and leaves the lead byte behind.
            // `output` is then written with U+FFFD substitution and the exact bytes are
            // preserved as hex in `error` so the row stays byte-for-byte recoverable.
            if ($acc && $output !== null && !mb_check_encoding($output, 'UTF-8')) {
                $err = 'note: output is not valid UTF-8; `output` shows U+FFFD substitution; raw bytes hex=' . bin2hex($output);
            }
            $rec = [
                'ecosystem' => 'php', 'runtime' => PHP_VERSION,
                'library' => $a->library, 'version' => $a->version, 'function' => $a->function,
                'surface' => $a->surface, 'case_id' => $c['id'], 'input' => $value,
                'accepted' => $acc, 'output' => $output, 'output_kind' => $okind, 'error' => $err,
                'kind' => $a->kind,
            ];
            fwrite($fh, encode_row($rec) . "\n");
            $n++;
            $stats[$key]['tot']++;
            if ($acc) {
                $stats[$key]['acc']++;
            }
        }
    }
    fclose($fh);

    // --- table --------------------------------------------------------------
    $w = max(array_map('strlen', array_keys($stats)));
    fwrite(STDERR, "\n" . str_pad('function', $w) . " | accepted/total\n" . str_repeat('-', $w) . "-|---------------\n");
    foreach ($stats as $k => $s) {
        fwrite(STDERR, str_pad($k, $w) . " | {$s['acc']}/{$s['tot']}\n");
    }
    fwrite(STDERR, "\nwrote $n rows from " . count($ADAPTERS) . " adapters to $out\n");
}

main($argv, $ADAPTERS, $SKIPPED);
