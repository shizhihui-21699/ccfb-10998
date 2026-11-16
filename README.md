# tls-doctor

An active TLS configuration health-check for a fleet of internal services.
Point it at `host:port` targets and it performs real TLS handshakes to discover
what each service actually supports, then scores it against a configurable
baseline.

It is **not** a vulnerability scanner and not a substitute for a TLS terminator.
It is an inventory-and-guardrail tool: *what protocols does this endpoint
accept, which suites on each, does it let a client renegotiate, is it stapling
OCSP, and where does it fall short of the baseline?*

## What it checks

| Check | How |
| --- | --- |
| **Protocol versions** | One ClientHello per version (SSLv3 … TLS 1.3), so a rejection is unambiguous. |
| **Cipher suites per version** | Iterative elimination: offer every candidate, the server picks one, remove it, repeat. `N` supported suites cost `N+1` handshakes instead of `N`. |
| **Server cipher order** | Offer the same two suites in both orders; if the choice does not change, the server enforces its own preference. |
| **Client-initiated renegotiation** | Complete a real TLS 1.2 handshake and ask for a renegotiation; a refusal (alert) is the hardened result. |
| **Secure renegotiation (RFC 5746)** | Whether the server echoes `renegotiation_info`, closing the 2009 prefix-injection flaw. |
| **OCSP stapling** | Request `status_request` and read the `CertificateStatus` staple; parse it to good / revoked / expired. Verifies stapling *happens*, not the signature chain. |
| **HSTS** | One HTTPS `GET /`, then parse `Strict-Transport-Security` (max-age, includeSubDomains, preload). |
| **Certificate** | Key type/size, signature algorithm (SHA-1), validity window, hostname coverage, OCSP AIA URL. |

Everything is done with hand-built TLS messages over plain `net.Socket`s, so the
tool can offer TLS 1.0/1.1 and RC4/3DES/EXPORT suites that a modern OpenSSL
build refuses to negotiate. It never finishes a handshake for the discovery
probes: it reads the server's first flight and disconnects.

## Quick start

```bash
npm install

# Start the fixture fleet (15 servers, 127.0.0.1 only, deliberately varied configs)
npm run fixtures

# In another terminal: scan them
node src/cli.ts scan 127.0.0.1:15401 127.0.0.1:15403 localhost:15407

# Scan a list of real services
node src/cli.ts scan @targets.txt --json report.json --markdown report.md --html report.html
```

Requires Node 22.6+ (native TypeScript type-stripping). No build step is needed
for `node src/cli.ts`; `npm run build` produces `dist/` for a compiled binary.

## Safety: it will not knock a service over

Scanning production must not become the incident. Every network action is
bounded:

- **Bounded concurrency.** A global cap on in-flight connections per host
  (default 6), and a separate cap on how many hosts are scanned at once.
- **Jitter.** A small random delay before each connect, so 200 services do not
  receive a synchronised burst.
- **Retry with backoff.** Transient failures (`ECONNRESET`, timeouts) retry with
  exponential backoff and full jitter; protocol rejections do not retry.
- **Per-host budget.** A hard ceiling on connections per host (default 260) and a
  wall-clock deadline (default 120 s). Enumeration reports `truncated` rather
  than running away.
- **Short-lived connections.** Discovery probes send one ClientHello and
  disconnect after the first flight. The only completed handshakes are the
  renegotiation test and the HSTS request.
- **Timeouts on every phase.** Connect and read timeouts are enforced
  separately, and an idle window ends the "collect the certificate" phase as
  soon as the server stops talking.

A scan of a single well-behaved host costs roughly 20 connections and about one
second. All of this is configurable in the `safety` block of a baseline.

## The baseline

The default baseline (`baselines/default.yaml`, mirrored in code) targets an
internal fleet: TLS 1.2+ required, TLS 1.0/1.1 and weak suites as failures,
client renegotiation and SHA-1 certificates forbidden, HSTS encouraged. Every
rule has a `severity` and a `weight`; the score is weighted points earned over
points available, and `unable to test` checks are excluded rather than counted
as failures.

Pass an overlay with `--baseline`:

```yaml
# strict.yaml — everything below this overlays the default
name: strict-internal
protocols:
  - id: proto-tls12
    title: TLS 1.2 disabled
    versions: [TLSv1.2]
    forbid: true
    severity: medium
    weight: 4
    message: We require TLS 1.3 everywhere.
  - id: proto-tls13
    title: TLS 1.3 enabled
    versions: [TLSv1.3]
    require: true
    severity: high
    weight: 10
    message: TLS 1.3 must be enabled.
suites:
  - id: suite-weak
    title: No weak cipher suites
    rejectWeak: true
    severity: critical
    weight: 20
    message: Any RC4/3DES/DES/EXPORT/NULL suite is unacceptable.
hsts:
  minMaxAge: 31536000
  requireIncludeSubDomains: true
```

Lists (`protocols`, `suites`) replace the defaults wholesale; object sections
(`safety`, `hsts`, `certificate`, …) are merged field by field.

`node src/cli.ts baseline` prints the effective baseline after overlays, which
is handy for diffing a change before rolling it out.

## Exit codes

`0` all scored checks pass · `1` any failing check or unreachable host ·
`2` usage error. Wire it into CI and fail the pipeline on a regression.

## Report formats

- **Terminal** per-host cards plus a fleet summary table.
- **`--json`** complete machine-readable results (every suite, every finding).
- **`--markdown`** a report suitable for a ticket or a wiki page.
- **`--html`** a single self-contained file, light/dark aware, no external assets.

## The fixture fleet

The test suite and `npm run fixtures` start real servers on `127.0.0.1` with
known, deliberately different configurations:

| Fixture | Configuration |
| --- | --- |
| `modern` | TLS 1.2+1.3, ECDHE/AEAD only, HSTS, renegotiation disabled |
| `tls10-open` | TLS 1.0–1.2 enabled |
| `weak-ciphers` | RC4 and 3DES negotiable (LibreSSL) |
| `client-order` | follows the client's cipher order |
| `reneg-open` | accepts client-initiated renegotiation |
| `expired-cert` | expired leaf |
| `wrong-host` | certificate misses the scanned hostname |
| `sha1-small` | SHA-1 signature |
| `small-key` | 1024-bit RSA |
| `no-hsts` | no HSTS header |
| `ocsp-good` / `ocsp-revoked` / `ocsp-expired` | stapled OCSP: good, revoked, and expired |
| `tls13-only` | TLS 1.3 only |

Three runtimes are used because no single one covers every case: `node:tls`,
OpenSSL 3 (`-status_file` for stapling) and LibreSSL (`/usr/bin/openssl`, whose
cipher table still negotiates RC4/3DES). Fixtures that cannot start are
skipped, so the suite works on machines without LibreSSL.

## Tests

```bash
npm test          # unit + integration; integration starts its own fixtures
npm run typecheck
```

## Layout

```
src/
  tls/         wire format, cipher table, OCSP DER reader
  net/         scheduler (concurrency/retry/backoff), one-shot ClientHello probe
  probes/      protocols, ciphers, preference, renegotiation, OCSP, HSTS, certificate
  evaluate/    baseline → findings → weighted score
  scan/        fleet orchestration
  report/      terminal, JSON, Markdown, HTML
  baseline/    schema, defaults, loading/merge
fixtures/      PKI generation, fixture servers, runner
test/          unit and integration tests
```

## Limitations

- Discovery probes do not complete a handshake, so they cannot see anything the
  server sends after `ServerHello` under TLS 1.3 (e.g. a TLS 1.3-only endpoint's
  OCSP staple is checked via `node:tls`, and its certificate is fetched by a
  completed handshake).
- OCSP staples are parsed but not cryptographically verified — this is a
  configuration check, not a revocation client.
- Cipher enumeration is bounded by an offer list; a server that negotiates a
  suite outside it is reported once as an anomaly rather than enumerated.
- Chain trust is reported from the local trust store and is informational:
  internal services routinely use private CAs.
