# tls-checkup

Actively probes the TLS configuration of internal services — with one
handshake per protocol version and per accepted cipher suite — and scores each
endpoint against a configurable baseline.

Answers, for each `host:port`:

| Question | How it is answered |
|---|---|
| Which protocol versions are enabled? | One ClientHello per version (TLS 1.0 – 1.3), read the ServerHello or the alert |
| Which cipher suites does each version accept? | Adaptive enumeration: offer all candidates, remove the chosen one, repeat until the server rejects |
| Does the server enforce its own suite order? | Offer the same two suites in both orders; same pick twice means server preference |
| Are insecure suites (RC4, 3DES, NULL, anonymous, export) still accepted? | They are offered explicitly; the raw hello path can offer suites node:tls refuses to build |
| Is insecure renegotiation possible? | RFC 5746 extension presence (passive) plus one live client-initiated renegotiation attempt on TLS 1.2. Three outcomes: accepted, refused, or no answer (reported as unproven, never as a pass) |
| Is OCSP stapling working? | Live request for a staple on TLS 1.2 and 1.3, DER parsed to good/revoked/unknown |
| How is HSTS configured? | `GET /` on the TLS port, plus an optional plain-HTTP fetch, parsed per RFC 6797 |
| What is the certificate state? | Expiry, key type and size, signature algorithm, chain length, self-signed |

## Quick start

Node 23.6+ (this repo is developed against Node 26). No runtime dependencies.

```bash
# 1. Start the lab (self-contained TLS servers with known-bad configs)
./lab/make-certs.sh
node lab/run-lab.ts --cert lab/certs/server.pem --key lab/certs/server.key \
  --chain lab/certs/ca.pem --ocsp lab/certs/response.der --port 18443

# 2. In another terminal, scan it
node src/cli.ts examples/lab-targets.txt --no-color

# 3. Or point it at real hosts
node src/cli.ts --target api.internal.example:443 --target db.internal:5432
```

## Targets

A target file has one target per line, `#` comments allowed:

```
api.internal.example                 # port 443 assumed
db.internal.example:5432
cache.internal:6379 cache-primary    # optional display name
web.internal:443 http:80             # also fetch plain HTTP on 80 for HSTS
[2001:db8::1]:8443 ipv6-service      # bracketed IPv6
```

`--target host[:port]` may be repeated instead of using a file.

## Baselines

A baseline is JSON: a list of weighted checks. Two ship with the tool
(`baseline/default.json`, `baseline/legacy-tolerant.json`); copy one and edit
it rather than editing in place.

Scoring is `100 * earned / possible`, where checks whose data could not be
collected are excluded from both sides. A failed informational check produces a
finding but no score movement. An endpoint that cannot be reached scores 0 —
never 100 by omission.

Check kinds: `version-minimum`, `version-forbidden`, `tls13-preferred`,
`no-weak-suites`, `no-insecure-suites`, `forward-secrecy-required`,
`server-cipher-preference`, `secure-renegotiation`, `no-client-renegotiation`,
`ocsp-stapling`, `hsts-present`, `hsts-max-age`, `hsts-include-subdomains`,
`certificate-valid`, `certificate-key-strength`, `certificate-signature`,
`custom-suite-forbidden`. `baseline/baseline.schema.json` documents the shape.

```bash
node src/cli.ts targets.txt --baseline baseline/legacy-tolerant.json
node src/cli.ts targets.txt --baseline ./team-baseline.json --format md --out report.md
```

## Not knocking services over

The defaults are deliberately gentle, and the limits are explicit rather than
emergent:

- **One connection at a time per endpoint.** Endpoints are grouped by host and
  walked in order by a single worker. `--concurrency` parallelises *endpoints*,
  never connections to one service. Measured: a scan of one endpoint never
  exceeded 1 simultaneous connection.
- **One handshake per fact.** A probe stops at ServerHello. It never sends
  Finished, never negotiates keys, and never sends application data except the
  optional `GET /` for HSTS. Servers see an ordinary client that hung up.
- **Adaptive enumeration, not brute force.** Offering all candidates and
  removing the accepted suite costs one handshake per *supported* suite plus
  one rejection, not one per candidate (≈60).
- **Hard budgets.** `--max-handshakes` caps a whole run; the per-endpoint budget
  is derived from `--max-suites`. `--delay` (default 20 ms) separates
  consecutive handshakes to the same endpoint.
- **No retries.** An unreachable endpoint is reported, not retried. Retrying
  unreachable services is what turns a checkup into a load test.
- **No renegotiation storms.** Exactly one client-initiated renegotiation
  attempt per endpoint, only on TLS 1.2 or older, only when enabled. A server
  that stays silent is given ~1 s, not the full connection timeout, because
  non-HTTP TLS services (Postgres, Redis, LDAP) never answer that ClientHello.
- **Every connection has a deadline** (`--timeout`, default 5 s) and is closed
  on expiry. HTTP exchanges have a shorter one (1 s), since a TLS service that
  is not HTTP will hold the socket open forever rather than reply.

For fragile appliances, lower further: `--concurrency 1 --delay 100
--max-suites 8`.

## Options

```
--baseline <name|path>   default | legacy-tolerant | path to JSON
--concurrency <n>        endpoints in parallel (default 4)
--timeout <ms>           per-connection timeout (default 5000)
--max-suites <n>         suites per version (default 32)
--max-handshakes <n>     whole-run ceiling (default 4000)
--delay <ms>             gap between handshakes to one endpoint (default 20)
--no-ocsp / --no-hsts / --no-renegotiation
--verify-certs / --ca <path>
--format <terminal|json|md|html>   --out <path>
--verbose                evidence and skipped checks
--fail-under <score>     per-endpoint threshold (default: baseline passScore)
```

Exit codes: `0` all compliant · `1` some below threshold · `2` usage or
configuration error · `3` nothing answered at all (usually a wrong target list
or a network problem, as distinct from "the services are insecure").

## The lab

`lab/` starts up to seven servers on consecutive ports, each deliberately
misconfigured in one or two ways. The lab is the oracle for the tool's own
tests: each profile declares what it does, and `test/lab.test.ts` asserts that
the probes observe exactly that.

| Profile | What it does | Expected verdict |
|---|---|---|
| `modern` | TLS 1.2+1.3, AEAD ECDHE, server preference, full HSTS | passes |
| `legacy` | TLS 1.0/1.1 still on, CBC suites, client preference | critical findings |
| `tls13only` | TLS 1.3 only | passes; renegotiation reported not-applicable |
| `weak` | TLS 1.2 static-RSA CBC only | weak-suite and forward-secrecy findings |
| `nohsts` | clean TLS, no HSTS header | medium finding |
| `http-hsts` | HSTS only on a plain-HTTP redirect, 1-hour max-age | "port does not serve TLS" + short max-age |
| `stapling` | `openssl s_server` stapling a real DER response | OCSP stapling detected, status `good` |

Not reproducible on this machine's OpenSSL 4 build, and therefore documented
rather than faked: RC4 and 3DES suites (removed from the default provider),
anonymous DH (not negotiable without DH parameters), and a server that *rejects*
client renegotiation. The tool still detects all of these on services that have
them — the detection path is exercised by unit tests with hand-built
ServerHellos.

## Design notes

**Why a hand-rolled ClientHello** (`src/tls/hello.ts`): node:tls validates its
cipher list against its OpenSSL build and refuses to construct a context that
offers RC4 or 3DES. For a checkup, the weak suites are precisely what must be
offerable, so the hello is built byte by byte. It also keeps each probe to a
single round trip.

**Why node:tls is still used** for OCSP, HSTS, certificates and live renegotiation:
those facts need a completed handshake or an HTTP exchange, and node:tls
supplies both correctly. Neither path depends on which suite was negotiated.

**Suite classification** (`src/tls/suites.ts`) judges mode (AEAD vs CBC) and
key exchange (ephemeral vs static) separately, because they are independent:
`TLS_RSA_WITH_AES_128_GCM_SHA256` is AEAD but has no forward secrecy, and
`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` has forward secrecy but a SHA-1 MAC. Both
are weak, for different reasons, and the report says which.

**The IANA registry** (`src/tls/suite-registry.generated.ts`) is generated from
`tls-parameters-4.csv` and committed, so no network access is needed at runtime.
Regenerate with `node scripts/gen-suite-registry.ts <csv>`.

## Development

```bash
npm test          # 89 tests: codec, parsers, classification, baseline, scheduler, CLI, lab
npm run typecheck
./lab/make-certs.sh
```

The test suite has two layers: pure offline tests (byte-level codec, parsers,
classification, scoring, scheduling limits) and the lab integration tests, which
skip cleanly if the certificates have not been generated.
