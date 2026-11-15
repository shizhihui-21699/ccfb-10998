/**
 * Renegotiation checks.
 *
 * Two separate facts, deliberately reported separately because they mean
 * different things:
 *
 *   1. Secure renegotiation support (RFC 5746, 2010). Detectable from the
 *      ServerHello alone: a conforming server echoes renegotiation_info. A
 *      server that never sends it either does not implement RFC 5746 or was
 *      built to ignore the extension, which is the condition that enabled the
 *      2009 renegotiation prefix-injection attack. This is a passive check
 *      costing zero extra connections beyond the ones we already make.
 *
 *   2. Whether the server *accepts a client-initiated renegotiation on a live
 *      TLS 1.2 connection*. This is the "insecure renegotiation" that most
 *      scanners test for, because it lets a peer multiply handshakes on an
 *      established session. It requires a second ClientHello inside the
 *      session. We use node:tls's renegotiate() for it, and only ever do one
 *      attempt per endpoint.
 *
 *      TLS 1.3 removed renegotiation entirely, so the live test only applies
 *      to TLS 1.2 down.
 *
 * Three outcomes, not two
 * -----------------------
 * "Accepted" and "refused" are not exhaustive. A service that is not an HTTP
 * server — Postgres, Redis, an LDAP listener — will accept the renegotiation
 * ClientHello, neither act on it nor refuse it, and leave the connection open.
 * Waiting for the full per-connection timeout on every such endpoint turns a
 * scan of database ports into something very slow. Worse, treating that silence
 * as "refused" reports an unproven pass as a pass.
 *
 * So the result carries `conclusive`:
 *
 *   accepted    -> clientInitiatedAccepted: true,  conclusive: true
 *   refused     -> clientInitiatedAccepted: false, conclusive: true   (alert/rejection)
 *   no answer   -> clientInitiatedAccepted: false, conclusive: false  (short wait)
 *
 * The short no-answer wait (RENEG_RESPONSE_WAIT_MS) is separate from the
 * connection timeout: a server that means to refuse sends a fatal alert almost
 * immediately, so a second of silence is already strong evidence that this
 * endpoint has no opinion. The scoring layer skips unproven cases rather than
 * counting them as passes.
 */
import { tlsSession } from './probe.ts';
import type { RenegotiationResult, TlsVersionName } from '../types.ts';

export interface RenegotiationOptions {
  host: string;
  port: number;
  serverName?: string;
  timeoutMs: number;
  rejectUnauthorized: boolean;
  caFile?: string;
  /** Version to run the live test on; undefined skips the live test. */
  liveTestVersion?: TlsVersionName;
  /** Skip the live test entirely (passive extension check only). */
  passiveOnly: boolean;
}

/**
 * How long to wait for a reply to the renegotiation ClientHello. A server that
 * refuses sends an alert at once; one that ignores it says nothing. One second
 * distinguishes the two without paying the full connection timeout per endpoint.
 */
const RENEG_RESPONSE_WAIT_MS = 1200;

export async function probeRenegotiation(
  opts: RenegotiationOptions,
  passiveSupported: boolean,
): Promise<RenegotiationResult> {
  if (opts.passiveOnly || !opts.liveTestVersion) {
    const legacyEnabled = opts.liveTestVersion !== undefined;
    return {
      secureRenegotiationSupported: passiveSupported,
      // No live test ran. If the endpoint has no TLS <= 1.2 at all, there is
      // nothing to renegotiate; otherwise the test was simply disabled.
      applicable: legacyEnabled,
      conclusive: false,
      clientInitiatedAccepted: false,
      detail: opts.passiveOnly
        ? 'live renegotiation test disabled by configuration'
        : 'no TLS 1.2 connection available for the live renegotiation test',
    };
  }

  const result = await liveRenegotiationTest(opts, opts.liveTestVersion);
  return {
    ...result,
    secureRenegotiationSupported: passiveSupported,
    applicable: true,
  };
}

async function liveRenegotiationTest(
  opts: RenegotiationOptions,
  version: TlsVersionName,
): Promise<Omit<RenegotiationResult, 'secureRenegotiationSupported' | 'applicable'>> {
  return new Promise((resolve) => {
    import('node:tls')
      .then((tls) => {
        let settled = false;
        let socket: import('node:tls').TLSSocket | undefined;

        const finish = (r: Omit<RenegotiationResult, 'secureRenegotiationSupported' | 'applicable'>) => {
          if (settled) return;
          settled = true;
          clearTimeout(deadline);
          clearTimeout(responseTimer);
          socket?.destroy();
          resolve(r);
        };

        // Overall deadline for reaching a connected socket.
        const deadline = setTimeout(() => {
          finish({
            clientInitiatedAccepted: false,
            conclusive: false,
            testedOn: version,
            detail: `could not establish a ${version} session within ${opts.timeoutMs}ms`,
          });
        }, opts.timeoutMs);
        // Deliberately not unref'd.

        let responseTimer: NodeJS.Timeout | undefined;

        socket = tls.connect(
          {
            host: opts.host,
            port: opts.port,
            servername: opts.serverName,
            minVersion: (version === 'TLSv1.2' ? 'TLSv1.2' : version === 'TLSv1.1' ? 'TLSv1.1' : 'TLSv1.0') as import('node:tls').SecureVersion,
            maxVersion: version as import('node:tls').SecureVersion,
            rejectUnauthorized: false, // renegotiation behaviour is independent of trust
            checkServerIdentity: () => undefined,
          },
          () => {
            clearTimeout(deadline);
            // One renegotiation attempt, on the established connection.
            setTimeout(() => {
              try {
                const ret = socket!.renegotiate({}, (err: Error | null) => {
                  if (!err) {
                    finish({
                      clientInitiatedAccepted: true,
                      conclusive: true,
                      testedOn: version,
                      detail: 'server accepted a client-initiated renegotiation (second handshake completed)',
                    });
                    return;
                  }
                  const code = (err as NodeJS.ErrnoException).code ?? '';
                  const { conclusive, detail } = classifyRenegError(code, err.message);
                  finish({ clientInitiatedAccepted: false, conclusive, testedOn: version, detail });
                });
                if (ret === false) {
                  finish({
                    clientInitiatedAccepted: false,
                    conclusive: true,
                    testedOn: version,
                    detail: 'the local TLS stack declined to send a renegotiation on this connection',
                  });
                  return;
                }
                // A refusal arrives as a fatal alert almost immediately; silence
                // past this window means the server neither accepted nor
                // refused, which is an inconclusive result rather than a pass.
                responseTimer = setTimeout(() => {
                  finish({
                    clientInitiatedAccepted: false,
                    conclusive: false,
                    testedOn: version,
                    detail:
                      `server neither answered nor refused the renegotiation within ${RENEG_RESPONSE_WAIT_MS}ms ` +
                      '(typical of a non-HTTP TLS service; reported as unproven, not as a pass)',
                  });
                }, RENEG_RESPONSE_WAIT_MS);
              } catch (err) {
                finish({
                  clientInitiatedAccepted: false,
                  conclusive: false,
                  testedOn: version,
                  detail: `renegotiation attempt failed immediately: ${(err as Error).message}`,
                });
              }
            }, 50);
          },
        );

        socket.on('error', (err: NodeJS.ErrnoException) => {
          finish({
            clientInitiatedAccepted: false,
            conclusive: false,
            testedOn: version,
            detail: `live test connection failed (${err.code ?? 'error'}): ${err.message}`,
          });
        });
        socket.on('close', () => {
          if (!settled) {
            finish({
              clientInitiatedAccepted: false,
              conclusive: false,
              testedOn: version,
              detail: 'connection closed during the renegotiation attempt',
            });
          }
        });
      })
      .catch((err: Error) => {
        resolve({
          clientInitiatedAccepted: false,
          conclusive: false,
          detail: `could not load node:tls: ${err.message}`,
        });
      });
  });
}

/** Distinguishes an explicit refusal (conclusive) from an ambiguous failure. */
function classifyRenegError(code: string, message: string): { conclusive: boolean; detail: string } {
  if (/NO_RENEGOTIATION/.test(code) || /no renegotiation/i.test(message)) {
    return { conclusive: true, detail: 'server explicitly refused a client-initiated renegotiation (good)' };
  }
  if (/WRONG_SSL_VERSION|HANDSHAKE_FAILURE|PROTOCOL_IS_SHUTDOWN|ALERT/i.test(code) || /alert/i.test(message)) {
    return { conclusive: true, detail: `server rejected the renegotiation attempt (${code || 'alert'})` };
  }
  return {
    conclusive: false,
    detail: `renegotiation attempt ended without a definite answer (${code || 'error'}: ${message.split('\n')[0]})`,
  };
}
