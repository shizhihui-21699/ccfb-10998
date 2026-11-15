/**
 * OCSP-stapling lab server, backed by `openssl s_server`.
 *
 * Why a separate process: node:tls cannot be told to staple a canned
 * OCSP response, and OpenSSL's own server is the only local tool that can.
 * This is the one profile where the lab depends on the system openssl binary;
 * if it is missing the profile reports itself unavailable instead of failing
 * the whole lab.
 *
 * The server is started with -status_file so it sends a real DER response
 * produced by lab/make-certs.sh. Clients that ask for a staple receive it,
 * which is exactly the condition the checkup's OCSP check must detect.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import { existsSync } from 'node:fs';

export interface StaplingServer {
  port: number;
  process: ChildProcess;
  close: () => Promise<void>;
}

/** Waits until the port accepts a TCP connection, or gives up. */
function waitForPort(port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const attempt = () => {
      const sock = net.connect({ host: '127.0.0.1', port });
      sock.setTimeout(50);
      sock.once('connect', () => {
        sock.destroy();
        resolve(true);
      });
      const fail = () => {
        sock.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 100);
      };
      sock.once('error', fail);
      sock.once('timeout', fail);
    };
    attempt();
  });
}

export interface StaplingOptions {
  certPath: string;
  keyPath: string;
  chainPath?: string;
  /** DER-encoded OCSP response to staple. */
  responseDerPath: string;
  port: number;
  opensslBin?: string;
}

/** Starts `openssl s_server` with stapling enabled on the given port. */
export async function startStaplingServer(opts: StaplingOptions): Promise<StaplingServer> {
  if (!existsSync(opts.responseDerPath)) {
    throw new Error(`OCSP response not found: ${opts.responseDerPath} (run lab/make-certs.sh)`);
  }
  const bin = opts.opensslBin ?? 'openssl';

  const args = [
    's_server',
    '-accept',
    String(opts.port),
    '-cert',
    opts.certPath,
    '-key',
    opts.keyPath,
    '-status_file',
    opts.responseDerPath,
    '-www',
    '-quiet',
    '-min_protocol',
    'TLSv1.2',
  ];
  if (opts.chainPath) args.push('-cert_chain', opts.chainPath);

  const child = spawn(bin, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr?.on('data', (d: Buffer) => {
    stderr += d.toString();
    if (stderr.length > 4096) stderr = stderr.slice(-4096);
  });

  const started = await waitForPort(opts.port, 5000);
  if (!started) {
    child.kill();
    throw new Error(`openssl s_server did not start on port ${opts.port}: ${stderr.trim() || 'no output'}`);
  }

  return {
    port: opts.port,
    process: child,
    close: () =>
      new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve();
          return;
        }
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
        // Do not let a wedged openssl keep the lab alive.
        setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            /* already gone */
          }
          resolve();
        }, 1000).unref();
      }),
  };
}
