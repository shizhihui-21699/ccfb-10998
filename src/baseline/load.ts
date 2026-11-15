/**
 * Baseline loading and validation.
 *
 * Hand-rolled validation against the schema's rules rather than a runtime
 * dependency: the shape is small, and a clear error message naming the bad
 * field matters more than generic schema output. Validating here means a
 * typo in a weight or an unknown check kind fails at load time, not after a
 * ten-minute scan.
 */
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import type { Baseline, BaselineCheck, CheckKind, CheckSeverity } from './evaluate.ts';

const CHECK_KINDS: readonly CheckKind[] = [
  'version-minimum',
  'version-forbidden',
  'no-weak-suites',
  'no-insecure-suites',
  'forward-secrecy-required',
  'server-cipher-preference',
  'secure-renegotiation',
  'no-client-renegotiation',
  'ocsp-stapling',
  'hsts-present',
  'hsts-max-age',
  'hsts-include-subdomains',
  'certificate-valid',
  'certificate-key-strength',
  'certificate-signature',
  'tls13-preferred',
  'custom-suite-forbidden',
];

const SEVERITIES: readonly CheckSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const KNOWN_BASELINES: Record<string, string> = {
  default: resolve(import.meta.dirname, '../../baseline/default.json'),
  'modern-internal': resolve(import.meta.dirname, '../../baseline/default.json'),
  'legacy-tolerant': resolve(import.meta.dirname, '../../baseline/legacy-tolerant.json'),
};

export class BaselineError extends Error {
  readonly path?: string;
  constructor(message: string, path?: string) {
    super(message);
    this.name = 'BaselineError';
    if (path !== undefined) this.path = path;
  }
}

/** Loads a baseline by name (built-in) or by path. */
export async function loadBaseline(nameOrPath: string): Promise<Baseline> {
  const path = KNOWN_BASELINES[nameOrPath] ?? resolve(nameOrPath);
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    throw new BaselineError(
      `cannot read baseline "${nameOrPath}" (looked at ${path}): ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`,
      path,
    );
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new BaselineError(`baseline at ${path} is not valid JSON: ${(err as Error).message}`, path);
  }
  return validateBaseline(raw, path);
}

/** Validates an already-parsed object and returns a typed Baseline. */
export function validateBaseline(raw: unknown, path?: string): Baseline {
    const where = path ? ` (${path})` : '';
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new BaselineError(`baseline${where} must be a JSON object`);
  }
  const obj = raw as Record<string, unknown>;

  if (typeof obj.id !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(obj.id)) {
    throw new BaselineError(`baseline${where}: "id" must be a lowercase kebab-case string`);
  }
  if (typeof obj.name !== 'string' || obj.name.trim() === '') {
    throw new BaselineError(`baseline${where}: "name" must be a non-empty string`);
  }
  if (obj.passScore !== undefined && (typeof obj.passScore !== 'number' || obj.passScore < 0 || obj.passScore > 100)) {
    throw new BaselineError(`baseline${where}: "passScore" must be a number between 0 and 100`);
  }
  if (!Array.isArray(obj.checks) || obj.checks.length === 0) {
    throw new BaselineError(`baseline${where}: "checks" must be a non-empty array`);
  }

  const seen = new Set<string>();
  const checks: BaselineCheck[] = obj.checks.map((c, i) => {
    const ctx = `baseline${where}: checks[${i}]`;
    if (typeof c !== 'object' || c === null) {
      throw new BaselineError(`${ctx} must be an object`);
    }
    const chk = c as Record<string, unknown>;
    if (typeof chk.id !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(chk.id)) {
      throw new BaselineError(`${ctx}: "id" must be a lowercase kebab-case string`);
    }
    if (seen.has(chk.id)) {
      throw new BaselineError(`${ctx}: duplicate check id "${chk.id}"`);
    }
    seen.add(chk.id);
    if (typeof chk.kind !== 'string' || !CHECK_KINDS.includes(chk.kind as CheckKind)) {
      throw new BaselineError(`${ctx} ("${chk.id}"): unknown check kind "${String(chk.kind)}"; valid kinds: ${CHECK_KINDS.join(', ')}`);
    }
    if (typeof chk.weight !== 'number' || !Number.isFinite(chk.weight) || chk.weight < 0) {
      throw new BaselineError(`${ctx} ("${chk.id}"): "weight" must be a non-negative number`);
    }
    if (typeof chk.severity !== 'string' || !SEVERITIES.includes(chk.severity as CheckSeverity)) {
      throw new BaselineError(`${ctx} ("${chk.id}"): "severity" must be one of ${SEVERITIES.join(', ')}`);
    }
    if (chk.informational !== undefined && typeof chk.informational !== 'boolean') {
      throw new BaselineError(`${ctx} ("${chk.id}"): "informational" must be a boolean`);
    }
    if (chk.params !== undefined && (typeof chk.params !== 'object' || chk.params === null || Array.isArray(chk.params))) {
      throw new BaselineError(`${ctx} ("${chk.id}"): "params" must be an object`);
    }
    if (chk.message !== undefined && typeof chk.message !== 'string') {
      throw new BaselineError(`${ctx} ("${chk.id}"): "message" must be a string`);
    }

    // Semantic checks for params that the evaluator depends on. Catching these
    // here turns a confusing runtime "skip" into an actionable error.
    validateParams(chk.id, chk.kind as CheckKind, chk.params as Record<string, unknown> | undefined, ctx);

    const out: BaselineCheck = {
      id: chk.id,
      kind: chk.kind as CheckKind,
      weight: chk.weight,
      severity: chk.severity as CheckSeverity,
      ...(chk.informational !== undefined ? { informational: chk.informational } : {}),
      ...(chk.params !== undefined ? { params: chk.params as Record<string, unknown> } : {}),
      ...(chk.message !== undefined ? { message: chk.message } : {}),
    };
    return out;
  });

  return {
    id: obj.id,
    name: obj.name,
    ...(typeof obj.description === 'string' ? { description: obj.description } : {}),
    ...(typeof obj.passScore === 'number' ? { passScore: obj.passScore } : {}),
    checks,
  };
}

const VALID_VERSIONS = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function validateParams(id: string, kind: CheckKind, params: Record<string, unknown> | undefined, ctx: string): void {
  const p = params ?? {};
  switch (kind) {
    case 'version-minimum': {
      const v = p.minimumVersion ?? 'TLSv1.2';
      if (!VALID_VERSIONS.includes(v as string)) {
        throw new BaselineError(`${ctx} ("${id}"): minimumVersion must be one of ${VALID_VERSIONS.join(', ')}`);
      }
      break;
    }
    case 'version-forbidden': {
      const vs = p.versions ?? [];
      if (!Array.isArray(vs) || vs.some((v) => !VALID_VERSIONS.includes(v as string))) {
        throw new BaselineError(`${ctx} ("${id}"): versions must be an array of ${VALID_VERSIONS.join(', ')}`);
      }
      break;
    }
    case 'hsts-max-age': {
      const n = p.minimumSeconds ?? 15768000;
      if (typeof n !== 'number' || n < 0) {
        throw new BaselineError(`${ctx} ("${id}"): minimumSeconds must be a non-negative number`);
      }
      break;
    }
    case 'certificate-valid': {
      const n = p.minimumDaysRemaining ?? 0;
      if (typeof n !== 'number' || n < 0) {
        throw new BaselineError(`${ctx} ("${id}"): minimumDaysRemaining must be a non-negative number`);
      }
      break;
    }
    case 'certificate-key-strength': {
      for (const k of ['minimumRsaBits', 'minimumEcBits'] as const) {
        if (p[k] !== undefined && (typeof p[k] !== 'number' || (p[k] as number) < 0)) {
          throw new BaselineError(`${ctx} ("${id}"): ${k} must be a non-negative number`);
        }
      }
      break;
    }
    case 'custom-suite-forbidden': {
      const s = p.suites ?? [];
      if (!Array.isArray(s)) throw new BaselineError(`${ctx} ("${id}"): suites must be an array`);
      break;
    }
    default:
      break;
  }
}
