/**
 * Configurable baseline: which checks run, how much each is worth, and which
 * thresholds define pass/fail. Shipped defaults live in `default-baseline.ts`;
 * users overlay a YAML/JSON file with `--baseline`.
 */
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import type { Severity } from "../types.ts";

export interface ProtocolRule {
  id: string;
  title: string;
  versions: string[];
  /** If the version is present the check fails; otherwise passes. */
  forbid?: boolean;
  /** If the version is missing the check fails. */
  require?: boolean;
  severity: Severity;
  weight: number;
  message: string;
}

export interface SuiteRule {
  id: string;
  title: string;
  /** Pseudo-selectors evaluated against the enumerated suite metadata. */
  rejectWeak?: boolean;
  rejectNoForwardSecrecy?: boolean;
  rejectAnonymous?: boolean;
  /** Reject RSA key exchange (no forward secrecy, ROBOT-adjacent). */
  rejectRsaKeyExchange?: boolean;
  /** Reject 3DES/RC4/DES even if metadata missed them. */
  rejectLegacyEncryption?: boolean;
  /** Highest protocol version this rule is limited to (optional). */
  appliesTo?: string[];
  severity: Severity;
  weight: number;
  message: string;
}

export interface RenegotiationBaseline {
  requireSecureRenegotiation: boolean;
  forbidClientInitiated: boolean;
  severity: Severity;
  weight: number;
}

export interface PreferenceBaseline {
  /** Server should enforce its own order. */
  requireServerOrder: boolean;
  severity: Severity;
  weight: number;
}

export interface OcspBaseline {
  /** What to expect when the certificate advertises an OCSP URL. */
  expectStapling: boolean;
  /** Fail if a staple is present but expired. */
  rejectExpired: boolean;
  severity: Severity;
  weight: number;
}

export interface HstsBaseline {
  require: boolean;
  minMaxAge: number;
  requireIncludeSubDomains: boolean;
  severity: Severity;
  weight: number;
}

export interface CertificateBaseline {
  minRsaBits: number;
  minEcBits: number;
  rejectSha1: boolean;
  maxDaysToExpiryWarn: number;
  severity: Severity;
  weight: number;
}

export interface ScoringBaseline {
  /** Grade thresholds, highest first. */
  grades: Array<{ minScore: number; grade: string }>;
}

export interface Baseline {
  version: string;
  name: string;
  description?: string;
  /** Concurrency cap and safety budget applied to every scan. */
  safety: {
    concurrency: number;
    retries: number;
    maxAttemptsPerHost: number;
    maxProbesPerVersion: number;
    deadlineMs: number;
    jitterMs: [number, number];
  };
  protocols: ProtocolRule[];
  suites: SuiteRule[];
  renegotiation: RenegotiationBaseline;
  preference: PreferenceBaseline;
  ocsp: OcspBaseline;
  hsts: HstsBaseline;
  certificate: CertificateBaseline;
  scoring: ScoringBaseline;
  /** Extra checks to skip entirely, by finding id. */
  disabled?: string[];
}

export class BaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BaselineError";
  }
}

/** Deep-merge a user overlay onto the defaults (arrays replace wholesale). */
export function mergeBaselines(base: Baseline, overlay: Partial<Baseline>): Baseline {
  return {
    ...base,
    ...overlay,
    safety: { ...base.safety, ...(overlay.safety ?? {}) },
    protocols: overlay.protocols ?? base.protocols,
    suites: overlay.suites ?? base.suites,
    renegotiation: { ...base.renegotiation, ...(overlay.renegotiation ?? {}) },
    preference: { ...base.preference, ...(overlay.preference ?? {}) },
    ocsp: { ...base.ocsp, ...(overlay.ocsp ?? {}) },
    hsts: { ...base.hsts, ...(overlay.hsts ?? {}) },
    certificate: { ...base.certificate, ...(overlay.certificate ?? {}) },
    scoring: { ...base.scoring, ...(overlay.scoring ?? {}) },
    disabled: overlay.disabled ?? base.disabled,
  };
}

/** Load and validate a baseline file (YAML or JSON). */
export function loadBaselineFile(path: string, base: Baseline): Baseline {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new BaselineError(`cannot read baseline ${path}: ${(err as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = path.endsWith(".json") ? JSON.parse(text) : parseYaml(text);
  } catch (err) {
    throw new BaselineError(`cannot parse baseline ${path}: ${(err as Error).message}`);
  }
  if (parsed === null || typeof parsed !== "object") {
    throw new BaselineError(`baseline ${path} must contain an object at the top level`);
  }
  assertValidOverlay(parsed as Record<string, unknown>, path);
  return mergeBaselines(base, parsed as Partial<Baseline>);
}

const SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);

function assertValidOverlay(obj: Record<string, unknown>, path: string): void {
  if (obj.protocols !== undefined && !Array.isArray(obj.protocols)) {
    throw new BaselineError(`${path}: protocols must be a list`);
  }
  if (obj.suites !== undefined && !Array.isArray(obj.suites)) {
    throw new BaselineError(`${path}: suites must be a list`);
  }
  for (const list of ["protocols", "suites"] as const) {
    const entries = obj[list];
    if (!Array.isArray(entries)) continue;
    entries.forEach((rule, i) => {
      if (rule === null || typeof rule !== "object") {
        throw new BaselineError(`${path}: ${list}[${i}] must be an object`);
      }
      const r = rule as Record<string, unknown>;
      if (typeof r.id !== "string" || r.id.length === 0) {
        throw new BaselineError(`${path}: ${list}[${i}] needs a string 'id'`);
      }
      if (typeof r.title !== "string" || r.title.length === 0) {
        throw new BaselineError(`${path}: ${list}[${i}] needs a string 'title'`);
      }
      if (typeof r.weight !== "number" || !Number.isFinite(r.weight) || r.weight < 0) {
        throw new BaselineError(
          `${path}: ${list}[${i}] needs a finite, non-negative 'weight'`,
        );
      }
      if (typeof r.severity !== "string" || !SEVERITIES.has(r.severity as Severity)) {
        throw new BaselineError(
          `${path}: ${list}[${i}] severity must be one of ${[...SEVERITIES].join(", ")}`,
        );
      }
      if (typeof r.message !== "string") {
        throw new BaselineError(`${path}: ${list}[${i}] needs a 'message'`);
      }
      if (list === "protocols") {
        // A protocol rule must name the versions it governs; the evaluator
        // iterates this list, so a missing or non-array value would crash it.
        if (!Array.isArray(r.versions) || r.versions.length === 0) {
          throw new BaselineError(`${path}: protocols[${i}] needs a non-empty 'versions' list`);
        }
        for (const v of r.versions) {
          if (typeof v !== "string") {
            throw new BaselineError(`${path}: protocols[${i}].versions must be strings`);
          }
        }
        if (r.forbid !== true && r.require !== true) {
          throw new BaselineError(`${path}: protocols[${i}] must set 'forbid: true' or 'require: true'`);
        }
      }
      if (list === "suites") {
        const selectors = [
          "rejectWeak",
          "rejectNoForwardSecrecy",
          "rejectAnonymous",
          "rejectRsaKeyExchange",
          "rejectLegacyEncryption",
        ] as const;
        if (!selectors.some((key) => r[key] === true)) {
          throw new BaselineError(
            `${path}: suites[${i}] needs at least one of ${selectors.join(", ")} set to true`,
          );
        }
        if (r.appliesTo !== undefined && !Array.isArray(r.appliesTo)) {
          throw new BaselineError(`${path}: suites[${i}].appliesTo must be a list of versions`);
        }
      }
    });
  }
  for (const section of [
    "safety",
    "renegotiation",
    "preference",
    "ocsp",
    "hsts",
    "certificate",
    "scoring",
  ] as const) {
    const value = obj[section];
    if (value !== undefined && (value === null || typeof value !== "object" || Array.isArray(value))) {
      throw new BaselineError(`${path}: ${section} must be an object`);
    }
  }
  assertNestedFields(obj, path);
}

/** Section keys that carry a `severity` the renderer looks up by name. */
const SEVERITY_SECTIONS = ["renegotiation", "preference", "ocsp", "hsts", "certificate"] as const;

/**
 * Validate the parts of the nested sections that a bad value would turn into a
 * crash or a wrong score at evaluation/render time, not merely a cosmetic one.
 */
function assertNestedFields(obj: Record<string, unknown>, path: string): void {
  for (const section of SEVERITY_SECTIONS) {
    const value = obj[section] as Record<string, unknown> | undefined;
    if (value && value.severity !== undefined) {
      if (typeof value.severity !== "string" || !SEVERITIES.has(value.severity as Severity)) {
        throw new BaselineError(
          `${path}: ${section}.severity must be one of ${[...SEVERITIES].join(", ")}`,
        );
      }
    }
  }

  const safety = obj.safety as Record<string, unknown> | undefined;
  if (safety) {
    for (const key of ["concurrency", "retries", "maxAttemptsPerHost", "maxProbesPerVersion", "deadlineMs"] as const) {
      const v = safety[key];
      if (v !== undefined && (typeof v !== "number" || !Number.isFinite(v) || v < 0)) {
        throw new BaselineError(`${path}: safety.${key} must be a finite, non-negative number`);
      }
    }
    if (safety.jitterMs !== undefined) {
      const jitter = safety.jitterMs;
      if (
        !Array.isArray(jitter) ||
        jitter.length !== 2 ||
        !jitter.every((n) => typeof n === "number" && Number.isFinite(n) && n >= 0)
      ) {
        throw new BaselineError(`${path}: safety.jitterMs must be a [min, max] pair of numbers`);
      }
    }
  }

  const scoring = obj.scoring as Record<string, unknown> | undefined;
  if (scoring && scoring.grades !== undefined) {
    const grades = scoring.grades;
    if (!Array.isArray(grades) || grades.length === 0) {
      throw new BaselineError(`${path}: scoring.grades must be a non-empty list`);
    }
    grades.forEach((g, i) => {
      if (g === null || typeof g !== "object") {
        throw new BaselineError(`${path}: scoring.grades[${i}] must be an object`);
      }
      const entry = g as Record<string, unknown>;
      if (typeof entry.minScore !== "number" || !Number.isFinite(entry.minScore)) {
        throw new BaselineError(`${path}: scoring.grades[${i}].minScore must be a finite number`);
      }
      if (typeof entry.grade !== "string" || entry.grade.length === 0) {
        throw new BaselineError(`${path}: scoring.grades[${i}].grade must be a string`);
      }
    });
  }

  if (obj.disabled !== undefined) {
    if (!Array.isArray(obj.disabled) || !obj.disabled.every((d) => typeof d === "string")) {
      throw new BaselineError(`${path}: disabled must be a list of finding ids`);
    }
  }
  for (const key of ["name", "version"] as const) {
    if (obj[key] !== undefined && typeof obj[key] !== "string") {
      throw new BaselineError(`${path}: ${key} must be a string`);
    }
  }
}
