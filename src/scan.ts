import { basename } from 'node:path';
import { discoverRepos } from './discovery.js';
import { detectEcosystem, detectSecondaryEcosystems } from './ecosystem.js';
import { buildReport } from './report.js';
import type { NpmAuditOutcome } from './audit/npm.js';
import type { PipAuditOutcome } from './audit/pip.js';
import type { Ecosystem, Report, RepoResult } from './types.js';

export interface ScanDeps {
  /** Motor npm inyectable (real en el CLI, fake en tests). */
  auditNpm: (repoPath: string) => Promise<NpmAuditOutcome>;
  /** Motor pip inyectable. */
  auditPip: (repoPath: string) => Promise<PipAuditOutcome>;
  /** Progreso "repo N/M": current, total, nombre del repo. */
  onProgress?: (current: number, total: number, repoName: string) => void;
  /** Descubrimiento inyectable (default: barrido real de la carpeta). */
  discover?: (root: string) => string[];
  /** Detección de ecosistema inyectable (default: por archivos marcadores). */
  detect?: (repoPath: string) => Ecosystem;
  now?: Date;
}

type RepoOutcome = Pick<RepoResult, 'status' | 'statusReason' | 'findings'>;

/**
 * Corre el motor del ecosistema con aislamiento de errores: un fallo controlado (ok:false)
 * o un throw se traducen a "no se pudo auditar", nunca tumban el escaneo completo (§7).
 */
async function runEngine(
  engine: () => Promise<NpmAuditOutcome | PipAuditOutcome>,
): Promise<RepoOutcome> {
  try {
    const outcome = await engine();
    if (outcome.ok) return { status: 'audited', statusReason: null, findings: outcome.findings };
    return { status: 'no-audit', statusReason: outcome.reason, findings: [] };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { status: 'no-audit', statusReason: reason, findings: [] };
  }
}

async function auditOneRepo(
  repoPath: string,
  ecosystem: Ecosystem,
  deps: ScanDeps,
): Promise<RepoOutcome> {
  if (ecosystem === 'none') return { status: 'not-applicable', statusReason: null, findings: [] };
  if (ecosystem === 'pip') return runEngine(() => deps.auditPip(repoPath));
  return runEngine(() => deps.auditNpm(repoPath));
}

/**
 * Orquesta el escaneo: descubre repos, detecta ecosistema, corre el motor que toque y
 * arma el reporte. Emite progreso por repo y aísla errores por repo. Devuelve el Report
 * ya agregado (el CLI decide render + escritura a disco).
 */
export async function scan(root: string, deps: ScanDeps): Promise<Report> {
  const discover = deps.discover ?? discoverRepos;
  const detect = deps.detect ?? detectEcosystem;

  const repoPaths = discover(root);
  const total = repoPaths.length;
  const results: RepoResult[] = [];

  for (let i = 0; i < repoPaths.length; i++) {
    const repoPath = repoPaths[i];
    const name = basename(repoPath);
    deps.onProgress?.(i + 1, total, name);

    const ecosystem = detect(repoPath);
    const outcome = await auditOneRepo(repoPath, ecosystem, deps);
    results.push({
      name,
      path: repoPath,
      ecosystem,
      secondaryEcosystems: detectSecondaryEcosystems(repoPath),
      ...outcome,
    });
  }

  return buildReport(root, results, deps.now);
}
