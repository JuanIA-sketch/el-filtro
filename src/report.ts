import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import picocolors from 'picocolors';
import type { Finding, Report, RepoResult, Severity } from './types.js';

const SCHEMA_VERSION = 1;
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];

/**
 * Envuelve los resultados por repo en el contrato JSON estable (§6.6) y calcula el
 * resumen. Función pura: recibe `now` para ser determinística en tests. Invariantes:
 * total === fixNow + canWait, y sum(bySeverity) === # hallazgos vulnerability.
 */
export function buildReport(root: string, repos: RepoResult[], now: Date = new Date()): Report {
  const allFindings = repos.flatMap((r) => r.findings);
  const reposAudited = repos.filter((r) => r.status === 'audited').length;

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
  for (const f of allFindings) {
    if (f.type === 'vulnerability' && f.severity) bySeverity[f.severity] += 1;
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    tool: 'el-filtro',
    generatedAt: now.toISOString(),
    root,
    summary: {
      reposScanned: repos.length,
      reposAudited,
      reposSkipped: repos.length - reposAudited,
      findings: {
        total: allFindings.length,
        fixNow: allFindings.filter((f) => f.bucket === 'fix-now').length,
        canWait: allFindings.filter((f) => f.bucket === 'can-wait').length,
      },
      bySeverity,
      unknownSeverity: allFindings.filter((f) => f.type === 'vulnerability' && !f.severity).length,
      abandonedPackages: allFindings.filter((f) => f.type === 'deprecated').length,
    },
    // Normalizado: el JSON siempre trae secondaryEcosystems y unresolvedAdvisories,
    // aunque vengan vacíos/en cero — contrato estable para El Repuesto.
    repos: repos.map((r) => ({
      ...r,
      secondaryEcosystems: r.secondaryEcosystems ?? [],
      findings: r.findings.map((f) => ({ ...f, unresolvedAdvisories: f.unresolvedAdvisories ?? 0 })),
    })),
  };
}

/** Salida JSON máquina-legible (el contrato que consume El Repuesto). */
export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

const HEADER_BOX = [
  '╔════════════════════════════════════════╗',
  '║   🔎  EL FILTRO — Dependencias          ║',
  '╚════════════════════════════════════════╝',
].join('\n');

function findingLine(repo: RepoResult, f: Finding): string {
  const version = f.installedVersions[0] ? ` ${f.installedVersions[0]}` : '';
  // Una vulnerabilidad sin severidad resuelta (pip sin dato en OSV) se nombra en palabras,
  // no con un paréntesis vacío.
  const tag =
    f.type === 'deprecated' ? 'abandonado' : (f.severity ?? 'gravedad desconocida');
  return `  • ${repo.name} › ${f.package}${version}  (${tag})`;
}

/**
 * Aviso cuando la gravedad de un paquete quedó resuelta a medias: la severidad mostrada es
 * la más alta de las que SÍ se resolvieron, así que la real podría ser mayor. Solo se dice
 * si además hay una severidad mostrada — si no hay ninguna, la explicación ya lo cubre.
 */
function unresolvedNote(f: Finding): string | null {
  const n = f.unresolvedAdvisories ?? 0;
  if (n === 0 || !f.severity) return null;
  return `(${n} advisor${n === 1 ? 'y' : 'ies'} sin evaluar: la gravedad real podría ser mayor)`;
}

/** Resumen humano agrupado por los 2 buckets, con desglose por repo (§6.6). */
export function renderConsole(report: Report, opts: { colors?: boolean } = {}): string {
  const pc = picocolors.createColors(opts.colors ?? false);
  const s = report.summary;
  const lines: string[] = [HEADER_BOX, ''];

  lines.push(`Carpeta: ${report.root}`);
  lines.push(
    `Repos escaneados: ${s.reposScanned}  ·  auditados: ${s.reposAudited}  ·  sin auditar: ${s.reposSkipped}`,
  );
  lines.push(
    `Hallazgos: ${s.findings.total}   ${pc.red(`🔴 ${s.findings.fixNow} arréglalo ya`)}   ${pc.yellow(
      `🟡 ${s.findings.canWait} pueden esperar`,
    )}`,
  );

  const withFindings = report.repos.filter((r) => r.findings.length > 0);
  const collect = (bucket: 'fix-now' | 'can-wait') =>
    withFindings.flatMap((r) => r.findings.filter((f) => f.bucket === bucket).map((f) => ({ r, f })));

  const fixNow = collect('fix-now');
  const canWait = collect('can-wait');

  lines.push('', pc.red(`🔴 ARRÉGLALO YA (${fixNow.length})`));
  if (fixNow.length === 0) lines.push(pc.dim('  (nada urgente)'));
  for (const { r, f } of fixNow) {
    lines.push(findingLine(r, f));
    lines.push(pc.dim(`      ${f.explanation}`));
    const nota = unresolvedNote(f);
    if (nota) lines.push(pc.dim(`      ${nota}`));
  }

  lines.push('', pc.yellow(`🟡 PUEDEN ESPERAR (${canWait.length})`));
  if (canWait.length === 0) lines.push(pc.dim('  (nada por aquí)'));
  for (const { r, f } of canWait) {
    lines.push(findingLine(r, f));
    const nota = unresolvedNote(f);
    if (nota) lines.push(pc.dim(`      ${nota}`));
  }

  const notAudited = report.repos.filter((r) => r.status === 'no-audit');
  if (notAudited.length > 0) {
    lines.push('', 'Repos sin auditar:');
    for (const r of notAudited) {
      lines.push(`  • ${r.name} — ${r.statusReason ?? 'razón desconocida'}`);
    }
  }

  const pending = report.repos.filter((r) => r.status === 'pending');
  if (pending.length > 0) {
    lines.push('', 'Repos pendientes:');
    for (const r of pending) {
      lines.push(`  • ${r.name} — ${r.statusReason ?? 'pendiente'}`);
    }
  }

  // La precedencia de ecosistema no es silenciosa: si el repo también tiene dependencias
  // del otro ecosistema, se dice. Esconderlas sería ocultar deuda sin auditar.
  const poliglotas = report.repos.filter((r) => (r.secondaryEcosystems ?? []).length > 0);
  if (poliglotas.length > 0) {
    lines.push('', 'Con dependencias de otro ecosistema (no auditadas en esta versión):');
    for (const r of poliglotas) {
      lines.push(`  • ${r.name} — también tiene dependencias ${r.secondaryEcosystems!.join(', ')}`);
    }
  }

  return lines.join('\n');
}

function safeTimestamp(iso: string): string {
  return iso.replace(/[:.]/g, '-'); // Windows no permite ':' en nombres de archivo
}

/**
 * Escribe el reporte JSON en `<baseDir>/.el-filtro/report-<ts>.json` y devuelve la
 * ruta escrita. Borde de I/O — cubierto por su test de temp dir y por e2e.
 */
export function writeReport(report: Report, baseDir: string): string {
  const dir = join(baseDir, '.el-filtro');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `report-${safeTimestamp(report.generatedAt)}.json`);
  writeFileSync(file, renderJson(report));
  return file;
}

export { SEVERITY_ORDER };
