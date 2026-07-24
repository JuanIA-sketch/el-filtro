import { existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  classifySeverity,
  classifyUnknownSeverity,
  unknownSeverityExplanation,
  vulnerabilityExplanation,
} from '../classify.js';
import type { ResolveSeverities, SeverityIndex } from '../osv.js';
import type { RunCommand } from '../runners/exec.js';
import type { Finding, Severity } from '../types.js';

/**
 * Vulnerabilidad cruda de `pip-audit --format json`, antes de resolver la severidad.
 *
 * OJO: pip-audit NO trae severidad (ni con servicio pypi ni osv) — solo id, fix_versions,
 * aliases y description. La severidad se resuelve aparte contra OSV (ver `osv.ts`).
 */
export interface PipVuln {
  package: string;
  version: string;
  id: string;
  fixVersions: string[];
  aliases: string[];
  description: string;
}

export type PipAuditOutcome = { ok: true; findings: Finding[] } | { ok: false; reason: string };

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * Convierte el JSON ya parseado de `pip-audit --format json` en una vulnerabilidad por
 * (paquete, id). Deduplica: pip-audit emite entradas repetidas de verdad (lo vi con
 * PYSEC-2021-142 y PYSEC-2020-96 en pyyaml). Lanza si el payload no es un reporte válido
 * para que el orquestador lo marque "no se pudo auditar" en vez de reportar 0 falsamente.
 */
export function parsePipAudit(auditJson: unknown): PipVuln[] {
  const root = asRecord(auditJson);
  if (!root || !Array.isArray(root.dependencies)) {
    throw new Error('pip-audit no devolvió un reporte válido.');
  }

  const seen = new Set<string>();
  const vulns: PipVuln[] = [];
  for (const entry of root.dependencies) {
    const dep = asRecord(entry);
    if (!dep || typeof dep.name !== 'string') continue;
    const version = typeof dep.version === 'string' ? dep.version : '';
    if (!Array.isArray(dep.vulns)) continue; // dependencia sin vulnerabilidades: se ignora

    for (const rawVuln of dep.vulns) {
      const v = asRecord(rawVuln);
      if (!v || typeof v.id !== 'string') continue;
      const key = `${dep.name}::${v.id}`;
      if (seen.has(key)) continue; // dedup
      seen.add(key);

      vulns.push({
        package: dep.name,
        version,
        id: v.id,
        fixVersions: asStringArray(v.fix_versions),
        aliases: asStringArray(v.aliases),
        description: typeof v.description === 'string' ? v.description : '',
      });
    }
  }
  return vulns;
}

/** Busca la severidad por el id propio o por cualquiera de sus alias (PYSEC → GHSA). */
function severityFor(vuln: PipVuln, index: SeverityIndex) {
  const direct = index[vuln.id];
  if (direct) return direct;
  for (const alias of vuln.aliases) {
    if (index[alias]) return index[alias];
  }
  return null;
}

// Orden de gravedad para quedarse con la peor de un paquete.
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  moderate: 3,
  low: 2,
  info: 1,
};

function worstSeverity(a: Severity | null, b: Severity | null): Severity | null {
  if (!a) return b;
  if (!b) return a;
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Combina las vulnerabilidades de pip-audit con el índice de severidades de OSV para
 * producir los Findings del contrato.
 *
 * AGREGA POR PAQUETE, igual que `npm audit` (que devuelve una entrada por paquete, no por
 * advisory). pip-audit sí emite una entrada por advisory, así que sin agregar saldría el
 * mismo paquete repetido N veces con el mismo texto: ruido en consola, conteos no
 * comparables entre ecosistemas, y El Repuesto proponiendo el mismo reemplazo N veces.
 * Se conserva la severidad más alta y se reúnen todos los ids de advisory.
 *
 * Reutiliza `classifySeverity` sin cambios, así que 🔴/🟡 significan exactamente lo mismo
 * que en npm. Sin severidad conocida: `severity: null` y 🟡 con explicación honesta.
 */
export function enrichPipFindings(vulns: PipVuln[], index: SeverityIndex): Finding[] {
  interface Agg {
    version: string;
    severity: Severity | null;
    fixAvailable: boolean;
    titles: string[];
    urls: string[];
    fixVersions: string[];
    unresolved: number;
  }
  const porPaquete = new Map<string, Agg>();

  for (const v of vulns) {
    const severity = severityFor(v, index);
    const prev = porPaquete.get(v.package);
    const ghsaUrls = v.aliases
      .filter((a) => a.startsWith('GHSA-'))
      .map((a) => `https://github.com/advisories/${a}`);

    if (!prev) {
      porPaquete.set(v.package, {
        version: v.version,
        severity,
        fixAvailable: v.fixVersions.length > 0,
        titles: [v.id],
        urls: [...new Set(ghsaUrls)],
        fixVersions: [...v.fixVersions],
        unresolved: severity ? 0 : 1,
      });
      continue;
    }
    prev.severity = worstSeverity(prev.severity, severity);
    prev.fixAvailable = prev.fixAvailable || v.fixVersions.length > 0;
    if (!severity) prev.unresolved += 1;
    if (!prev.titles.includes(v.id)) prev.titles.push(v.id);
    for (const u of ghsaUrls) if (!prev.urls.includes(u)) prev.urls.push(u);
    for (const f of v.fixVersions) if (!prev.fixVersions.includes(f)) prev.fixVersions.push(f);
  }

  return [...porPaquete].map(([pkg, agg]): Finding => {
    const bucket = agg.severity ? classifySeverity(agg.severity) : classifyUnknownSeverity();
    return {
      type: 'vulnerability',
      package: pkg,
      installedVersions: agg.version ? [agg.version] : [],
      severity: agg.severity,
      bucket,
      // pip-audit no distingue directa/transitiva; se audita el requirements.txt declarado.
      direct: true,
      fixAvailable: agg.fixAvailable,
      explanation: agg.severity ? vulnerabilityExplanation(bucket) : unknownSeverityExplanation(),
      advisory: {
        titles: agg.titles,
        urls: agg.urls,
        range: agg.fixVersions.length > 0 ? `< ${agg.fixVersions.join(' / ')}` : '',
      },
      unresolvedAdvisories: agg.unresolved,
    };
  });
}

const REQUIREMENTS = 'requirements.txt';
const MISSING_PIP_AUDIT = 'falta pip-audit. Corre: pip install pip-audit';

/**
 * En Windows corremos con `shell: true` (para resolver .cmd/.exe), y ahí un binario
 * ausente NO produce ENOENT: el shell devuelve exit code con un mensaje **localizado**
 * ("no se reconoce como un comando…" en español). Sin esto, la persona vería un error
 * críptico en vez del comando exacto para instalarlo — justo lo que el brief §6.3 pide evitar.
 */
export function looksLikeMissingPipAudit(stderr: string): boolean {
  return /no se reconoce como un comando|is not recognized as an internal or external command|command not found/i.test(
    stderr,
  );
}

function pipErrorReason(err: unknown): string {
  const e = err as NodeJS.ErrnoException;
  if (e?.code === 'ENOENT') return MISSING_PIP_AUDIT;
  return e instanceof Error ? e.message : String(err);
}

/** Recorta la salida de error de pip para un statusReason legible. */
function firstErrorLine(stderr: string): string {
  const line = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => /^ERROR/i.test(l));
  return line ? line.replace(/^ERROR:\s*/i, '').slice(0, 160) : 'pip-audit falló';
}

/**
 * Motor pip real para UN repo (BORDE). Corre `pip-audit -r requirements.txt --format json
 * --no-deps` y enriquece la severidad contra OSV (1 llamada por paquete vulnerable).
 * Nunca lanza: todo fallo se traduce a ok:false para no tumbar el escaneo. Si OSV falla,
 * el repo SÍ queda auditado — solo pierde la severidad (🟡 + explicación).
 */
export async function auditPipRepo(
  repoPath: string,
  run: RunCommand,
  resolveSeverities: ResolveSeverities,
): Promise<PipAuditOutcome> {
  if (!existsSync(join(repoPath, REQUIREMENTS))) {
    return {
      ok: false,
      reason: 'sin requirements.txt (soporte de pyproject/Poetry: no en esta versión)',
    };
  }

  let result;
  try {
    result = await run('pip-audit', ['-r', REQUIREMENTS, '--format', 'json', '--no-deps'], {
      cwd: repoPath,
    });
  } catch (err) {
    return { ok: false, reason: pipErrorReason(err) };
  }

  // Binario ausente vía shell (Windows): mensaje claro con el comando exacto.
  if (looksLikeMissingPipAudit(result.stderr)) return { ok: false, reason: MISSING_PIP_AUDIT };

  // pip-audit sale con code 1 cuando HAY vulnerabilidades: eso es normal, se parsea igual.
  // Un fallo real (ResolutionImpossible, etc.) deja stdout vacío/no-JSON.
  let vulns: PipVuln[];
  try {
    vulns = parsePipAudit(JSON.parse(result.stdout));
  } catch {
    return { ok: false, reason: firstErrorLine(result.stderr) };
  }

  // Severidad: 1 llamada a OSV por paquete vulnerable (no por advisory).
  const index: SeverityIndex = {};
  const porPaquete = new Map<string, string>();
  for (const v of vulns) porPaquete.set(v.package, v.version);
  for (const [name, version] of porPaquete) {
    Object.assign(index, await resolveSeverities(name, version));
  }

  return { ok: true, findings: enrichPipFindings(vulns, index) };
}
