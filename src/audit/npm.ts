import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifySeverity, vulnerabilityExplanation } from '../classify.js';
import {
  buildDeprecatedFinding,
  directDependencies,
  type ResolveDeprecation,
} from './deprecated.js';
import type { RunCommand } from '../runners/exec.js';
import type { Finding, Severity } from '../types.js';

/**
 * Resultado del motor npm para UN repo. `ok:false` es un fallo controlado (sin red,
 * sin lockfile generable…) que se traduce a status "no-audit"; el scan además atrapa
 * cualquier throw como aislamiento de errores.
 */
export type NpmAuditOutcome = { ok: true; findings: Finding[] } | { ok: false; reason: string };

/**
 * Hallazgo crudo de `npm audit --json` para UN paquete, antes de enriquecerlo con
 * la versión instalada (del lockfile) y el bucket/explicación (classify). Función
 * pura de parseo: la orquestación (invocar npm, generar lockfile) es borde.
 */
export interface NpmVulnFinding {
  package: string;
  severity: Severity;
  direct: boolean;
  fixAvailable: boolean;
  range: string;
  nodes: string[];
  titles: string[];
  urls: string[];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
}

const SEVERITIES: ReadonlySet<string> = new Set(['critical', 'high', 'moderate', 'low', 'info']);

function asSeverity(v: unknown): Severity {
  return SEVERITIES.has(v as string) ? (v as Severity) : 'info';
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * Convierte el JSON ya parseado de `npm audit --json` (auditReportVersion 2, npm v7+)
 * en un hallazgo por paquete vulnerable. Lanza si el input no es un reporte válido
 * (p.ej. `{error:...}` cuando falta el lockfile) para que el orquestador lo marque
 * como "no se pudo auditar" en vez de reportar 0 vulnerabilidades falsamente.
 */
export function parseNpmAudit(auditJson: unknown): NpmVulnFinding[] {
  const root = asRecord(auditJson);
  if (!root || 'error' in root || !asRecord(root.vulnerabilities)) {
    throw new Error('npm audit no devolvió un reporte válido (¿falta el lockfile o hubo un error?).');
  }
  const vulnerabilities = root.vulnerabilities as Record<string, unknown>;

  const findings: NpmVulnFinding[] = [];
  for (const [name, raw] of Object.entries(vulnerabilities)) {
    const v = asRecord(raw);
    if (!v) continue;

    // `via` mezcla strings (paquetes transitivos que introducen el fallo) y objetos
    // advisory {title,url,severity,range}. Solo los objetos traen título/url.
    const titles: string[] = [];
    const urls: string[] = [];
    if (Array.isArray(v.via)) {
      for (const entry of v.via) {
        const adv = asRecord(entry);
        if (!adv) continue; // entrada string → se ignora aquí
        if (typeof adv.title === 'string' && !titles.includes(adv.title)) titles.push(adv.title);
        if (typeof adv.url === 'string' && !urls.includes(adv.url)) urls.push(adv.url);
      }
    }

    findings.push({
      package: name,
      severity: asSeverity(v.severity),
      direct: v.isDirect === true,
      fixAvailable: Boolean(v.fixAvailable),
      range: typeof v.range === 'string' ? v.range : '',
      nodes: asStringArray(v.nodes),
      titles,
      urls,
    });
  }
  return findings;
}

/**
 * Resuelve la(s) versión(es) instalada(s) hoy leyendo el `package-lock.json`
 * (lockfileVersion 2/3), donde `packages` está indexado por el path exacto que
 * `npm audit` reporta en `nodes` (p.ej. "node_modules/axios"). Devuelve versiones
 * únicas; ignora paths ausentes. Es el dato puntual que consume El Repuesto.
 */
export function installedVersionsFromLockfile(lockJson: unknown, nodes: string[]): string[] {
  const lock = asRecord(lockJson);
  const packages = asRecord(lock?.packages);
  if (!packages) return [];

  const versions: string[] = [];
  for (const node of nodes) {
    const entry = asRecord(packages[node]);
    const version = entry?.version;
    if (typeof version === 'string' && !versions.includes(version)) versions.push(version);
  }
  return versions;
}

/**
 * Combina el parseo del audit con las versiones del lockfile y la clasificación
 * determinística para producir los Findings finales del contrato (§6.5, §6.6).
 * Pura: recibe ambos JSON ya parseados; la orquestación de I/O vive en auditNpmRepo.
 */
export function enrichFindings(auditJson: unknown, lockJson: unknown): Finding[] {
  return parseNpmAudit(auditJson).map((v): Finding => {
    const bucket = classifySeverity(v.severity);
    return {
      type: 'vulnerability',
      package: v.package,
      installedVersions: installedVersionsFromLockfile(lockJson, v.nodes),
      severity: v.severity,
      bucket,
      direct: v.direct,
      fixAvailable: v.fixAvailable,
      explanation: vulnerabilityExplanation(bucket),
      advisory: { titles: v.titles, urls: v.urls, range: v.range },
    };
  });
}

/**
 * Hallazgos de paquetes abandonados de un repo npm (§6.4): recorre las dependencias
 * DIRECTAS del package.json, resuelve la versión instalada en el lockfile y pregunta al
 * registro si esa versión está marcada como deprecated. Un paquete sin versión en el
 * lockfile se omite (no se puede afirmar qué versión tienes). Nunca lanza: si el
 * resolvedor falla (sin red), simplemente no se reportan abandonados.
 */
export async function deprecatedFindingsFor(
  packageJson: unknown,
  lockJson: unknown,
  resolve: ResolveDeprecation,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const name of directDependencies(packageJson)) {
    const [version] = installedVersionsFromLockfile(lockJson, [`node_modules/${name}`]);
    if (!version) continue;
    try {
      const message = await resolve(name, version);
      if (message) findings.push(buildDeprecatedFinding(name, version, message));
    } catch {
      // Sin red o registro caído: se omite este paquete, el resto del escaneo sigue.
    }
  }
  return findings;
}

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'];

function findLockfile(dir: string): string | null {
  for (const name of LOCKFILES) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  return null;
}

function npmErrorReason(err: unknown): string {
  const e = err as NodeJS.ErrnoException;
  if (e?.code === 'ENOENT') return 'npm no está disponible en el PATH';
  return e instanceof Error ? e.message : String(err);
}

/**
 * Corre `npm audit --json` en `dir` y arma los Findings usando el lockfile dado.
 * `packageJsonPath` es siempre el del repo REAL (no la copia temporal), y si se pasa un
 * resolvedor se suman los hallazgos de paquetes abandonados (§6.4).
 */
async function runAuditIn(
  dir: string,
  lockPath: string,
  run: RunCommand,
  packageJsonPath: string,
  resolveDeprecation?: ResolveDeprecation,
): Promise<NpmAuditOutcome> {
  let result;
  try {
    result = await run('npm', ['audit', '--json'], { cwd: dir });
  } catch (err) {
    return { ok: false, reason: npmErrorReason(err) };
  }
  // npm audit sale con code 1 cuando HAY vulnerabilidades: se parsea el stdout igual.
  let findings: Finding[];
  let lockJson: unknown;
  try {
    const auditJson = JSON.parse(result.stdout);
    lockJson = JSON.parse(readFileSync(lockPath, 'utf8'));
    findings = enrichFindings(auditJson, lockJson);
  } catch {
    return { ok: false, reason: 'npm audit no devolvió un reporte válido' };
  }

  // Paquetes abandonados: se suman a los hallazgos de vulnerabilidad. Que falle esta parte
  // (sin red) no invalida la auditoría de vulnerabilidades que ya salió bien.
  if (resolveDeprecation) {
    try {
      const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
      findings = [...findings, ...(await deprecatedFindingsFor(packageJson, lockJson, resolveDeprecation))];
    } catch {
      // package.json ilegible o registro caído: se reporta lo que sí se pudo.
    }
  }

  return { ok: true, findings };
}

/**
 * Motor npm real para UN repo (BORDE). Si hay lockfile, audita in-place (audit es
 * solo lectura). Si falta, usa una COPIA TEMPORAL: copia package.json a un dir temp,
 * genera ahí el lockfile con `npm install --package-lock-only --ignore-scripts`,
 * audita y borra — sin tocar el repo del usuario (decisión confirmada del brief).
 * Nunca lanza: todo fallo se traduce a ok:false para no tumbar el escaneo (§7).
 */
export async function auditNpmRepo(
  repoPath: string,
  run: RunCommand,
  resolveDeprecation?: ResolveDeprecation,
): Promise<NpmAuditOutcome> {
  const packageJsonPath = join(repoPath, 'package.json');
  const existingLock = findLockfile(repoPath);
  if (existingLock) {
    return runAuditIn(repoPath, existingLock, run, packageJsonPath, resolveDeprecation);
  }

  if (!existsSync(packageJsonPath)) {
    return { ok: false, reason: 'no hay package.json para auditar' };
  }

  let tmp: string | null = null;
  try {
    tmp = mkdtempSync(join(tmpdir(), 'el-filtro-audit-'));
    copyFileSync(join(repoPath, 'package.json'), join(tmp, 'package.json'));
    await run('npm', ['install', '--package-lock-only', '--ignore-scripts'], { cwd: tmp });
    const tmpLock = findLockfile(tmp);
    if (!tmpLock) {
      return { ok: false, reason: 'no se pudo generar el lockfile (¿sin conexión?). Corre: npm install' };
    }
    // El package.json que se lee para deprecated es el del repo real, no la copia temporal.
    return await runAuditIn(tmp, tmpLock, run, packageJsonPath, resolveDeprecation);
  } catch (err) {
    return { ok: false, reason: npmErrorReason(err) };
  } finally {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  }
}
