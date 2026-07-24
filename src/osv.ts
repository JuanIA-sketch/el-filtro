import type { Severity } from './types.js';

/**
 * Resolución de severidad para el motor pip.
 *
 * `pip-audit` NO expone severidad en su JSON (verificado con pip-audit 2.10.1: las únicas
 * claves por vulnerabilidad son id/fix_versions/aliases/description, tanto con el servicio
 * `pypi` como con `osv`). La API pública de OSV sí la trae, sin API key ni registro, y con
 * el MISMO vocabulario que npm audit (CRITICAL/HIGH/MODERATE/LOW) — por eso `classify.ts`
 * se reutiliza tal cual y 🔴/🟡 significan lo mismo en ambos ecosistemas.
 */

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

const LABELS: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  moderate: 'moderate',
  low: 'low',
};

/** Etiqueta de OSV → severidad interna. Desconocida/ausente → null (nunca inventar). */
export function normalizeOsvSeverity(label: string | null | undefined): Severity | null {
  if (typeof label !== 'string') return null;
  return LABELS[label.trim().toLowerCase()] ?? null;
}

/** Índice id → severidad, construido desde la respuesta de OSV. */
export type SeverityIndex = Record<string, Severity>;

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
}

/**
 * Construye el índice id → severidad desde un `POST /v1/query` de OSV.
 *
 * Clave del diseño: solo las entradas GHSA traen `database_specific.severity`; las PYSEC
 * (que son las que devuelve pip-audit) NO. Pero ambas se referencian mutuamente vía
 * `aliases`, así que cada severidad se indexa bajo el id propio Y bajo todos sus alias —
 * de ahí que un id PYSEC herede la severidad de su gemelo GHSA.
 */
export function severityIndexFromOsv(osvJson: unknown): SeverityIndex {
  const root = asRecord(osvJson);
  const vulns = root?.vulns;
  if (!Array.isArray(vulns)) return {};

  const index: SeverityIndex = {};
  for (const entry of vulns) {
    const v = asRecord(entry);
    if (!v) continue;
    const dbSpecific = asRecord(v.database_specific);
    const severity = normalizeOsvSeverity(dbSpecific?.severity as string | undefined);
    if (!severity) continue;

    if (typeof v.id === 'string') index[v.id] = severity;
    if (Array.isArray(v.aliases)) {
      for (const alias of v.aliases) {
        if (typeof alias === 'string' && !index[alias]) index[alias] = severity;
      }
    }
  }
  return index;
}

/** Firma inyectable del resolvedor de severidad (fake en tests, red real en el CLI). */
export type ResolveSeverities = (packageName: string, version: string) => Promise<SeverityIndex>;

/**
 * BORDE de red: consulta OSV por paquete+versión (1 llamada por paquete vulnerable) y
 * devuelve el índice de severidades. Nunca lanza: si no hay red o la respuesta es rara,
 * devuelve {} y los hallazgos quedan con severidad desconocida (🟡 + explicación), sin
 * tumbar la auditoría del repo.
 */
export const fetchOsvSeverities: ResolveSeverities = async (packageName, version) => {
  try {
    const res = await fetch(OSV_QUERY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: packageName, ecosystem: 'PyPI' }, version }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return {};
    return severityIndexFromOsv(await res.json());
  } catch {
    return {};
  }
};
