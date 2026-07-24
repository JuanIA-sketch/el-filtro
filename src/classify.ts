import type { Bucket, Severity } from './types.js';

// Mapeo 100% determinístico severidad → urgencia (§6.5). Sin IA, sin API key.
const FIX_NOW: ReadonlySet<Severity> = new Set<Severity>(['critical', 'high']);

/** 🔴 fix-now ← critical/high · 🟡 can-wait ← moderate/low/info. */
export function classifySeverity(severity: Severity): Bucket {
  return FIX_NOW.has(severity) ? 'fix-now' : 'can-wait';
}

// Plantillas fijas: explican el hallazgo en lenguaje simple, no en jerga de CVE.
const VULN_EXPLANATION: Record<Bucket, string> = {
  'fix-now':
    'Esta librería tiene una vulnerabilidad conocida que se puede explotar directamente — actualízala antes de publicar algo que dependa de ella.',
  'can-wait':
    'Esta librería tiene una vulnerabilidad menor o difícil de explotar — conviene actualizarla, pero no es urgente.',
};

/** Explicación en lenguaje simple para un hallazgo de vulnerabilidad, según su bucket. */
export function vulnerabilityExplanation(bucket: Bucket): string {
  return VULN_EXPLANATION[bucket];
}

/**
 * Bucket cuando no se pudo determinar la gravedad (hallazgo pip cuyo advisory no tiene
 * etiqueta de severidad, o escaneo sin red). Cae en 🟡 a propósito: sin evidencia no se
 * infla la urgencia — el brief advierte que un falso positivo el día 1 rompe la confianza.
 */
export function classifyUnknownSeverity(): Bucket {
  return 'can-wait';
}

/** Explicación honesta para severidad desconocida: dice que hay que mirarlo a mano. */
export function unknownSeverityExplanation(): string {
  return 'Esta librería tiene una vulnerabilidad conocida, pero no se pudo determinar qué tan grave es — revísala a mano para decidir si corre prisa.';
}
