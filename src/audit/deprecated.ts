import type { Finding } from '../types.js';

/**
 * Detección de paquetes abandonados (§6.4 del brief).
 *
 * Solo la **Señal 1**: el flag `deprecated` explícito del registro de npm — 100% confiable,
 * lo pone quien mantiene el paquete. La Señal 2 (umbral de meses sin publicar) queda fuera
 * a propósito: marcaría como muerto algo que solo está maduro y estable, y un falso positivo
 * el día 1 rompe la confianza más rápido de lo que la construye un acierto.
 */

const REGISTRY = 'https://registry.npmjs.org';
// Packument abreviado: mucho más liviano que el completo y trae `deprecated` por versión.
const ABBREVIATED = 'application/vnd.npm.install-v1+json';

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
}

// Contextos NEGATIVOS: el mensaje usa "use/using" para advertir, no para ofrecer salida
// ("Do not use this package", "use at your own risk"). Si aparece uno, no hay alternativa.
const NEGATIVE_CONTEXT =
  /\b(?:do\s+not|don'?t|never|avoid|no\s+longer|not)\s+(?:use|using)\b|\bat\s+your\s+own\s+risk\b|\bin\s+use\b/i;

// Un token de paquete: nombre npm (admite @scope/nombre, guiones, puntos).
const PKG = String.raw`[\w@][\w@/.-]*`;

/**
 * Formas EXPLÍCITAS de nombrar un reemplazo. Deliberadamente estrictas: cada patrón exige
 * un marcador inequívoco ("instead", "replaced by", "in favor of"…) además del nombre del
 * paquete. No basta con que aparezca el verbo "use" suelto.
 */
const REPLACEMENT_PATTERNS: RegExp[] = [
  new RegExp(String.raw`\buse\s+${PKG}(?:\s+\w+){0,3}\s+instead\b`, 'i'), // "Use uuid module instead"
  new RegExp(String.raw`\brecommend(?:s|ed)?\s+using\s+${PKG}`, 'i'), // "we recommend using babel-preset-env"
  new RegExp(String.raw`\breplaced\s+by\s+${PKG}`, 'i'),
  new RegExp(String.raw`\bsuperseded\s+by\s+${PKG}`, 'i'),
  new RegExp(String.raw`\bin\s+favou?r\s+of\s+${PKG}`, 'i'),
  new RegExp(String.raw`\bmigrate\s+to\s+${PKG}`, 'i'),
  new RegExp(String.raw`\bswitch\s+to\s+${PKG}`, 'i'),
];

/**
 * ¿El mensaje de deprecación nombra un reemplazo? Determinístico, sin IA.
 *
 * SESGO DELIBERADO: el mensaje es texto libre que cada quien escribe distinto, así que esta
 * detección es imposible de hacer perfecta. Ante la duda se responde `false` → el hallazgo
 * cae en 🔴 (más urgente de lo necesario). El error inaceptable es el contrario: dar 🟡 y
 * hacer creer que hay salida cuando no la hay. Por eso primero se descartan los contextos
 * negativos y luego se exige un marcador explícito de reemplazo.
 */
export function hasKnownAlternative(message: string): boolean {
  if (typeof message !== 'string' || message.trim() === '') return false;
  if (NEGATIVE_CONTEXT.test(message)) return false;
  return REPLACEMENT_PATTERNS.some((re) => re.test(message));
}

/** Mensaje de deprecación de una versión concreta, o null si esa versión no está marcada. */
export function deprecatedFromPackument(packument: unknown, version: string): string | null {
  const versions = asRecord(asRecord(packument)?.versions);
  const entry = asRecord(versions?.[version]);
  const deprecated = entry?.deprecated;
  return typeof deprecated === 'string' && deprecated.trim() !== '' ? deprecated : null;
}

/**
 * Dependencias DIRECTAS declaradas en package.json (prod + dev).
 *
 * Solo las directas: son las que de verdad puedes cambiar, y son las que El Repuesto podrá
 * proponer reemplazar. Revisar el árbol completo dispararía cientos de consultas al registro
 * por repo para hallazgos sobre los que no puedes actuar directamente.
 */
export function directDependencies(packageJson: unknown): string[] {
  const pkg = asRecord(packageJson);
  const names = new Set<string>();
  for (const field of ['dependencies', 'devDependencies']) {
    const deps = asRecord(pkg?.[field]);
    if (!deps) continue;
    for (const name of Object.keys(deps)) names.add(name);
  }
  return [...names];
}

/**
 * Construye el hallazgo de paquete abandonado. Regla de bucket del brief §6.5:
 * 🔴 deprecated SIN alternativa conocida (estás varado) · 🟡 CON alternativa (hay a dónde ir).
 * `severity` es null a propósito: estar abandonado no es una vulnerabilidad con gravedad.
 */
export function buildDeprecatedFinding(
  packageName: string,
  version: string,
  message: string,
): Finding {
  const conAlternativa = hasKnownAlternative(message);
  return {
    type: 'deprecated',
    package: packageName,
    installedVersions: version ? [version] : [],
    severity: null,
    bucket: conAlternativa ? 'can-wait' : 'fix-now',
    direct: true,
    fixAvailable: conAlternativa,
    explanation: conAlternativa
      ? 'Quien mantiene esta librería la dio por abandonada y señala con qué reemplazarla — cambia cuando puedas, no corre prisa hoy.'
      : 'Quien mantiene esta librería la dio por abandonada y no señala reemplazo: ya no recibirá parches de seguridad, así que conviene salir de ella.',
    advisory: { titles: [message], urls: [], range: '' },
    unresolvedAdvisories: 0,
  };
}

/** Firma inyectable: resuelve el mensaje de deprecación de un paquete+versión. */
export type ResolveDeprecation = (
  packageName: string,
  version: string,
) => Promise<string | null>;

/**
 * BORDE de red: consulta el registro de npm (sin credenciales) y cachea el packument en
 * memoria durante el escaneo — la familia de repos comparte muchas dependencias, así que
 * la caché evita repetir la misma consulta repo tras repo. Nunca lanza: sin red devuelve
 * null y simplemente no se reportan abandonados.
 */
export function createDeprecationResolver(): ResolveDeprecation {
  const cache = new Map<string, unknown>();

  return async (packageName, version) => {
    try {
      if (!cache.has(packageName)) {
        const res = await fetch(`${REGISTRY}/${encodeURIComponent(packageName)}`, {
          headers: { Accept: ABBREVIATED },
          signal: AbortSignal.timeout(15_000),
        });
        cache.set(packageName, res.ok ? await res.json() : null);
      }
      return deprecatedFromPackument(cache.get(packageName), version);
    } catch {
      return null;
    }
  };
}
