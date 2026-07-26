/** Severidad estructurada de npm audit (v7+). */
export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'info';

/** Los 2 niveles de urgencia en lenguaje simple (§6.5 del brief). */
export type Bucket = 'fix-now' | 'can-wait';

/** Ecosistema de un repo (§6.2). 'none' = no aplica, no es un error. */
export type Ecosystem = 'npm' | 'pip' | 'none';

/** Referencias de advisory conservadas para El Repuesto (no jerga en el reporte humano). */
export interface Advisory {
  titles: string[];
  urls: string[];
  range: string;
}

/**
 * Arreglo concreto que `npm audit` señala para un hallazgo: QUÉ instalar y en qué versión.
 *
 * `package` puede NO ser el paquete vulnerable: en un fallo transitivo npm apunta al padre
 * que hay que subir (p.ej. `esbuild` vulnerable → sube `vitest`). Recomendar el paquete
 * vulnerable en ese caso sería mandar a alguien a tocar algo que ni está en su package.json.
 *
 * `isSemVerMajor` marca que el salto es de versión mayor, es decir, que puede romper.
 */
export interface FixTarget {
  package: string;
  version: string;
  isSemVerMajor: boolean;
}

/**
 * Un hallazgo en el reporte. `type` reserva espacio para 'deprecated' (Etapa 3)
 * sin romper el esquema; en Etapa 1 solo se emiten 'vulnerability'. `severity` es
 * null para hallazgos sin severidad (deprecated).
 */
export interface Finding {
  type: 'vulnerability' | 'deprecated';
  package: string;
  installedVersions: string[];
  severity: Severity | null;
  bucket: Bucket;
  direct: boolean;
  fixAvailable: boolean;
  /**
   * El arreglo concreto, cuando npm lo nombra. `fixAvailable` tiene TRES estados y este
   * campo es el que los separa:
   *   - `fixAvailable: true`  + `fix: {...}` → hay que instalar algo distinto de lo declarado
   *   - `fixAvailable: true`  + `fix: null`  → se arregla dentro del rango ya declarado
   *                                            (npm no nombra versión porque no hace falta)
   *   - `fixAvailable: false` + `fix: null`  → no hay versión segura publicada
   * Colapsar los dos primeros perdería la versión objetivo; confundir los dos últimos diría
   * "no hay arreglo" del caso más fácil de arreglar. Opcional en el tipo; `buildReport` lo
   * normaliza a null para que el JSON siempre lo traiga.
   */
  fix?: FixTarget | null;
  explanation: string;
  advisory: Advisory | null;
  /**
   * Advisories agrupados en este hallazgo cuya severidad NO se pudo resolver (solo pip:
   * npm audit siempre trae severidad). `severity` es la más alta de las que SÍ se
   * resolvieron, así que un valor > 0 significa que la gravedad real podría ser mayor.
   * Opcional en el tipo; `buildReport` lo normaliza a 0 para que el JSON siempre lo traiga.
   */
  unresolvedAdvisories?: number;
}

/** Estado de auditoría de un repo. audited+skipped = scanned. */
export type RepoStatus = 'audited' | 'no-audit' | 'not-applicable' | 'pending';

export interface RepoResult {
  name: string;
  path: string;
  ecosystem: Ecosystem;
  /**
   * Ecosistemas presentes que no ganaron la precedencia (npm gana cuando conviven).
   * Se reporta para que una carpeta políglota no esconda dependencias sin auditar.
   * Opcional en el tipo; `buildReport` lo normaliza a [] para que el JSON siempre lo traiga.
   */
  secondaryEcosystems?: Ecosystem[];
  status: RepoStatus;
  statusReason: string | null;
  findings: Finding[];
}

export interface ReportSummary {
  reposScanned: number;
  reposAudited: number;
  reposSkipped: number;
  findings: { total: number; fixNow: number; canWait: number };
  bySeverity: Record<Severity, number>;
  /**
   * Vulnerabilidades cuya gravedad no se pudo determinar (pip sin etiqueta en OSV, o
   * escaneo sin red). Mantiene el invariante fuerte:
   * sum(bySeverity) + unknownSeverity === # hallazgos type:'vulnerability'.
   */
  unknownSeverity: number;
  abandonedPackages: number;
}

/** El contrato JSON estable que El Repuesto leerá mañana (§6.6). */
export interface Report {
  schemaVersion: number;
  tool: 'el-filtro';
  generatedAt: string;
  root: string;
  summary: ReportSummary;
  repos: RepoResult[];
}
