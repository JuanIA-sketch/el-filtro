import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { buildReport, renderJson, renderConsole, writeReport } from '../src/report.js';
import type { Finding, RepoResult, Severity } from '../src/types.js';
import { makeTempDir, cleanupTempDirs } from './helpers/tmp.js';

afterAll(cleanupTempDirs);

function vuln(pkg: string, severity: Severity, bucket: 'fix-now' | 'can-wait'): Finding {
  return {
    type: 'vulnerability',
    package: pkg,
    installedVersions: ['1.0.0'],
    severity,
    bucket,
    direct: true,
    fixAvailable: true,
    explanation: 'explicación simple',
    advisory: { titles: [`Fallo en ${pkg}`], urls: ['https://example.test/a'], range: '<1.0.0' },
  };
}

function deprecatedFinding(pkg: string): Finding {
  return {
    type: 'deprecated',
    package: pkg,
    installedVersions: ['2.0.0'],
    severity: null,
    bucket: 'fix-now',
    direct: true,
    fixAvailable: false,
    explanation: 'paquete abandonado',
    advisory: null,
  };
}

/** Hallazgo pip con severidad resuelta a medias: 2 de sus advisories quedaron sin evaluar. */
function partiallyResolvedVuln(pkg: string): Finding {
  return {
    type: 'vulnerability',
    package: pkg,
    installedVersions: ['5.1'],
    severity: 'moderate',
    bucket: 'can-wait',
    direct: true,
    fixAvailable: true,
    explanation: 'explicación simple',
    advisory: { titles: ['PYSEC-A', 'PYSEC-B', 'PYSEC-C'], urls: [], range: '< 5.4' },
    unresolvedAdvisories: 2,
  };
}

/** Vulnerabilidad pip cuya gravedad no se pudo determinar (sin label en OSV o sin red). */
function unknownSeverityVuln(pkg: string): Finding {
  return {
    type: 'vulnerability',
    package: pkg,
    installedVersions: ['2.10'],
    severity: null,
    bucket: 'can-wait',
    direct: true,
    fixAvailable: true,
    explanation: 'no se pudo determinar la gravedad',
    advisory: { titles: ['PYSEC-0000-1'], urls: [], range: '< 3.0' },
  };
}

const repos: RepoResult[] = [
  {
    name: 'repo-a',
    path: '/x/repo-a',
    ecosystem: 'npm',
    status: 'audited',
    statusReason: null,
    findings: [
      vuln('lodash', 'critical', 'fix-now'),
      vuln('minimist', 'high', 'fix-now'),
      vuln('axios', 'moderate', 'can-wait'),
      vuln('tar', 'low', 'can-wait'),
      deprecatedFinding('request'), // Etapa 3 (forward-compat): severity null, type deprecated
      unknownSeverityVuln('jinja2'), // Etapa 2: vulnerability con severity null
      partiallyResolvedVuln('pyyaml'), // Etapa 2: severidad resuelta a medias
    ],
  },
  { name: 'repo-b', path: '/x/repo-b', ecosystem: 'npm', status: 'audited', statusReason: null, findings: [] },
  {
    name: 'repo-c',
    path: '/x/repo-c',
    ecosystem: 'npm',
    status: 'no-audit',
    statusReason: 'falta lockfile y npm sin red',
    findings: [],
  },
  {
    name: 'repo-d',
    path: '/x/repo-d',
    ecosystem: 'pip',
    status: 'pending',
    statusReason: 'pip: motor en Etapa 2',
    findings: [],
  },
  { name: 'repo-e', path: '/x/repo-e', ecosystem: 'none', status: 'not-applicable', statusReason: null, findings: [] },
  {
    name: 'repo-poliglota',
    path: '/x/repo-poliglota',
    ecosystem: 'npm',
    secondaryEcosystems: ['pip'],
    status: 'audited',
    statusReason: null,
    findings: [],
  },
];

const FIXED = new Date('2026-07-24T15:00:00.000Z');

describe('buildReport', () => {
  const report = buildReport('/x', repos, FIXED);

  it('cuenta repos escaneados, auditados y sin auditar', () => {
    expect(report.summary.reposScanned).toBe(6);
    expect(report.summary.reposAudited).toBe(3);
    expect(report.summary.reposSkipped).toBe(3);
  });

  it('agrega los hallazgos por bucket', () => {
    expect(report.summary.findings.total).toBe(7);
    expect(report.summary.findings.fixNow).toBe(3);
    expect(report.summary.findings.canWait).toBe(4);
  });

  it('agrega por severidad solo las vulnerabilidades con severidad conocida', () => {
    // pyyaml (resuelto a medias) SÍ cuenta como moderate: su severidad es conocida.
    expect(report.summary.bySeverity).toEqual({ critical: 1, high: 1, moderate: 2, low: 1, info: 0 });
    expect(report.summary.abandonedPackages).toBe(1);
  });

  it('cuenta aparte las vulnerabilidades sin severidad determinada', () => {
    expect(report.summary.unknownSeverity).toBe(1);
  });

  it('INVARIANTE: total === fixNow + canWait', () => {
    const f = report.summary.findings;
    expect(f.total).toBe(f.fixNow + f.canWait);
  });

  it('INVARIANTE: sum(bySeverity) + unknownSeverity === número de hallazgos vulnerability', () => {
    const vulnCount = repos.flatMap((r) => r.findings).filter((f) => f.type === 'vulnerability').length;
    const sev = report.summary.bySeverity;
    const sum = sev.critical + sev.high + sev.moderate + sev.low + sev.info;
    expect(sum + report.summary.unknownSeverity).toBe(vulnCount);
  });

  it('reposAudited + reposSkipped === reposScanned', () => {
    const s = report.summary;
    expect(s.reposAudited + s.reposSkipped).toBe(s.reposScanned);
  });

  it('envuelve con metadata estable del contrato', () => {
    expect(report.schemaVersion).toBe(1);
    expect(report.tool).toBe('el-filtro');
    expect(report.root).toBe('/x');
    expect(report.generatedAt).toBe('2026-07-24T15:00:00.000Z');
  });
});

describe('renderJson', () => {
  it('produce JSON parseable que preserva el esquema', () => {
    const report = buildReport('/x', repos, FIXED);
    const parsed = JSON.parse(renderJson(report));
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.repos).toHaveLength(6);
    const finding = parsed.repos[0].findings[0];
    expect(finding).toHaveProperty('installedVersions');
    expect(finding).toHaveProperty('bucket');
    expect(finding).toHaveProperty('advisory');
    // Campo aditivo del contrato: siempre presente, aunque venga vacío.
    expect(parsed.repos[0].secondaryEcosystems).toEqual([]);
    expect(parsed.repos[5].secondaryEcosystems).toEqual(['pip']);
  });

  it('normaliza `fix` a null para que el JSON siempre lo traiga', () => {
    // Mismo trato que secondaryEcosystems/unresolvedAdvisories: El Repuesto distingue
    // "campo ausente" (reporte viejo) de "sin versión objetivo" (fix: null). Si el campo
    // no viniera siempre, esa distinción se pierde.
    const report = buildReport('/x', repos, FIXED);
    const parsed = JSON.parse(renderJson(report));
    const finding = parsed.repos[0].findings[0];
    expect(finding).toHaveProperty('fix');
    expect(finding.fix).toBeNull();
  });
});

describe('renderConsole', () => {
  const text = renderConsole(buildReport('/x', repos, FIXED), { colors: false });

  it('muestra los dos buckets con sus conteos y los repos sin auditar', () => {
    expect(text).toMatch(/ARR[ÉE]GLALO YA/i);
    expect(text).toMatch(/PUEDEN ESPERAR/i);
    expect(text).toContain('lodash');
    expect(text).toContain('repo-c');
    expect(text).toContain('falta lockfile y npm sin red');
  });

  it('avisa cuando la severidad de un paquete quedó resuelta a medias', () => {
    // No basta con dejarlo en el JSON: si 2 advisories no se evaluaron, el reporte no
    // debe verse tan seguro como uno completamente resuelto.
    expect(text).toMatch(/2 advisor|sin evaluar|sin resolver/i);
  });

  it('etiqueta la severidad desconocida en palabras, sin dejar un paréntesis vacío', () => {
    expect(text).not.toContain('()');
    expect(text).toMatch(/jinja2 2\.10\s+\(gravedad desconocida\)/);
  });

  it('avisa de los repos con dependencias de otro ecosistema sin auditar (no en silencio)', () => {
    expect(text).toContain('repo-poliglota');
    expect(text).toMatch(/otro ecosistema|tambi[ée]n tiene dependencias/i);
    expect(text).toContain('pip');
  });

  it('snapshot del reporte de consola (sin color)', () => {
    expect(text).toMatchSnapshot();
  });
});

describe('writeReport', () => {
  it('escribe el JSON en <root>/.el-filtro/report-<ts>.json y devuelve la ruta', () => {
    const root = makeTempDir();
    const report = buildReport(root, repos, FIXED);
    const written = writeReport(report, root);
    expect(existsSync(written)).toBe(true);
    expect(written).toContain('.el-filtro');
    const back = JSON.parse(readFileSync(written, 'utf8'));
    expect(back.schemaVersion).toBe(1);
    expect(back.repos).toHaveLength(6);
  });
});
