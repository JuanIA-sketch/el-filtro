import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parsePipAudit, enrichPipFindings, looksLikeMissingPipAudit } from '../src/audit/pip.js';
import type { SeverityIndex } from '../src/osv.js';

function loadFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

describe('parsePipAudit', () => {
  // Fixture real: pip-audit 2.10.1 contra jinja2==2.10 + pyyaml==5.1.
  const vulns = parsePipAudit(loadFixture('pip-audit-vuln.json'));

  it('extrae paquete y versión instalada de cada vulnerabilidad', () => {
    const jinja = vulns.filter((v) => v.package === 'jinja2');
    expect(jinja.length).toBeGreaterThan(0);
    expect(jinja[0].version).toBe('2.10');
  });

  it('DEDUPLICA las entradas repetidas que emite pip-audit', () => {
    // En el fixture real, pyyaml trae PYSEC-2021-142 y PYSEC-2020-96 por duplicado.
    const pyyamlIds = vulns.filter((v) => v.package === 'pyyaml').map((v) => v.id);
    expect(pyyamlIds).toContain('PYSEC-2021-142');
    expect(new Set(pyyamlIds).size).toBe(pyyamlIds.length);
    expect(pyyamlIds.filter((id) => id === 'PYSEC-2021-142')).toHaveLength(1);
  });

  it('ignora dependencias sin vulnerabilidades (no las lista como hallazgo)', () => {
    // markupsafe 3.0.3 aparece en el fixture con vulns: [].
    expect(vulns.some((v) => v.package === 'markupsafe')).toBe(false);
  });

  it('conserva fix_versions y aliases (el alias GHSA es lo que resuelve la severidad)', () => {
    const v = vulns.find((x) => x.id === 'PYSEC-2019-217')!;
    expect(v.fixVersions).toContain('2.10.1');
    expect(v.aliases.some((a) => a.startsWith('GHSA-'))).toBe(true);
  });

  it('un audit limpio devuelve arreglo vacío', () => {
    expect(parsePipAudit(loadFixture('pip-audit-clean.json'))).toEqual([]);
  });

  it('lanza con payload inválido, para que el orquestador lo marque no-audit', () => {
    expect(() => parsePipAudit({})).toThrow();
    expect(() => parsePipAudit(null)).toThrow();
    expect(() => parsePipAudit({ dependencies: 'no-es-array' })).toThrow();
  });
});

describe('looksLikeMissingPipAudit', () => {
  // En Windows con shell:true el binario ausente NO lanza ENOENT: el shell devuelve
  // exit code y un mensaje localizado. Esto se detecta para dar el comando exacto.
  it('detecta el mensaje real de Windows en español', () => {
    const stderr =
      '"pip-audit" no se reconoce como un comando interno o externo,\r\nprograma o archivo por lotes ejecutable.\r\n';
    expect(looksLikeMissingPipAudit(stderr)).toBe(true);
  });

  it('detecta el mensaje de Windows en inglés', () => {
    expect(
      looksLikeMissingPipAudit("'pip-audit' is not recognized as an internal or external command"),
    ).toBe(true);
  });

  it('detecta el mensaje de shells POSIX', () => {
    expect(looksLikeMissingPipAudit('bash: pip-audit: command not found')).toBe(true);
  });

  it('NO confunde un error legítimo de pip-audit con binario ausente', () => {
    expect(
      looksLikeMissingPipAudit('ERROR: Cannot install -r requirements.txt because of conflicts'),
    ).toBe(false);
    expect(looksLikeMissingPipAudit('')).toBe(false);
  });
});

describe('enrichPipFindings', () => {
  const vulns = parsePipAudit(loadFixture('pip-audit-vuln.json'));

  it('usa el índice de OSV para asignar severidad y bucket, reutilizando la regla de npm', () => {
    const index: SeverityIndex = { 'PYSEC-2019-217': 'high', 'PYSEC-2020-176': 'moderate' };
    const findings = enrichPipFindings(vulns, index);

    const jinja = findings.find((f) => f.package === 'jinja2')!;
    expect(jinja.severity).toBe('high');
    expect(jinja.bucket).toBe('fix-now');

    const pyyaml = findings.find((f) => f.package === 'pyyaml')!;
    expect(pyyaml.severity).toBe('moderate');
    expect(pyyaml.bucket).toBe('can-wait');
  });

  it('resuelve la severidad también cuando el índice solo conoce el ALIAS del hallazgo', () => {
    // El índice conoce el GHSA, el hallazgo de pip-audit es PYSEC.
    const soloAlias: SeverityIndex = { 'GHSA-462w-v97r-4m45': 'high' };
    const f = enrichPipFindings(vulns, soloAlias).find((x) => x.package === 'jinja2')!;
    expect(f.severity).toBe('high');
    expect(f.bucket).toBe('fix-now');
  });

  it('sin severidad conocida deja severity null en 🟡 y lo explica, sin inventar gravedad', () => {
    const findings = enrichPipFindings(vulns, {});
    expect(findings.every((f) => f.severity === null)).toBe(true);
    expect(findings.every((f) => f.bucket === 'can-wait')).toBe(true);
    expect(findings[0].explanation).not.toMatch(/CVE|GHSA|PYSEC/);
    expect(findings[0].explanation.length).toBeGreaterThan(20);
  });

  it('produce Findings con la forma del contrato (versión instalada y fixAvailable)', () => {
    const f = enrichPipFindings(vulns, {})[0];
    expect(f.type).toBe('vulnerability');
    expect(f.installedVersions.length).toBe(1);
    expect(typeof f.fixAvailable).toBe('boolean');
    expect(f.advisory?.urls).toBeDefined();
  });
});

describe('enrichPipFindings — agrega por paquete, igual que el motor npm', () => {
  const vulns = parsePipAudit(loadFixture('pip-audit-vuln.json'));

  it('emite UN hallazgo por paquete, no uno por advisory', () => {
    const findings = enrichPipFindings(vulns, {});
    // El fixture real trae 6 advisories de jinja2 y 3 de pyyaml.
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.package).sort()).toEqual(['jinja2', 'pyyaml']);
  });

  it('se queda con la severidad MÁS ALTA del paquete', () => {
    // jinja2: PYSEC-2019-217 es high, el resto moderate → gana high.
    const index: SeverityIndex = {
      'PYSEC-2019-217': 'high',
      'PYSEC-2021-66': 'moderate',
      'PYSEC-2026-1473': 'moderate',
    };
    const jinja = enrichPipFindings(vulns, index).find((f) => f.package === 'jinja2')!;
    expect(jinja.severity).toBe('high');
    expect(jinja.bucket).toBe('fix-now');
  });

  it('reúne los ids de todos los advisories del paquete (para El Repuesto)', () => {
    const jinja = enrichPipFindings(vulns, {}).find((f) => f.package === 'jinja2')!;
    expect(jinja.advisory!.titles).toContain('PYSEC-2019-217');
    expect(jinja.advisory!.titles).toContain('PYSEC-2021-66');
  });

  it('si ningún advisory del paquete tiene severidad, queda null en 🟡', () => {
    const findings = enrichPipFindings(vulns, {});
    expect(findings.every((f) => f.severity === null)).toBe(true);
    expect(findings.every((f) => f.bucket === 'can-wait')).toBe(true);
  });

  it('con severidad parcial usa la conocida, ignorando las que no se pudieron resolver', () => {
    const jinja = enrichPipFindings(vulns, { 'PYSEC-2019-217': 'critical' }).find(
      (f) => f.package === 'jinja2',
    )!;
    expect(jinja.severity).toBe('critical');
  });
});

describe('enrichPipFindings — caso MIXTO: severidad conocida + sin resolver en el mismo paquete', () => {
  const vulns = parsePipAudit(loadFixture('pip-audit-vuln.json'));
  // jinja2 trae 6 advisories en el fixture real.
  const jinjaTotal = vulns.filter((v) => v.package === 'jinja2').length;

  it('la severidad conocida MÁS ALTA gana (no se descarta información buena)', () => {
    const index: SeverityIndex = { 'PYSEC-2021-66': 'moderate', 'PYSEC-2019-217': 'high' };
    const jinja = enrichPipFindings(vulns, index).find((f) => f.package === 'jinja2')!;
    expect(jinja.severity).toBe('high');
    expect(jinja.bucket).toBe('fix-now');
  });

  it('DEJA MARCA de cuántos advisories quedaron sin resolver dentro del hallazgo', () => {
    // 1 de 6 resuelto → 5 sin evaluar. Sin marca, el reporte se vería seguro sin serlo:
    // cualquiera de esos 5 podría ser critical.
    const jinja = enrichPipFindings(vulns, { 'PYSEC-2021-66': 'moderate' }).find(
      (f) => f.package === 'jinja2',
    )!;
    expect(jinja.severity).toBe('moderate');
    expect(jinja.unresolvedAdvisories).toBe(jinjaTotal - 1);
  });

  it('sin nada pendiente la marca queda en 0', () => {
    const todos: SeverityIndex = Object.fromEntries(
      vulns.filter((v) => v.package === 'jinja2').map((v) => [v.id, 'low' as const]),
    );
    const jinja = enrichPipFindings(vulns, todos).find((f) => f.package === 'jinja2')!;
    expect(jinja.unresolvedAdvisories).toBe(0);
  });

  it('si no se resolvió ninguno, la marca cuenta todos y la severidad queda null', () => {
    const jinja = enrichPipFindings(vulns, {}).find((f) => f.package === 'jinja2')!;
    expect(jinja.severity).toBeNull();
    expect(jinja.unresolvedAdvisories).toBe(jinjaTotal);
  });

  it('los hallazgos npm nunca traen advisories sin resolver (npm sí da severidad)', () => {
    // Contraste explícito entre motores: npm audit trae severidad estructurada siempre.
    const jinja = enrichPipFindings(vulns, {}).find((f) => f.package === 'jinja2')!;
    expect(typeof jinja.unresolvedAdvisories).toBe('number');
  });
});
